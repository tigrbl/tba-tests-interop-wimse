"""Check the TbA bindings over disposable loopback using the shared runner."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

import ci_nine_hop_matrix as runner
from support.nine_hop_tba import PIN, build_bindings


def check(upstream, manifest):
    scenario, inventory = runner.read_manifest(manifest)
    pins = runner.reference_pins(scenario)
    roles = list(scenario["role_candidates"])
    all_tba = {role: PIN for role in roles}
    mixed = {**pins, "ingress": PIN}
    assignments = {
        "all-tba": all_tba,
        "mixed-http-signature-and-jose": {
            **mixed, "driver": PIN, "issuer-a": PIN, "exchange-a": PIN,
            "exchange-b": PIN, "coordinator": PIN, "issuer-b": PIN,
        },
        "pinned-research-to-tba-file-tool": {**mixed, "file-tool": PIN},
        "tba-research-to-pinned-file-tool": {**mixed, "research": PIN},
    }
    by_assignment = {tuple(runner.assignment_for(row)[role] for role in roles): row for row in inventory}
    rows = [by_assignment[tuple(assignment[role] for role in roles)] for assignment in assignments.values()]
    seen = {}
    wire = None

    def load(context):
        nonlocal wire
        wire = context["wimse"]
        send = wire.send

        def observe(request, case=None, timeout=15):
            target = urlsplit(request.url)
            events = seen.setdefault(case, [])
            event = {"port": target.port, "path": target.path, "request": request}
            events.append(event)
            response = send(request, case=case, timeout=timeout)
            event["response"] = response
            return response

        wire.send = observe
        return {(role, binding.pin): binding for role, binding in build_bindings(context).items()}

    with TemporaryDirectory() as scratch:
        args = SimpleNamespace(
            manifest=manifest, upstream=upstream, agent="local",
            observations=Path(scratch) / "observations.jsonl", shard=0, shards=1,
        )
        with (
            patch.object(runner, "read_manifest", return_value=(scenario, rows)),
            patch.object(runner, "load_bindings", side_effect=load),
        ):
            runner.run_shard(args)
        results = runner.read_observations([args.observations])

    for name, row in zip(assignments, rows):
        execution_id = row["id"]
        result = results[execution_id]
        events = seen[execution_id]
        statuses = [event["response"].status for event in events]
        routes = list(runner.ROUTES)
        routes[1] = (runner.INGRESS_PORT, runner.INGRESS_ROUTE)
        assert len(events) == len(routes), (name, statuses, result["problems"])
        assert all(event["port"] == port and event["path"].endswith(path)
                   for event, (port, path) in zip(events, routes)), name
        if name in {"all-tba", "mixed-http-signature-and-jose"}:
            assert result["status"] == "observed", (name, result)
            assert statuses == scenario["success_oracle"]["http_statuses"], (name, statuses)
            assert_success(events, wire)
        else:
            assert statuses[:8] == [200] * 8 and statuses[8] == 401, (name, statuses, result)
        print(f"{name} {statuses} {execution_id}")


def assert_success(events, wire):
    headers = [{key.lower(): value for key, value in event["request"].headers.items()} for event in events]
    replies = [json.loads(event["response"].body) for event in events]
    assert replies[1]["state"] == "completed"
    assert replies[1]["output"] == {"count": 11, "upper": "HELLO WIMSE"}
    assert replies[4]["summary"] == "$4.2M"
    assert replies[8]["file"] == "Q3.pdf" and replies[8]["content"]
    assert len({headers[index]["workload-identity-token"] for index in (1, 2, 4)}) == 1
    txn_a, grant, access, b1, b2 = (
        replies[index][key] for index, key in
        ((0, "txn_token"), (2, "assertion"), (3, "access_token"), (5, "txn_token"), (7, "txn_token"))
    )
    tokens = [wire.parse_jwt(serialized) for serialized in (txn_a, grant, access, b1, b2)]
    assert [token[0]["typ"] for token in tokens] == [
        "txntoken+jwt", "jwt-chg+jwt", "at+jwt", "txntoken+jwt", "txntoken+jwt",
    ]
    token_claims = [token[1] for token in tokens]
    assert len({claims["txn"] for claims in token_claims}) == 1
    assert set(token_claims[0]["scope"].split()) == {"files:read", "files:list"}
    assert token_claims[4]["scope"] == "files:read"
    assert all(txn_a not in json.dumps(headers[index])
               and txn_a.encode() not in events[index]["request"].body for index in range(3, 9))
    for idx, claim_idx, token in ((1, 0, txn_a), (6, 3, b1), (8, 4, b2)):
        assert headers[idx]["txn-token"] == token
        assert wire.parse_jwt(headers[idx]["workload-identity-token"])[1]["sub"] == token_claims[claim_idx]["req_wl"]
    proof = wire.parse_jwt(headers[8]["authorization"].removeprefix("WPT "))[1]
    assert proof["wth"] == wire.b64u(sha256(headers[8]["workload-identity-token"].encode()).digest())
    assert proof["tth"] == wire.b64u(sha256(b2.encode()).digest())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("upstream", type=Path)
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()
    check(arguments.upstream, arguments.manifest)
