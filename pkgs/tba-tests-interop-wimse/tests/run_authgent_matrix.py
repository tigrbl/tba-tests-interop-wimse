"""Run the 41 published Authgent cases against the pinned loopback runtimes."""

import argparse
from collections import Counter
from contextlib import contextmanager
import gzip
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from xml.etree import ElementTree

from authgent_matrix_runtime import AuthgentServices, authgent_issuer, fingerprint
from qualify_authgent_runtime import AUTHGENT_REVISION
from tba_tests_interop_wimse.evidence import audit_pytest_report
from support.cred_endpoint import (
    HTTP_PROFILE, REVISION, CredHttpSignatureAdapter, bridge_digest, build_cred_bridge, cred_hop,
)
from support.qualification_overlay import wic_source_digest
from support.signature_cases import SignatureHop
from support.spire_issuer import IMAGE_REFERENCE, spire_wit_issuers
from support.typed_service_flow import TypedServiceFlow
from support.typed_workload_chain import TypedWorkloadChain
from support.wic_fixture import DNS


def matrix_rows(mapping, runtime):
    with gzip.open(runtime, "rt", encoding="utf-8") as stream:
        rows = [row for row in json.load(stream)["planned_executions"]
                if row["hops"][0].get("support") == "authgent"]
    with gzip.open(mapping, "rt", encoding="utf-8") as stream:
        shards = json.load(stream)
    pairs = [pair for shard in shards for pair in shard]
    published, runtime_ids = zip(*pairs)
    if len(published) not in (1, 142_844) or len(set(published)) != len(published) or len(set(runtime_ids)) != len(runtime_ids):
        raise ValueError("Expected a unique runtime mapping for the full inventory or one selected ID")
    selected = {row["id"] for row in rows}
    originals = {runtime_id: original for original, runtime_id in pairs if runtime_id in selected}
    if len(published) == 142_844 and (len(originals) != len(rows) or len(rows) != 41):
        raise ValueError("Expected exactly 41 distinct published Authgent IDs and corresponding runtime rows")
    return [(originals[row["id"]], row) for row in rows if row["id"] in originals]


class CredWorkloadLab:
    def __init__(self, directory, bridge, spire):
        self.directory, self.bridge, self.spire = directory, bridge, spire

    @contextmanager
    def hop(self, case, direction, hop, names):
        with TemporaryDirectory(dir=self.directory) as work:
            yield cred_hop(Path(work), case, direction, self.bridge, self.spire, names)


def audit(row, observed):
    actual = tuple(observed[key] for key in ("reached_hops", "decision_hop", "result", "effects"))
    expected = tuple(row[key] for key in ("reached_hops", "decision_hop", "expected_result", "expected_effects"))
    if actual != expected:
        raise ValueError(f"{row['id']} expected {expected!r}, observed {observed!r}")
    first, *tail = observed["trace"]
    assert first["participant"] == "authgent" and first["operation"] == "authgent-issue"
    if first["decision"] == "deny":
        assert first["http_status"] == 403 and first["oauth_error"] == "access_denied"
        assert not tail and "issued_transaction_sha256" not in first and observed["effects"] == 0
        return
    assert first["http_status"] == 200
    fingerprint = first["issued_transaction_sha256"]
    assert len(bytes.fromhex(fingerprint)) == 32
    for model, hop in zip(row["hops"][1:], tail):
        if hop["operation"] == "source-exchange":
            assert hop["presented_transaction_sha256"] == fingerprint
        if hop["result"] == "peer-identity-refused":
            assert "verified_transaction_sha256" not in hop
        elif hop["operation"] == "call":
            assert hop["transaction_verifier"] == model["receiver_pin"][0]
            assert hop["verified_transaction_sha256"] == fingerprint
        elif hop["result"] == "destination-authorization-grant-issued":
            assert hop["verified_transaction_sha256"] == fingerprint
    if tail and tail[-1]["operation"] == "destination-exchange":
        source, destination = tail
        if destination["decision"] == "allow":
            assert source["issued_grant_sha256"] == destination["presented_grant_sha256"]
            assert destination["verified_transaction_sha256"] == fingerprint
            assert len(bytes.fromhex(destination["issued_access_token_sha256"])) == 32
        else:
            assert source["issued_grant_sha256"] != destination["presented_grant_sha256"]
            assert "issued_access_token_sha256" not in destination


def binding_control(endpoint, tokens, profile, direction, wit_issuer):
    caller, server = endpoint
    headers = caller.proof_headers(server.server_port, headers={"txn-token": tokens[0]})
    headers["txn-token"] = tokens[1]
    denied = caller.send_proof("127.0.0.1", server.server_port, DNS, headers=headers)
    assert denied["http_status"] == 401 and not server.ledger.snapshot(), denied
    reason = denied["response"]["reason"].lower()
    expected = ("signature",) if profile == HTTP_PROFILE else ("txn", "transaction", "tth")
    assert any(text in reason for text in expected), denied
    valid = caller.request("127.0.0.1", server.server_port, DNS, headers={"txn-token": tokens[0]})
    assert valid["http_status"] == 201 and len(server.ledger.snapshot()) == 1, valid
    return {"profile": profile, "direction": direction, "wit_issuer": wit_issuer,
            "accepted_http_status": valid["http_status"], "substitution_http_status": denied["http_status"],
            "substitution_reason": reason, "substitution_effects": 0,
            "signed_transaction_sha256": fingerprint(tokens[0]),
            "substituted_transaction_sha256": fingerprint(tokens[1])}


def binding_controls(lab, issuer):
    """Confirm valid and substituted Authgent tokens with both request proof profiles."""
    tokens = [issuer.exchange("workload-0", {"calendar.write"})[0] for _ in range(2)]
    assert tokens[0] != tokens[1]
    controls = []
    http = CredHttpSignatureAdapter(lab.directory, lab.bridge)
    for direction in ("forward", "reverse"):
        for wit_issuer in ("baseline", "spire-wit-svid"):
            hop = {"profile": "wit-wpt", "wit_issuer": wit_issuer}
            case = {"scenario_id": "07", "variant": "valid-peer", "layer": "operation",
                    "target_hop": "1", "hops": {"1": hop}}
            names = {"caller_name": "workload-0", "receiver_name": "workload-1"}
            with lab.hop(case, direction, hop, names) as fixture:
                with SignatureHop(fixture).running() as endpoint:
                    controls.append(binding_control(endpoint, tokens, hop["profile"], direction, wit_issuer))
        http_case = {**case, "hops": {"1": {"profile": HTTP_PROFILE, "wit_issuer": "baseline"}}}
        with http.isolated(http_case, {"direction": direction}) as fixture:
            with fixture.enforcing.running() as endpoint:
                controls.append(binding_control(endpoint, tokens, HTTP_PROFILE, direction, "baseline"))
    return controls


def record_junit(suite, row, observation):
    item = ElementTree.SubElement(suite, "testcase", name=row["id"], classname="authgent_matrix")
    properties = ElementTree.SubElement(item, "properties")
    result = {"execution_id": row["id"], "hop_sequence_id": row["hop_sequence_id"],
              "status": "passed", "observation": observation}
    for name in ("execution_id", "hop_sequence_id"):
        ElementTree.SubElement(properties, "property", name=name, value=result[name])
    ElementTree.SubElement(properties, "property", name="execution_result", value=json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("snapshot", "mapping", "runtime", "authgent-checkout", "authgent-python", "cred-checkout", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda value: Path(value).resolve())
    args = parser.parse_args()

    rows = matrix_rows(args.mapping, args.runtime)
    if not rows:
        return
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    if snapshot["peers"]["implementations"]["authgent"]["candidate_ref"] != AUTHGENT_REVISION:
        raise ValueError("Authgent revision differs from the matrix snapshot")
    args.output.mkdir(parents=True, exist_ok=False)
    bridge = build_cred_bridge(args.cred_checkout, args.output / "cred")
    if bridge_digest(bridge) != snapshot["cred_bridge_sha256"]:
        raise ValueError("Generated Cred proof bridge differs from the qualification snapshot")
    txn_bridge = bridge.with_name("authgent_cred_transaction.mjs")
    shutil.copyfile(Path(__file__).with_name(txn_bridge.name), txn_bridge)
    subprocess.run(["node", str(txn_bridge), "build", str(args.cred_checkout)], check=True, timeout=30)

    counts = Counter()
    suite = ElementTree.Element("testsuite", name="authgent_matrix", tests=str(len(rows)),
                                failures="0", errors="0", skipped="0")
    tba_digest = wic_source_digest()
    with (authgent_issuer(args.authgent_python, args.authgent_checkout, args.output) as issuer,
          spire_wit_issuers(args.output) as spire,
          (args.output / "per-id.jsonl").open("x", encoding="utf-8") as report):
        lab = CredWorkloadLab(args.output, bridge, spire)
        chain = TypedWorkloadChain(snapshot["peers"], lambda: SimpleNamespace(signature=lab))
        controls = binding_controls(lab, issuer)
        for published_id, row in rows:
            class BoundServices(AuthgentServices):
                def __init__(self, hops, agent_factory):
                    super().__init__(hops, issuer, txn_bridge, row["outcome_id"])

            flow = TypedServiceFlow(chain, BoundServices)
            if not flow.supports(row):
                raise ValueError(f"Missing qualified runtime binding for {published_id}")
            observation = flow.observe(row)
            audit(row, observation)
            record_junit(suite, row, observation)
            report.write(json.dumps({"published_id": published_id, "runtime_id": row["id"], "status": "passed",
                                     "hops": row["hops"], "outcome_id": row["outcome_id"],
                                     "observation": observation}) + "\n")
            report.flush()
            counts[row["outcome_id"]] += 1
    results = args.output / "results.xml"
    ElementTree.ElementTree(suite).write(results, encoding="utf-8", xml_declaration=True)
    if not audit_pytest_report([row for _, row in rows], results)["complete"]:
        raise ValueError("Authgent JUnit report does not cover the exact runtime rows")
    summary = {
        "authgent_revision": AUTHGENT_REVISION, "cred_revision": REVISION, "spire_image": IMAGE_REFERENCE,
        "cred_proof_bridge_sha256": bridge_digest(bridge),
        "cred_transaction_component_sha256": sha256(txn_bridge.with_name("txn-token.js").read_bytes()).hexdigest(),
        "current_tba_fixture_sha256": tba_digest,
        "snapshot_tba_pins": sorted({hop["caller_pin"][1] for _, row in rows for hop in row["hops"]
                                     if hop["caller_pin"][0] == "tba" and hop["caller_pin"][1]}),
        "input_sha256": {name: sha256(getattr(args, name).read_bytes()).hexdigest()
                         for name in ("snapshot", "mapping", "runtime")},
        "published_ids_verified": sum(counts.values()),
        "results": dict(counts), "binding_controls": controls,
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
