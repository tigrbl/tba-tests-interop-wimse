"""Run the pinned success driver and check its observed HTTP handoffs."""
import argparse
from collections import Counter
import csv
import gzip
from itertools import product
import json
from pathlib import Path
import re
import subprocess
import sys


SCENARIO = "ietf127-b-chain"
ROUTES = (
    (5051, "/tts/token"), (5000, "/workflows/text-stats/executions"),
    (5051, "/oauth/token"), (5061, "/oauth/token"), (5060, "/coordinate"),
    (5061, "/tts/token"), (5062, "/research"), (5061, "/tts/token"),
    (5063, "/files/read"),
)


def run_reference(upstream, agent):
    if not re.fullmatch(r"[a-z0-9]+", agent):
        raise ValueError("Invalid disposable workflow deployment identifier")
    sys.path.insert(0, str(upstream / "peers"))
    import domain_a
    import domain_b

    # The fixture hardcodes the author's deployment and HTTP socket. Bind only
    # those two addresses at signing time. Retain its pinned WIMSE audience.
    driver_path = upstream / "peers/chain_driver.py"
    driver = {"__name__": "pinned_chain", "__file__": str(driver_path)}
    original = "http://127.0.0.1:5050/api/v2/agents/dbsccjan18nkaiapu9v0/"
    source = driver_path.read_text(encoding="utf-8").replace(
        original, f"http://127.0.0.1:5000/api/v2/agents/{agent}/"
    )
    exec(compile(source, str(driver_path), "exec"), driver)
    server_a = domain_a.start_in_thread(5051)
    servers_b = domain_b.start_all_in_threads()
    try:
        succeeded, _, _ = driver["run_b_chain"](True)
        if not succeeded:
            # The captured statuses provide diagnostics without exposing tokens.
            print("Pinned driver did not reach its success outcome", file=sys.stderr)
            return 1
        return 0
    finally:
        domain_b.shutdown_all(servers_b)
        server_a.shutdown()


def wire_results(upstream, capture, oracle):
    sys.path.insert(0, str(upstream / "checkers"))
    import observes_chain as wire

    cmd = ["tshark", "-n", "-r", "-"]
    for port in sorted({port for port, _ in ROUTES}):
        cmd.extend(["-d", f"tcp.port=={port},http"])
    cmd.extend(["-Y", "http", "-T", "json"])
    with capture.open("rb") as stream:
        packets = json.loads(subprocess.check_output(cmd, stdin=stream, text=True, timeout=60),
                             object_pairs_hook=wire._collect_duplicates)
    requests, responses = {}, {}
    for packet in packets:
        layers = packet["_source"]["layers"]
        tcp, http = layers["tcp"], layers["http"]
        if isinstance(http, list):
            http = http[-1]
        sid = wire._first_str(tcp.get("tcp.stream"))
        if wire._is_request(http):
            headers = {}
            for line in wire._extract_lines(http, "http.request.line"):
                name, separator, value = line.partition(":")
                if separator:
                    headers[name.lower()] = value.strip()
            if "http.authorization" in http:
                headers.setdefault("authorization", wire._first_str(http["http.authorization"]))
            if headers.get("x-test-case") == "B_CHAIN":
                requests[sid] = (int(tcp["tcp.dstport"]), http, headers)
        elif wire._extract_status(http):
            responses[sid] = http
    observed = list(requests.items())
    statuses = [wire._extract_status(responses.get(sid, {})) for sid, _ in observed]
    problems = []

    def require(condition, message):
        if not condition:
            problems.append(message)

    require(len(observed) == len(ROUTES), "Expected exactly nine tagged HTTP requests")
    for (_, (port, http, _)), (want_port, path) in zip(observed, ROUTES):
        require(port == want_port and wire._first_str(http.get("http.request.uri")).endswith(path),
                f"Unexpected route for expected endpoint {want_port}{path}")
        require(wire._first_str(http.get("http.request.method")) == "POST", "Expected HTTP POST")
    require(statuses == oracle["http_statuses"], "Unexpected hop response status")
    if problems:
        return {"statuses": statuses, "problems": problems}

    def response(hop):
        return wire._decode_body(responses[observed[hop - 1][0]])

    def request(hop):
        return wire._decode_body(observed[hop - 1][1][1])

    def headers(hop):
        return observed[hop - 1][1][2]

    txn_a = response(1).get("txn_token", "")
    assertion = response(3).get("assertion", "")
    access = response(4).get("access_token", "")
    txn_b1 = response(6).get("txn_token", "")
    txn_b2 = response(8).get("txn_token", "")
    tokens = (txn_a, assertion, access, txn_b1, txn_b2)
    claims = tuple(wire._jwt_payload(token) for token in tokens)
    types = [wire._jwt_header(token).get("typ") for token in tokens]
    require(types == ["txntoken+jwt", "jwt-chg+jwt", "at+jwt", "txntoken+jwt", "txntoken+jwt"],
            "Unexpected token types")
    transaction_ids = {claim.get("txn") for claim in claims}
    require(len(transaction_ids) == 1 and None not in transaction_ids, "Transaction IDs diverged")
    require(headers(2).get("txn-token") == txn_a and request(3).get("subject_token") == txn_a,
            "Domain A issued token was not presented to ingress and source exchange")
    require(request(4).get("assertion") == assertion, "Source assertion was not redeemed")
    require(headers(5).get("authorization") == f"Bearer {access}" and
            request(6).get("access_token") == access, "Domain B access token did not reach both consumers")
    require(headers(7).get("txn-token") == txn_b1 and request(8).get("txn_token") == txn_b1 and
            headers(9).get("txn-token") == txn_b2, "Domain B transaction tokens did not follow the expected handoffs")
    require(bool(txn_a) and all(txn_a not in json.dumps((request(hop), headers(hop)))
                               for hop in range(4, 10)), "Domain A transaction token appeared in Domain B")
    require(set(claims[0].get("scope", "").split()) == set(oracle["initial_scope"]) and
            set(claims[-1].get("scope", "").split()) == set(oracle["final_scope"]),
            "Transaction scope did not narrow from the initial to final scope")
    for hop, claim in ((2, claims[0]), (7, claims[3]), (9, claims[4])):
        require(bool(claim.get("req_wl")) and claim.get("req_wl") ==
                wire._jwt_payload(headers(hop).get("workload-identity-token", "")).get("sub"),
                f"Hop {hop} transaction workload binding differs from the caller WIT")
    proof = wire._jwt_payload(headers(9).get("workload-proof-token") or
                              headers(9).get("authorization", "").removeprefix("WPT "))
    wit = headers(9).get("workload-identity-token", "")
    require(bool(wit and txn_b2) and proof.get("wth") == wire._b64url_sha256(wit) and
            proof.get("tth") == wire._b64url_sha256(txn_b2), "Final WPT token hashes differ")
    ingress = response(2)
    require(ingress.get("state") == oracle["ingress_state"] and
            (ingress.get("output") or ingress.get("data")) ==
            {"count": oracle["ingress_count"], "upper": oracle["ingress_uppercase"]},
            "Ingress did not return the completed text-stats output")
    require(response(5).get("summary") == oracle["research_summary"], "Unexpected research summary")
    require(response(9).get("file") == oracle["protected_file"] and bool(response(9).get("content")),
            "Expected one successful read of the protected file")
    return {"statuses": statuses, "problems": problems}


def report(manifest, output, observation):
    with gzip.open(manifest, "rt", encoding="utf-8") as stream:
        inventory = json.load(stream)
    scenario = inventory["named_scenarios"][SCENARIO]
    rows = [row for row in inventory["planned_executions"] if row.get("named_scenario_id") == SCENARIO]
    by_role = scenario["role_candidates"]
    pins = {}
    for definition in scenario["roles"]:
        role = definition["id"]
        if demo := definition.get("demo"):
            pins[role] = ("ietf127-demo", scenario["revision"], demo)
        elif rich := definition.get("rich"):
            pins[role] = ("rich-hackathon", scenario["revision"], rich)
        elif role == "ingress":
            pin = scenario["pin_overrides"]["agentmaurice"]
            pins[role] = ("agentmaurice", pin["version"], pin["configuration"])
        else:
            raise ValueError(f"Reference runtime binding is missing for {role}")
        if list(pins[role]) not in by_role[role]:
            raise ValueError(f"Reference runtime binding for {role} is absent from the inventory")
    verdict = observation["status"]
    qualified = verdict == "pass"
    output.mkdir(parents=True, exist_ok=True)
    counts = Counter({"pass": 0, "fail": 0, "blocked": 0})
    role_rows = [
        {"role": role, "pin": pin, "qualified": qualified and tuple(pin) == pins[role]}
        for role, options in by_role.items() for pin in options
    ]
    handoffs = []
    for hop in scenario["hops"]:
        caller, receiver = hop["caller"], hop["receiver"]
        handoffs.extend(
            {"operation": hop["operation"], "caller": source, "receiver": target,
             "qualified": qualified and tuple(source) == pins[caller] and tuple(target) == pins[receiver]}
            for source, target in product(by_role[caller], by_role[receiver])
        )
    actual_assignments, ids = set(), set()
    with (output / "per-id.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["execution_id", "status", "missing_runtime_roles", "reason"])
        for row in rows:
            assignment = {}
            for hop in row["hops"]:
                for side in ("caller", "receiver"):
                    role, pin = hop[side], tuple(hop[f"{side}_pin"])
                    if assignment.setdefault(role, pin) != pin:
                        raise ValueError(f"Inconsistent repeated role binding in {row['id']}")
            actual_assignments.add(tuple(assignment[role] for role in by_role))
            ids.add(row["id"])
            missing = [f"{role}={assignment[role][0]}" for role in by_role if assignment[role] != pins[role]]
            status = "blocked" if missing else verdict
            reason = ("Missing named-flow runtime adapter" if missing else
                      " | ".join(observation.get("problems", ())))
            writer.writerow([row["id"], status, " ".join(missing), reason])
            counts[status] += 1
    expected_assignments = set(product(*(map(tuple, options) for options in by_role.values())))
    if actual_assignments != expected_assignments or len(ids) != len(rows) or len(ids) != 12_288:
        raise ValueError("The per-ID report does not account for all published assignments")
    summary = {
        "counts": counts, "qualified_role_bindings": sum(row["qualified"] for row in role_rows),
        "total_role_bindings": len(role_rows),
        "qualified_directional_handoffs": sum(row["qualified"] for row in handoffs),
        "total_directional_handoffs": len(handoffs), "reference": observation,
    }
    for name, content in (("summary", summary), ("qualification", {"roles": role_rows, "handoffs": handoffs})):
        (output / f"{name}.json").write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return int(counts["pass"] != len(ids))


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    run = modes.add_parser("run")
    run.add_argument("upstream", type=Path)
    run.add_argument("agent")
    evaluate = modes.add_parser("report")
    evaluate.add_argument("manifest", type=Path)
    evaluate.add_argument("output", type=Path)
    evaluate.add_argument("--upstream", type=Path)
    evaluate.add_argument("--capture", type=Path)
    evaluate.add_argument("--driver-exit", type=int)
    args = parser.parse_args()
    if args.mode == "run":
        return run_reference(args.upstream.resolve(), args.agent)
    observation = {"status": "blocked", "problems": ["Reference lab did not launch"]}
    if args.capture is not None:
        with gzip.open(args.manifest, "rt", encoding="utf-8") as stream:
            oracle = json.load(stream)["named_scenarios"][SCENARIO]["success_oracle"]
        try:
            result = wire_results(args.upstream.resolve(), args.capture, oracle)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            observation = {"status": "blocked", "problems": [f"Capture audit unavailable ({type(error).__name__})"]}
        else:
            if args.driver_exit != 0:
                result["problems"].append(f"Pinned success driver exited {args.driver_exit}")
            observation = {"status": "fail" if result["problems"] else "pass", **result}
    return report(args.manifest, args.output, observation)


if __name__ == "__main__":
    sys.exit(main())
