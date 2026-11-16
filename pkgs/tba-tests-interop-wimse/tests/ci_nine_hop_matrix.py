"""Execute and reconcile sharded nine-hop assignments on hosted Ubuntu."""
from argparse import ArgumentParser
from collections import Counter
from contextlib import ExitStack
import csv
from itertools import product
import json
from pathlib import Path
from subprocess import SubprocessError
from threading import Thread
from uuid import uuid4

from ci_nine_hop import ROUTES, assignment_for, check_case, decode_capture, load_driver, read_manifest, reference_pins
from nine_hop_runtime import REQUIRED, Runtime, load_bindings


INGRESS_PORT = 5002
INGRESS_ROUTE = "/workflows/text-stats/executions"


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def ingress_handler(runtime, wimse, domain_a, base):
    class Ingress(base):
        def do_POST(self):
            role = "ingress"
            binding = runtime.binding(role)
            if binding is None or not self.path.endswith(INGRESS_ROUTE):
                self.send_error_json(404, "ingress-not-bound")
                return
            raw_body = self.read_body()
            with runtime.role(role):
                ok, status, reason, identity = wimse.verify_wimse_proof(
                    self.command, self.path, dict(self.headers), raw_body,
                    {"peer.ietf127.example": domain_a.PEER_JWKS},
                    expected_aud="http://maurice.ietf127.example:5050",
                )
                if not ok:
                    self.send_error_json(status, reason)
                    return
                tokens = self.headers.get_all("Txn-Token", [])
                try:
                    if len(tokens) != 1:
                        raise ValueError("missing or ambiguous transaction token")
                    claims = wimse.verify_jwt(
                        tokens[0], domain_a.TTS_A_JWKS, expected_typ="txntoken+jwt",
                        expected_aud="maurice.ietf127.example",
                    )
                    text = json.loads(raw_body)["inputs"]["text"]
                    if claims.get("req_wl") != identity["peer_id"] or not isinstance(text, str):
                        raise ValueError("transaction workload or inputs differ")
                except (TypeError, ValueError, KeyError):
                    self.send_error_json(403, "ingress-context-invalid")
                    return
                self.send_json(200, {
                    "state": "completed", "execution_id": str(uuid4()),
                    "output": {"count": len(text), "upper": text.upper()},
                })

    return Ingress


def run_shard(args):
    with ExitStack() as stack:
        return execute(args, stack)


def execute(args, stack):
    scenario, rows = read_manifest(args.manifest)
    reference = reference_pins(scenario)
    upstream = args.upstream.resolve()
    maurice_driver = load_driver(upstream, args.agent)
    fixture_driver = load_driver(upstream, args.agent, INGRESS_PORT)
    import domain_a
    import domain_b
    import wimse

    context = {
        "upstream": upstream, "scenario": scenario, "domain_a": domain_a, "domain_b": domain_b,
        "wimse": wimse, "agent": args.agent, "agentmaurice_file_tool_agent": args.agent,
        "stack": stack, "workdir": args.observations.parent,
    }
    runtime = Runtime(load_bindings(context), wimse)
    runtime.patch_primitives()
    local_ingress = ingress_handler(runtime, wimse, domain_a, domain_b.WimseBaseHandler)
    post_a = runtime.wrap_handler(domain_a.DomainAHandler, {"/tts/token": "issuer-a", "/oauth/token": "exchange-a"}.get)
    post_b = runtime.wrap_handler(domain_b.TokenServicesHandler,
                                  {"/tts/token": "issuer-b", "/oauth/token": "exchange-b"}.get)
    routed = (
        (5051, domain_a.DomainAServer, post_a),
        (5061, domain_b.WimseThreadingHTTPServer, post_b),
        (5060, domain_b.WimseThreadingHTTPServer,
         runtime.wrap_handler(domain_b.CoordinatorHandler, lambda _: "coordinator")),
        (5062, domain_b.WimseThreadingHTTPServer,
         runtime.wrap_handler(domain_b.ResearchHandler, lambda _: "research")),
        (5063, domain_b.WimseThreadingHTTPServer,
         runtime.wrap_handler(domain_b.FileToolHandler, lambda _: "file-tool")),
        (INGRESS_PORT, domain_b.WimseThreadingHTTPServer, local_ingress),
    )
    with ExitStack() as stack, args.observations.open("w", encoding="utf-8") as out:
        for port, server_type, handler in routed:
            server = stack.enter_context(server_type(("127.0.0.1", port), handler))
            Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            stack.callback(server.shutdown)

        for row in rows[args.shard::args.shards]:
            execution_id = row["id"]
            assignment = assignment_for(row)
            runtime.assignment = assignment
            runtime.execution_id = execution_id
            runtime.observed.clear()
            missing = [f"{role}={pin[0]}" for role, pin in assignment.items()
                       if pin != reference[role] and runtime.binding(role) is None]
            if missing:
                result = {"status": "blocked", "missing_runtime_roles": missing,
                          "problems": ["Missing named-flow runtime adapter"]}
            else:
                uses_maurice = assignment["ingress"] == reference["ingress"]
                with runtime.role("driver"):
                    try:
                        success, _, _ = (maurice_driver if uses_maurice else fixture_driver)(True)
                    except (OSError, ValueError, RuntimeError) as error:
                        success = False
                        error_type = type(error).__name__
                    else:
                        error_type = None
                unobserved = [
                    f"{role}={pin[0]}:{operation}"
                    for role, pin in assignment.items() if pin != reference[role]
                    for operation in sorted(REQUIRED[role]) if not runtime.observed[(role, operation)]
                ]
                problems = []
                if not success:
                    problems.append(f"Driver did not reach its success outcome{f' ({error_type})' if error_type else ''}")
                if unobserved:
                    problems.append("Missing observed peer operations " + " ".join(unobserved))
                result = {"status": "fail" if problems else "observed",
                          "uses_maurice_ingress": uses_maurice, "problems": problems}
            out.write(json.dumps({"execution_id": execution_id, **result}) + "\n")
            out.flush()


def audit_shard(args):
    scenario, rows = read_manifest(args.manifest)
    expected = {row["id"] for row in rows[args.shard::args.shards]}
    observations = read_observations([args.observations]) if args.observations.is_file() else {}
    if set(observations) - expected:
        raise ValueError("Shard produced unexpected execution IDs")
    capture_error = None
    if args.capture.is_file() and any(row["status"] != "blocked" for row in observations.values()):
        try:
            wire, requests, responses = decode_capture(args.upstream.resolve(), args.capture)
        except (OSError, ValueError, SubprocessError) as error:
            capture_error = type(error).__name__
        else:
            if set(requests) - expected:
                raise ValueError("Capture contains requests outside its shard")
    else:
        capture_error = "capture unavailable"

    with args.results.open("w", encoding="utf-8") as out:
        for execution_id in sorted(expected):
            result = observations.get(execution_id, {
                "execution_id": execution_id, "status": "blocked", "problems": ["Runner produced no result"],
            })
            if result["status"] != "blocked":
                if capture_error:
                    result["status"] = "blocked"
                    result["problems"].append(f"Capture audit unavailable ({capture_error})")
                else:
                    routes = list(ROUTES)
                    if not result["uses_maurice_ingress"]:
                        routes[1] = (INGRESS_PORT, INGRESS_ROUTE)
                    observed = check_case(wire, requests.get(execution_id, {}), responses, scenario["success_oracle"], routes)
                    result["statuses"] = observed["statuses"]
                    result["problems"].extend(observed["problems"])
                    result["status"] = "fail" if result["problems"] else "pass"
            out.write(json.dumps(result) + "\n")


def read_observations(paths):
    results = {}
    for path in paths:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                result = json.loads(line)
                execution_id = result["execution_id"]
                if execution_id in results:
                    raise ValueError(f"Duplicate execution result for {execution_id}")
                results[execution_id] = result
    return results


def aggregate(args):
    scenario, rows = read_manifest(args.manifest)
    results = read_observations(sorted(args.shard_dir.rglob("results.jsonl")))
    expected = {row["id"] for row in rows}
    if len(rows) != scenario["expected_assignments"] or len(expected) != len(rows) or set(results) - expected:
        raise ValueError("The report does not match the named execution inventory")
    missing_artifact_ids = expected - results.keys()
    if not results:
        raise ValueError("No shard results were uploaded")
    for execution_id in missing_artifact_ids:
        results[execution_id] = {"status": "blocked", "problems": ["Shard evidence did not upload"]}
    counts = Counter({"pass": 0, "fail": 0, "blocked": 0})
    role_evidence, handoff_evidence = {}, {}
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "per-id.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["execution_id", "status", "http_statuses", "missing_runtime_roles", "reason"])
        for row in rows:
            execution_id = row["id"]
            result = results[execution_id]
            status = result["status"]
            if status not in counts:
                raise ValueError(f"Unsupported outcome {status}")
            counts[status] += 1
            writer.writerow([
                execution_id, status, " ".join(map(str, result.get("statuses", ()))),
                " ".join(result.get("missing_runtime_roles", ())), " | ".join(result["problems"]),
            ])
            if status == "pass":
                for role, pin in assignment_for(row).items():
                    role_evidence.setdefault((role, pin), execution_id)
                for hop in row["hops"]:
                    key = hop["operation"], tuple(hop["caller_pin"]), tuple(hop["receiver_pin"])
                    handoff_evidence.setdefault(key, execution_id)

    candidates = scenario["role_candidates"]
    role_rows = [
        {"role": role, "pin": pin, "evidence_execution_id": role_evidence.get((role, tuple(pin)))}
        for role, pins in candidates.items() for pin in pins
    ]
    handoff_rows = [
        {"operation": hop["operation"], "caller": source, "receiver": target,
         "evidence_execution_id": handoff_evidence.get((hop["operation"], tuple(source), tuple(target)))}
        for hop in scenario["hops"] for source, target in product(candidates[hop["caller"]], candidates[hop["receiver"]])
    ]
    summary = {"counts": counts, "qualified_role_bindings": len(role_evidence), "total_role_bindings": len(role_rows),
               "qualified_directional_handoffs": len(handoff_evidence), "total_directional_handoffs": len(handoff_rows)}
    write_json(args.output / "summary.json", summary)
    write_json(args.output / "qualification.json", {"roles": role_rows, "handoffs": handoff_rows})
    print(json.dumps(summary, indent=2))
    return int(counts["pass"] != len(expected))


def main():
    parser = ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    audit = commands.add_parser("audit")
    merge = commands.add_parser("aggregate")
    for command in (run, audit, merge):
        command.add_argument("manifest", type=Path)
    for command in (run, audit):
        command.add_argument("upstream", type=Path)
        command.add_argument("observations", type=Path)
        command.add_argument("shard", type=int)
        command.add_argument("shards", type=int)
    run.add_argument("agent")
    audit.add_argument("capture", type=Path)
    audit.add_argument("results", type=Path)
    merge.add_argument("shard_dir", type=Path)
    merge.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command != "aggregate" and not 0 <= args.shard < args.shards:
        parser.error("shard index must be in the configured shard range")
    return {"run": run_shard, "audit": audit_shard, "aggregate": aggregate}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
