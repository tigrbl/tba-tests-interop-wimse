"""Qualify and execute native policy cases with baseline or SVID issuers."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path

import pytest

from run_native_baseline_workload_batch import qualify
from run_native_wit_svid_batch import AttemptJournal, qualify as qualify_issuer
from support.native_acquired_policy import SUPPORT
from support.native_specialized_services import RECEIPT, TRANSACTION
from tba_test_interop_wimse.evidence import audit_pytest_report
from tba_test_interop_wimse.native_expansion import BASELINE_WORKLOAD_RECORD, COMBINED_SCOPE, NATIVE_ISSUERS, expanded_plan
from typed_service_selection import (
    native_baseline_policy_rows, native_svid_policy_rows, policy_svid_scope, service_control_rows, svid_policy_control_rows,
)


SVID_COUNTS = {"tba-wit-svid": 4132, "tba-x509-svid": 1683, COMBINED_SCOPE: 2960}


def audit_bindings(rows, audit):
    counts = Counter()
    for row in rows:
        case = audit["results"][row["id"]]
        if case["status"] != "passed":
            continue
        attempt, = case["attempts"]
        observation = attempt["observation"]
        trace = observation["trace"]
        first, last = trace[0], trace[-1]
        if first["operation"] == TRANSACTION and first["decision"] == "allow":
            issued = first["issued_transaction_sha256"]
            assert len(bytes.fromhex(issued)) == 32
            counts["transaction_tokens_issued"] += 1
            if len(trace) > 1:
                verified = trace[1].get("verified_transaction_sha256")
                if verified is not None or observation["decision_hop"] > 2 or trace[1]["decision"] == "allow":
                    assert verified == issued
                    counts["issued_transaction_verified_downstream"] += 1
        if last["operation"] in SUPPORT:
            assert last["support_role"] == row["hops"][-1]["support"] and last["initially_allowed"]
            assert (last["decision"], observation["effects"]) in {("allow", 1), ("deny", 0)}
            counts[f"{last['support_role']}:{last['decision']}"] += 1
            source = {"issuer-revocation-refused": "issuer", "holder-self-revocation-refused": "holder"}.get(last["result"])
            if source:
                assert last["verified_revocation_source"] == source
        if last["operation"] == RECEIPT:
            assert last["support_role"] == row["hops"][-1]["support"] and observation["effects"] == 0
            if last["decision"] == "allow":
                assert last["verified_receipts"] == len(trace) - 1
            counts[f"{last['support_role']}:{last['decision']}"] += 1
    return dict(sorted(counts.items()))


def audit_svids(rows, audit):
    counts = Counter()
    for row in rows:
        result = audit["results"][row["id"]]
        if result["status"] != "passed":
            continue
        attempt, = result["attempts"]
        for hop, actual in zip(row["hops"], attempt["observation"]["trace"]):
            expected = {hop.get(field) for field in ("wic_issuer", "wit_issuer")} & NATIVE_ISSUERS.keys()
            seen = actual.get("svids", {})
            assert seen.keys() == expected, (row["id"], actual)
            for issuer, evidence in seen.items():
                assert len(bytes.fromhex(evidence["sha256"])) == 32
                counts[f"{issuer}:presented"] += 1
                if evidence["verified"]:
                    assert evidence["identity"] == f"spiffe://example.org/{hop['caller']}"
                    counts[f"{issuer}:verified"] += 1
                else:
                    assert actual["result"] == "peer-identity-refused", (row["id"], actual)
                    counts[f"{issuer}:refused"] += 1
    return dict(sorted(counts.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--profile-controls", type=Path, required=True)
    parser.add_argument("--svids", action="store_true")
    parser.add_argument("--wit-controls", type=Path)
    parser.add_argument("--x509-controls", type=Path)
    parser.add_argument("--combined-controls", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    phase = parser.add_mutually_exclusive_group(required=True)
    phase.add_argument("--qualify", action="store_true")
    phase.add_argument("--qualification-results", type=Path)
    args = parser.parse_args()

    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    peers = snapshot["peers"]
    qualify(peers, args.profile_controls)
    if args.svids:
        if not all((args.wit_controls, args.x509_controls, args.combined_controls)):
            parser.error("--svids requires WIT, X.509, and combined issuer controls")
        qualify_issuer(snapshot, args.wit_controls, "tba-wit-svid")
        qualify_issuer(snapshot, args.x509_controls, "tba-x509-svid")
        qualify_issuer(snapshot, args.combined_controls, COMBINED_SCOPE)
    plan = expanded_plan(peers, include_candidates=True, include_native=True, include_executions=True)
    if args.svids:
        rows = native_svid_policy_rows(plan)
        if Counter(map(policy_svid_scope, rows)) != SVID_COUNTS:
            raise ValueError("Expected the agreed 8,775 specialized SVID executions")
        controls = svid_policy_control_rows(rows)
        qualification_key = "native_svid_policy"
    else:
        rows = native_baseline_policy_rows(plan)
        if len(rows) != 2396:
            raise ValueError("Expected the agreed 2,396 baseline policy executions")
        controls = service_control_rows(rows)
        qualification_key = "native_baseline_policy"
    paths = sorted({tuple(hop["operation"] for hop in row["hops"]) for row in rows})
    record = {"version": peers[BASELINE_WORKLOAD_RECORD]["version"], "paths": paths}
    selected = controls if args.qualify else rows
    if not args.qualify:
        audit = audit_pytest_report(controls, args.qualification_results)
        if not audit["complete"]:
            raise ValueError("Native baseline policy qualification incomplete")
        audit_bindings(controls, audit)
        if args.svids:
            audit_svids(controls, audit)
        record["evidence"] = str(args.qualification_results.resolve())
    snapshot[qualification_key] = record

    args.output.mkdir(parents=True, exist_ok=False)
    runtime = (args.output / "qualification.json").resolve()
    runtime.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    ids = {row["id"] for row in selected}
    (args.output / "selection.json").write_text(json.dumps(sorted(ids)), encoding="utf-8")
    os.environ.update(TBA_WIMSE_PEER_SNAPSHOT=str(runtime), TBA_WIMSE_EXPANDED="1", TBA_WIMSE_INCLUDE_NATIVE="1",
                      TBA_WIMSE_NATIVE_BASELINE_POLICY="svid" if args.svids else "1",
                      TBA_WIMSE_SERVICE_CONTROLS=str(int(args.qualify)))
    for variable in ("TBA_WIMSE_EXECUTION_ID", "TBA_WIMSE_HOP_PATH", "TBA_WIMSE_NATIVE_ISSUER",
                     "TBA_WIMSE_NATIVE_WIT_ONLY", "TBA_WIMSE_NATIVE_ACQUISITION", "TBA_WIMSE_TYPED_SERVICE",
                     "TBA_WIMSE_NATIVE_BASELINE_WORKLOAD"):
        os.environ.pop(variable, None)
    target = Path(__file__).parent / "peer/test_candidate_executions.py"
    results = args.output / "results.xml"
    with (args.output / "attempts.jsonl").open("x", encoding="utf-8") as stream:
        tracker = AttemptJournal(stream, ids, "Native SVID policy" if args.svids else "Native baseline policy")
        options = ["-o", "addopts=", "-o", "junit_family=xunit1", "-p", "no:cacheprovider",
                   "-qq", "--junitxml", str(results), "--basetemp", str(args.output / "pytest-runtime"), str(target)]
        if args.workers > 1:
            options.extend(("-n", str(args.workers)))
        code = pytest.main(options, plugins=[tracker])
    audit = audit_pytest_report(selected, results)
    summary = {key: value for key, value in audit.items() if key != "results"}
    summary["bindings"] = audit_bindings(selected, audit)
    if args.svids:
        summary["svids"] = audit_svids(selected, audit)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary), flush=True)
    return code or int(not audit["complete"])


if __name__ == "__main__":
    raise SystemExit(main())
