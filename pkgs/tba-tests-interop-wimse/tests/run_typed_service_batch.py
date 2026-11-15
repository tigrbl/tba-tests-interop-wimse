"""Qualify and execute the exact typed-service tranche."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shutil

import pytest

from run_native_wit_svid_batch import AttemptJournal, qualify
from tba_tests_interop_wimse.evidence import audit_pytest_report
from tba_tests_interop_wimse.native_expansion import COMBINED_SCOPE, expanded_plan
from typed_service_selection import acquisition_control_rows, native_acquisition_rows, service_control_rows, typed_service_rows


def audit_acquisitions(audit):
    acquisition_counts = {"delivered": 0, "refused": 0, "next_mtls_verified": 0}
    for case in audit["results"].values():
        if case["status"] != "passed":
            continue
        attempt, = case["attempts"]
        first, *downstream = attempt["observation"]["trace"]
        if first["operation"] != "acquire":
            raise ValueError("Expected acquisition at hop one")
        if first["decision"] == "deny":
            if first["grpc_status"] != "PERMISSION_DENIED" or downstream or "acquired_sha256" in first:
                raise ValueError("Refused acquisition produced credentials or reached downstream")
            acquisition_counts["refused"] += 1
            continue
        fingerprint = bytes.fromhex(first["acquired_sha256"])
        if first["decision"] != "allow" or first["grpc_status"] != "OK" or len(fingerprint) != 32:
            raise ValueError("Missing Workload API delivery evidence")
        acquisition_counts["delivered"] += 1
        if downstream:
            if downstream[0]["presented_peer_sha256"] != first["acquired_sha256"]:
                raise ValueError("Next mTLS receiver saw a different certificate")
            acquisition_counts["next_mtls_verified"] += 1
    return acquisition_counts


def audit_acquired_policy(rows, audit):
    counts = Counter()
    for row in rows:
        case = audit["results"][row["id"]]
        if case["status"] != "passed":
            continue
        attempt, = case["attempts"]
        observed = attempt["observation"]
        trace = observed["trace"]
        if len(trace) < 3:
            assert observed["effects"] == 0
            continue
        terminal = trace[-1]
        assert terminal["support_role"] == row["hops"][-1]["support"] and terminal["initially_allowed"]
        assert (terminal["decision"], observed["effects"]) in {("allow", 1), ("deny", 0)}
        counts[f"{terminal['support_role']}:{terminal['decision']}"] += 1
        if terminal["result"] == "issuer-revocation-refused":
            assert terminal["verified_revocation_source"] == "issuer"
        elif terminal["result"] == "holder-self-revocation-refused":
            assert terminal["verified_revocation_source"] == "holder"
    return dict(sorted(counts.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--wit-controls", type=Path, required=True)
    parser.add_argument("--x509-controls", type=Path, required=True)
    parser.add_argument("--combined-controls", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    tranche = parser.add_mutually_exclusive_group()
    tranche.add_argument("--native-acquisition", action="store_true")
    tranche.add_argument("--specialized-acquisition", action="store_true")
    phase = parser.add_mutually_exclusive_group(required=True)
    phase.add_argument("--qualify", action="store_true")
    phase.add_argument("--qualification-results", type=Path)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    qualify(snapshot, args.wit_controls, "tba-wit-svid")
    qualify(snapshot, args.x509_controls, "tba-x509-svid")
    qualify(snapshot, args.combined_controls, COMBINED_SCOPE)
    plan = expanded_plan(snapshot["peers"], include_candidates=True, include_native=True, include_executions=True)
    native_acquisition = args.native_acquisition or args.specialized_acquisition
    if native_acquisition:
        rows = native_acquisition_rows(plan, specialized=args.specialized_acquisition)
        expected_ids = 105 if args.specialized_acquisition else 627
        if len(rows) != expected_ids:
            raise ValueError(f"Acquisition selection differs from the agreed {expected_ids} IDs")
        controls = acquisition_control_rows(rows, specialized=args.specialized_acquisition)
        qualification_key = (
            "native_specialized_acquisition_qualification" if args.specialized_acquisition
            else "native_acquisition_qualification"
        )
    else:
        rows = typed_service_rows(plan)
        if len(rows) != 21140 or sum("native_stage" in row for row in rows) != 14899:
            raise ValueError("Service selection differs from the agreed 21,140 IDs")
        controls = service_control_rows(rows)
        qualification_key = "typed_service_qualification"
    if args.qualify:
        selected = controls
    else:
        qualification = audit_pytest_report(controls, args.qualification_results)
        if not qualification["complete"]:
            raise ValueError("Typed-service qualification incomplete")
        if native_acquisition:
            audit_acquisitions(qualification)
        if args.specialized_acquisition:
            audit_acquired_policy(controls, qualification)
        snapshot[qualification_key] = str(args.qualification_results.resolve())
        selected = rows
    ids = {row["id"] for row in selected}
    args.output.mkdir(parents=True, exist_ok=False)
    runtime = (args.output / "qualification.json").resolve()
    runtime.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    if not native_acquisition:
        shutil.copytree(args.snapshot.with_suffix(".cred"), runtime.with_suffix(".cred"))
    (args.output / "selection.json").write_text(json.dumps(sorted(ids)), encoding="utf-8")
    os.environ.update(
        TBA_WIMSE_PEER_SNAPSHOT=str(runtime), TBA_WIMSE_EXPANDED="1", TBA_WIMSE_INCLUDE_NATIVE="1",
        TBA_WIMSE_TYPED_SERVICE=str(int(not native_acquisition)),
        TBA_WIMSE_NATIVE_ACQUISITION="specialized" if args.specialized_acquisition else str(int(native_acquisition)),
        TBA_WIMSE_SERVICE_CONTROLS=str(int(args.qualify)),
    )
    for variable in ("TBA_WIMSE_NATIVE_WIT_ONLY", "TBA_WIMSE_NATIVE_ISSUER", "TBA_WIMSE_EXECUTION_ID",
                     "TBA_WIMSE_HOP_PATH"):
        os.environ.pop(variable, None)
    target = Path(__file__).parent / "peer/test_candidate_executions.py"
    results = args.output / "results.xml"
    with (args.output / "attempts.jsonl").open("x", encoding="utf-8") as stream:
        label = "Native credential acquisition" if native_acquisition else "Typed service"
        tracker = AttemptJournal(stream, ids, label)
        options = ["-o", "addopts=", "-o", "junit_family=xunit1", "-p", "no:cacheprovider",
                   "-qq", "--junitxml", str(results),
                   "--basetemp", str(args.output / "pytest-runtime"), str(target)]
        if args.workers > 1:
            options.extend(("-n", str(args.workers)))
        print(f"{label}: running {len(ids)} cases", flush=True)
        code = pytest.main(options, plugins=[tracker])
    audit = audit_pytest_report(selected, results)
    summary = {key: val for key, val in audit.items() if key != "results"}
    if native_acquisition:
        summary["workload_api"] = audit_acquisitions(audit)
    if args.specialized_acquisition:
        summary["policy"] = audit_acquired_policy(selected, audit)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary), flush=True)
    return code or int(not audit["complete"])


if __name__ == "__main__":
    raise SystemExit(main())
