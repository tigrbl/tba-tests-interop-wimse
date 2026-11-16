"""Qualify native support services without running the full execution inventory."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from run_native_baseline_policy_batch import audit_bindings, audit_svids
from run_typed_service_batch import audit_acquisitions, audit_acquired_policy
from support.qualification_overlay import wic_source_digest
from tba_tests_interop_wimse.evidence import audit_pytest_report
from tba_tests_interop_wimse.native_expansion import BASELINE_WORKLOAD_RECORD, expanded_plan
from typed_service_selection import (
    acquisition_control_rows, native_acquisition_rows, native_baseline_policy_rows, native_svid_policy_rows,
    service_control_rows, svid_policy_control_rows, typed_service_rows,
)


def run_controls(snapshot, output, controls, **selection):
    path = output / "qualification.json"
    path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    report = output / "results.xml"
    pytest_file = Path(__file__).parent / "peer/test_candidate_executions.py"
    env = {key: value for key, value in os.environ.items() if key not in {
        "TBA_WIMSE_EXECUTION_ID", "TBA_WIMSE_EXECUTION_SELECTION", "TBA_WIMSE_FROZEN_MANIFEST", "TBA_WIMSE_HOP_PATH",
        "TBA_WIMSE_NATIVE_WIT_ONLY", "TBA_WIMSE_NATIVE_ISSUER", "TBA_WIMSE_NATIVE_BASELINE_WORKLOAD",
        "TBA_WIMSE_TYPED_SERVICE", "TBA_WIMSE_NATIVE_ACQUISITION", "TBA_WIMSE_NATIVE_BASELINE_POLICY",
        "TBA_WIMSE_GO_SPIFFE_ONLY",
    }}
    env.update(TBA_WIMSE_PEER_SNAPSHOT=str(path), TBA_WIMSE_EXPANDED="1", TBA_WIMSE_INCLUDE_NATIVE="1",
               TBA_WIMSE_SERVICE_CONTROLS="1", **selection)
    subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "junit_family=xunit1",
                    "--junitxml", str(report), "--basetemp", str(output / "pytest"), str(pytest_file)],
                   env=env, check=True)
    audit = audit_pytest_report(controls, report)
    if not audit["complete"]:
        raise ValueError(f"{output.name} controls did not fully pass: {audit['counts']}")
    return audit


def qualify_services(snapshot, source, output):
    fingerprint = "sha256:" + wic_source_digest()
    peers = snapshot["peers"]
    if peers.get(BASELINE_WORKLOAD_RECORD, {}).get("version") != fingerprint:
        raise ValueError("Native endpoint controls must match this fixture build")
    plan = expanded_plan(peers, include_candidates=True, include_native=True, include_executions=True)
    output.mkdir(parents=True, exist_ok=False)

    for stage, rows, controls, selection in (
        ("native_baseline_policy", native_baseline_policy_rows(plan), service_control_rows,
         {"TBA_WIMSE_NATIVE_BASELINE_POLICY": "1"}),
        ("native_svid_policy", native_svid_policy_rows(plan), svid_policy_control_rows,
         {"TBA_WIMSE_NATIVE_BASELINE_POLICY": "svid"}),
        ("native_acquisition_qualification", native_acquisition_rows(plan), acquisition_control_rows,
         {"TBA_WIMSE_NATIVE_ACQUISITION": "1"}),
        ("native_specialized_acquisition_qualification", native_acquisition_rows(plan, specialized=True),
         lambda rows: acquisition_control_rows(rows, specialized=True), {"TBA_WIMSE_NATIVE_ACQUISITION": "specialized"}),
        ("typed_service_qualification", typed_service_rows(plan), service_control_rows, {"TBA_WIMSE_TYPED_SERVICE": "1"}),
    ):
        batch = output / stage
        batch.mkdir()
        if source.with_suffix(".cred").is_dir():
            shutil.copytree(source.with_suffix(".cred"), batch / "qualification.cred")
        if stage.endswith("_policy"):
            snapshot[stage] = dict(version=fingerprint,
                                   paths=sorted({tuple(hop["operation"] for hop in row["hops"]) for row in rows}))
        selected = controls(rows)
        if not selected:
            raise ValueError(f"No controls for {stage}")
        audit = run_controls(snapshot, batch, selected, **selection)
        evidence = f"{stage}/results.xml"
        if stage.endswith("_policy"):
            audit_bindings(selected, audit)
            if stage == "native_svid_policy":
                audit_svids(selected, audit)
            snapshot[stage]["evidence"] = evidence
        else:
            if "acquisition" in stage:
                audit_acquisitions(audit)
            if stage == "native_specialized_acquisition_qualification":
                audit_acquired_policy(selected, audit)
            snapshot[stage] = evidence
        print(f"{stage}: {len(selected)} controls passed for {len(rows)} cases", flush=True)

    target = output / "qualification.json"
    if source.with_suffix(".cred").is_dir():
        shutil.copytree(source.with_suffix(".cred"), target.with_suffix(".cred"))
    if (controls := source.parent / "native-controls.json").is_file():
        shutil.copyfile(controls, output / controls.name)
    target.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    qualify_services(json.loads(args.snapshot.read_text(encoding="utf-8")), args.snapshot, args.output.resolve())


if __name__ == "__main__":
    main()
