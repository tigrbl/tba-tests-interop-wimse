"""Qualify and execute all 728 short TbA baseline workload cases."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
from xml.etree import ElementTree

import pytest

from run_native_wit_svid_batch import AttemptJournal
from support.qualification_overlay import wic_source_digest
from tba_test_interop_wimse.evidence import audit_pytest_report
from tba_test_interop_wimse.native_expansion import (
    BASELINE_WORKLOAD_RECORD, expanded_plan, native_baseline_workload_rows,
)


def qualify(peers, controls):
    version = "sha256:" + wic_source_digest()
    roles = {
        role: {(row["profile"], row["identifier_scheme"], row["configuration"])
               for row in peers["capabilities"]
               if row["implementation"] == "tba" and row["role"] == role
               and row.get("version") == version and row["status"] == "qualified"}
        for role in ("caller", "receiver")
    }
    profiles = roles["caller"] & roles["receiver"]
    observed = Counter()
    for item in ElementTree.parse(controls).iter("testcase"):
        if any(item.find(name) is not None for name in ("failure", "error", "skipped")):
            raise ValueError("A native baseline workload control did not pass")
        evidence = {prop.get("name"): prop.get("value") for prop in item.findall("./properties/property")}
        observed[tuple(evidence[key] for key in
                       ("profile", "identifier_scheme", "configuration", "decision", "effects"))] += 1
    expected = Counter((*profile, decision, effects) for profile in profiles
                       for decision, effects in (("allow", "1"), ("deny", "0")))
    if len(profiles) != 8 or observed != expected:
        raise ValueError("Expected one allow and one refusal per pinned native baseline profile")
    peers[BASELINE_WORKLOAD_RECORD] = {
        "version": version, "profiles": sorted(profiles), "evidence": str(controls.resolve()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    qualify(snapshot["peers"], args.controls)
    plan = expanded_plan(snapshot["peers"], include_candidates=True, include_native=True, include_executions=True)
    selected = native_baseline_workload_rows(plan)
    ids = {row["id"] for row in selected}
    if (len(ids) != len(selected) or Counter(row["hop_count"] for row in selected) != {1: 220, 2: 508}
            or any(row["status"] != "qualified" for row in selected)):
        raise ValueError("Native baseline selection differs from the agreed 728 qualified IDs")
    args.output.mkdir(parents=True, exist_ok=False)
    runtime = (args.output / "qualification.json").resolve()
    runtime.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    (args.output / "selection.json").write_text(json.dumps(sorted(ids)), encoding="utf-8")
    os.environ.update(TBA_WIMSE_PEER_SNAPSHOT=str(runtime), TBA_WIMSE_EXPANDED="1",
                      TBA_WIMSE_INCLUDE_NATIVE="1", TBA_WIMSE_NATIVE_BASELINE_WORKLOAD="1")
    for variable in ("TBA_WIMSE_EXECUTION_ID", "TBA_WIMSE_HOP_PATH", "TBA_WIMSE_NATIVE_ISSUER",
                     "TBA_WIMSE_NATIVE_WIT_ONLY", "TBA_WIMSE_NATIVE_ACQUISITION", "TBA_WIMSE_TYPED_SERVICE",
                     "TBA_WIMSE_NATIVE_BASELINE_POLICY"):
        os.environ.pop(variable, None)
    target = Path(__file__).parent / "peer/test_candidate_executions.py"
    results = args.output / "results.xml"
    with (args.output / "attempts.jsonl").open("x", encoding="utf-8") as stream:
        tracker = AttemptJournal(stream, ids, "Native baseline workload")
        code = pytest.main(["-o", "addopts=", "-o", "junit_family=xunit1", "-p", "no:cacheprovider",
                            "-qq", "--junitxml", str(results), "--basetemp", str(args.output / "pytest-runtime"),
                            str(target)], plugins=[tracker])
    audit = audit_pytest_report(selected, results)
    summary = {key: value for key, value in audit.items() if key != "results"}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary), flush=True)
    return code or int(not audit["complete"])


if __name__ == "__main__":
    raise SystemExit(main())
