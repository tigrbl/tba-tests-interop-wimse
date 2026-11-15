"""Run the outstanding existing-peer three-call cases with incremental evidence."""

import argparse
import json
import os
from collections import Counter
from pathlib import Path

import pytest

from support.typed_workload_chain import TypedWorkloadChain
from tba_tests_interop_wimse.evidence import audit_pytest_report
from tba_tests_interop_wimse.native_expansion import expanded_plan


def logical_key(row):
    # Compare case history across fixture revisions while keeping exact IDs in results.
    return json.dumps([row["outcome_id"], [
        {key: [value[0], value[2]] if key.endswith("_pin") and value[0] == "tba" else value
         for key, value in hop.items()}
        for hop in row["hops"]
    ]], sort_keys=True)


def snapshot(path):
    return json.loads(path.read_text(encoding="utf-8"))["peers"]


class BatchEvidence:
    def __init__(self, rows, output):
        self.ids = {row["id"] for row in rows}
        self.output = output
        self.counts = Counter()

    def pytest_collection_modifyitems(self, config, items):
        selected = [item for item in items if item.callspec.params["hop_execution"]["id"] in self.ids]
        if len(selected) != len(self.ids):
            raise pytest.UsageError("Three-call batch collection does not match the selected IDs")
        removed = [item for item in items if item.callspec.params["hop_execution"]["id"] not in self.ids]
        config.hook.pytest_deselected(items=removed)
        items[:] = selected

    def pytest_runtest_logreport(self, report):
        properties = dict(report.user_properties)
        if report.when == "call" and "execution_result" in properties:
            result = json.loads(properties["execution_result"])
        elif report.when == "setup" and report.outcome != "passed":
            result = {"execution_id": report.nodeid.rsplit("[", 1)[-1].removesuffix("]"),
                      "status": "setup-failure", "reason": str(report.longrepr)}
        else:
            return
        self.output.write(json.dumps(result, sort_keys=True) + "\n")
        self.output.flush()
        self.counts[result["status"]] += 1
        total = sum(self.counts.values())
        if total == 1 or total % 100 == 0:
            print(f"Three-call runtime {total}/{len(self.ids)} {dict(self.counts)}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--pilot-snapshot", type=Path, required=True)
    parser.add_argument("--pilot-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--retry-attempts", type=Path, help="Retry failed IDs from a completed attempt log")
    args = parser.parse_args()
    peers = snapshot(args.snapshot)
    current = expanded_plan(peers, include_candidates=True, include_executions=True)["planned_executions"]
    pilot = expanded_plan(snapshot(args.pilot_snapshot), include_candidates=True,
                          include_executions=True)["planned_executions"]
    evidence = audit_pytest_report(pilot, args.pilot_report)["results"]
    passed = {logical_key(row) for row in pilot if evidence[row["id"]]["status"] == "passed"}
    chain = TypedWorkloadChain(peers)
    rows = [row for row in current if tuple(hop["operation"] for hop in row["hops"]) == ("call",) * 3
            and chain.supports(row) and logical_key(row) not in passed]
    if len(rows) != 23408 or len(passed) != 266:
        parser.error(f"Expected 23,408 cases and 266 prior passes, got {len(rows)} and {len(passed)}")
    if args.retry_attempts:
        with args.retry_attempts.open(encoding="utf-8") as source:
            previous = [json.loads(line) for line in source]
        if len(previous) != len(rows) or {row["execution_id"] for row in previous} != {r["id"] for r in rows}:
            parser.error("Retry log must cover the exact original selection")
        remaining = {row["execution_id"] for row in previous if row["status"] != "passed"}
        rows = [row for row in rows if row["id"] in remaining]
        if not rows:
            parser.error("Retry log contains no remaining cases")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "selection.json").write_text(json.dumps([row["id"] for row in rows]), encoding="utf-8")
    os.environ.update(TBA_WIMSE_PEER_SNAPSHOT=str(args.snapshot.resolve()),
                      TBA_WIMSE_EXPANDED="1", TBA_WIMSE_HOP_PATH="call,call,call")
    os.environ.pop("TBA_WIMSE_EXECUTION_ID", None)
    os.environ.pop("TBA_WIMSE_INCLUDE_NATIVE", None)
    target = Path(__file__).parent / "peer/test_candidate_executions.py"
    print(f"Launching {len(rows)} three-call IDs against {args.snapshot}", flush=True)
    with (args.output / "attempts.jsonl").open("x", encoding="utf-8") as output:
        tracker = BatchEvidence(rows, output)
        result = pytest.main(["-o", "addopts=", "-o", "junit_family=xunit1", "-p", "no:cacheprovider",
                              "-qq", "--junitxml", str(args.output / "results.xml"), str(target)],
                             plugins=[tracker])
        print(f"Three-call final {dict(tracker.counts)}", flush=True)
        incomplete = (sum(tracker.counts.values()) != len(rows)
                      or bool(set(tracker.counts) - {"passed", "failed"}))
    return result or int(incomplete)


if __name__ == "__main__":
    raise SystemExit(main())
