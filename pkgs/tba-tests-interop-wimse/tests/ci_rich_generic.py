"""Partition and collect the generic RICH portion of the published matrix."""
from argparse import ArgumentParser
from collections import Counter
import csv
import gzip
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from ci_full_matrix import EXPECTED, named_rows, read_inventory
from tba_tests_interop_wimse.hop_runner import hop_mismatches
from tba_tests_interop_wimse.observations import Observation, mismatches


RICH_LANES = ("rich-workload", "rich-typed")


def selection(baseline, expanded):
    return [(lane, row) for lane, row in named_rows(read_inventory(baseline), read_inventory(expanded)).values()
            if lane in RICH_LANES]


def prepare(args):
    from support.rich_generic import qualify_rich

    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    with TemporaryDirectory() as directory:
        baselines = qualify_rich(snapshot["peers"], directory)
    (args.plan / "rich-generic-qualification.json").write_text(json.dumps({
        "snapshot_sha256": sha256(args.snapshot.read_bytes()).hexdigest(),
        "manifest_sha256": sha256(args.expanded.read_bytes()).hexdigest(),
        "baselines": baselines,
    }, indent=2) + "\n", encoding="utf-8")
    shard_count = len(read_inventory(args.plan / "mapping.json.gz"))
    shards = [[] for _ in range(shard_count)]
    for index, (lane, row) in enumerate(selection(args.baseline, args.expanded)):
        shards[index % shard_count].append(row["id"])
    for index, ids in enumerate(shards):
        (args.plan / f"rich-shard-{index}.json").write_text(json.dumps(ids), encoding="utf-8")


def collect(args):
    qualification = args.plan / "rich-generic-qualification.json"
    qualified = json.loads(qualification.read_text(encoding="utf-8"))
    if qualified["manifest_sha256"] != sha256(args.expanded.read_bytes()).hexdigest():
        raise ValueError("RICH qualification was recorded against a different published inventory")
    if len(qualified["baselines"]) != 4 or any(
        control["observation"] != {"decision": "allow", "effects": 1} or control["outcome"] != "pass"
        for control in qualified["baselines"]
    ):
        raise ValueError("All four distinct RICH directions require passing runtime controls")
    expected = {row["id"]: (lane, row) for lane, row in selection(args.baseline, args.expanded)}
    scenarios = {case["id"]: case for case in read_inventory(args.expanded)["scenario_definitions"]}
    results = {}
    errors = []
    for path in sorted(args.plan.glob("rich-shard-*.json")):
        shard = path.stem.removeprefix("rich-shard-")
        ids = set(json.loads(path.read_text(encoding="utf-8")))
        evidence = args.reports / f"interop-shard-{shard}" / "rich-generic.jsonl"
        if not evidence.is_file():
            errors.append(f"Missing RICH evidence for shard {shard}")
            continue
        for line in evidence.read_text(encoding="utf-8").splitlines():
            result = json.loads(line)
            key = result["execution_id"]
            if key not in ids or key in results:
                raise ValueError(f"Unexpected or duplicate RICH result {key}")
            lane, row = expected[key]
            status = result["status"]
            if status == "passed":
                if lane == "rich-typed":
                    disagreements = hop_mismatches(row, result["observation"])
                else:
                    case = scenarios[row["scenario_id"]]
                    observation = result["observation"]
                    disagreements = mismatches(case, Observation(**{**observation, "events": tuple(observation["events"])}))
                if disagreements:
                    raise ValueError(f"RICH pass disagrees with oracle for {key}: {disagreements}")
            elif status not in {"blocked", "failed", "setup-failure"} or not result["reason"]:
                raise ValueError(f"Invalid RICH result for {key}")
            results[key] = {**result, "shard": shard, "evidence": str(evidence.relative_to(args.reports))}
    args.output.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    with gzip.open(args.output / "results.csv.gz", "wt", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("execution_id", "status", "reason", "shard", "evidence"))
        for key in expected:
            result = results.get(key, {"status": "not-run", "reason": "No validated RICH shard result"})
            counts[result["status"]] += 1
            writer.writerow((key, result["status"], result["reason"], result.get("shard", ""),
                             result.get("evidence", "")))
    summary = {"total": sum(EXPECTED[lane] for lane in RICH_LANES), "counts": counts, "errors": errors,
               "complete": not errors and not counts["not-run"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (args.output / qualification.name).write_text(json.dumps(qualified, indent=2) + "\n", encoding="utf-8")
    return int(bool(not summary["complete"] or counts["failed"] or counts["setup-failure"]))


def main():
    parser = ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command, paths in (("prepare", ("snapshot",)), ("collect", ("reports", "output"))):
        mode = commands.add_parser(command)
        for key in ("baseline", "expanded", "plan", *paths):
            mode.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    return (prepare if args.command == "prepare" else collect)(args)


if __name__ == "__main__":
    raise SystemExit(main())
