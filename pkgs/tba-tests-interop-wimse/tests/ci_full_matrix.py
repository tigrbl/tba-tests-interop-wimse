"""Reconcile the published full matrix against the hosted execution reports."""

from argparse import ArgumentParser
from collections import Counter, defaultdict
import csv
import gzip
from hashlib import sha256
import json
from pathlib import Path


GROUPS = ("workload_executions", "planned_executions")
EXPECTED = {"baseline": 142_844, "rich-workload": 1_136, "rich-typed": 5_102, "nine-hop": 12_288}
STATUS = {
    "passed": "pass", "failed": "fail", "blocked": "blocked",
    "pass": "pass", "fail": "fail", "not-run": "blocked", "setup-failure": "blocked",
}
RICH = "rich-hackathon"


def read_inventory(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def named_rows(baseline, expanded):
    inventory = {}
    counts = Counter()
    for group in GROUPS:
        old, new = baseline[group], expanded[group]
        if new[:len(old)] != old:
            raise ValueError(f"The expanded inventory changed a published {group} row")
        for index, row in enumerate(new):
            if index < len(old):
                lane = "baseline"
            elif row.get("named_scenario_id") == "ietf127-b-chain":
                lane = "nine-hop"
            elif group == "workload_executions":
                lane = "rich-workload"
            else:
                lane = "rich-typed"
            execution_id = row["id"]
            if execution_id in inventory:
                raise ValueError(f"Duplicate published ID {execution_id}")
            inventory[execution_id] = (lane, row)
            counts[lane] += 1
    if dict(counts) != EXPECTED or len(inventory) != 161_370:
        raise ValueError(f"Unexpected published inventory partition: {counts}")
    return inventory


def read_results(path, opener, expected, source_summary, source_counts):
    with opener(path, "rt", encoding="utf-8", newline="") as stream:
        rows = {}
        counts = Counter()
        for row in csv.DictReader(stream):
            execution_id = row["execution_id"]
            if execution_id in rows or execution_id not in expected:
                raise ValueError(f"Duplicate or unexpected result in {path.name}: {execution_id}")
            rows[execution_id] = row
            counts[row["status"]] += 1
        if rows.keys() != expected:
            raise ValueError(f"{path.name} is missing {len(expected - rows.keys())} published IDs")
        if counts != Counter(source_summary["counts"]) or set(counts) - source_counts:
            raise ValueError(f"{path.name} does not reconcile with its source summary")
    return rows


def rich_blocker(lane, row):
    if lane == "rich-workload":
        roles = sorted({
            f"{side}:{endpoint['configuration']}"
            for pair in row["pairs"].values() for side, endpoint in pair.items()
            if endpoint["implementation"] == RICH
        })
        if not roles:
            raise ValueError("RICH workload candidate has no RICH endpoint")
        if not row["pending_endpoints"] or not row["missing_baselines"]:
            raise ValueError("RICH workload candidate requires runtime reconciliation")
        return "RICH workload endpoint and directional baseline unqualified", roles
    roles = sorted({
        f"{side}:{pin[2]}"
        for hop in row["hops"] for side in ("caller", "receiver")
        if (pin := hop.get(f"{side}_pin")) and pin[0] == RICH
    })
    if not roles:
        raise ValueError("RICH typed candidate has no RICH endpoint")
    return "RICH generic typed-hop runtime adapter unavailable", roles


def aggregate(args):
    expanded = read_inventory(args.expanded)
    inventory = named_rows(read_inventory(args.baseline), expanded)
    expected = defaultdict(set)
    for execution_id, (lane, _) in inventory.items():
        expected[lane].add(execution_id)
    baseline_summary = json.loads((args.baseline_report / "summary.json").read_text(encoding="utf-8"))
    provenance = json.loads((args.baseline_report / "provenance.json").read_text(encoding="utf-8"))
    baseline_csv = args.baseline_report / "results.csv.gz"
    if (provenance["published_manifest_sha256"] != sha256(args.baseline.read_bytes()).hexdigest()
            or provenance["results_sha256"] != sha256(baseline_csv.read_bytes()).hexdigest()):
        raise ValueError("Baseline input or results differ from their recorded SHA-256")
    nine_summary = json.loads((args.nine_hop_report / "summary.json").read_text(encoding="utf-8"))
    baseline = read_results(baseline_csv, gzip.open, expected["baseline"], baseline_summary,
                            {"passed", "failed", "blocked", "not-run", "setup-failure"})
    named = read_results(args.nine_hop_report / "per-id.csv", open, expected["nine-hop"], nine_summary,
                         {"pass", "fail", "blocked"})

    args.output.mkdir(parents=True, exist_ok=True)
    counts = {lane: Counter({"pass": 0, "fail": 0, "blocked": 0}) for lane in EXPECTED}
    blockers = defaultdict(Counter)
    rich_roles = defaultdict(Counter)
    rich_sequences = Counter()
    infrastructure = Counter()
    with gzip.open(args.output / "per-id.csv.gz", "wt", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("execution_id", "lane", "status", "source_status", "reason", "rich_roles",
                         "hop_sequence_id", "runtime_id", "shard", "evidence"))
        for execution_id, (lane, row) in inventory.items():
            details = {}
            roles = []
            if lane in ("baseline", "nine-hop"):
                details = (baseline if lane == "baseline" else named)[execution_id]
                source_status = details["status"]
                status = STATUS[source_status]
                reason = details["reason"]
                if source_status in ("not-run", "setup-failure"):
                    infrastructure[source_status] += 1
                    reason = f"Infrastructure {source_status}: {reason}"
            else:
                status, source_status = "blocked", "preflight-blocked"
                reason, roles = rich_blocker(lane, row)
                rich_roles[lane][" + ".join(roles)] += 1
                rich_sequences[row["hop_sequence_id"]] += 1
            if status == "blocked":
                blockers[lane][reason] += 1
            counts[lane][status] += 1
            writer.writerow((execution_id, lane, status, source_status, reason, " ".join(roles),
                             row["hop_sequence_id"], details.get("runtime_id", ""), details.get("shard", ""),
                             details.get("evidence", "")))
    totals = Counter({"pass": 0, "fail": 0, "blocked": 0})
    for lane_counts in counts.values():
        totals.update(lane_counts)
    summary = {
        "total": len(inventory), "counts": totals, "lanes": counts,
        "blocked_reasons": {lane: dict(reasons.most_common()) for lane, reasons in blockers.items()},
        "rich_blocked_by_role_assignment": rich_roles,
        "rich_blocked_by_sequence": dict(rich_sequences.most_common()),
        "infrastructure_outcomes": infrastructure,
        "baseline_errors": baseline_summary.get("errors", []),
        "manifest_sha256": sha256(args.expanded.read_bytes()).hexdigest(),
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = [
        "## Full WIMSE interoperability matrix", "",
        "| Lane | Passed | Failed | Blocked |", "| --- | ---: | ---: | ---: |",
    ]
    for lane, lane_counts in (*counts.items(), ("**Total**", totals)):
        lines.append(f"| {lane} | {lane_counts['pass']:,} | {lane_counts['fail']:,} | {lane_counts['blocked']:,} |")
    lines.extend(("", "### Blockers", ""))
    for lane, reasons in blockers.items():
        lines.extend(f"- {count:,} {lane} — {reason}" for reason, count in reasons.most_common())
    if infrastructure:
        lines.extend(("", "Infrastructure outcomes are included in blocked counts and flagged in the per-ID file."))
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return int(bool(infrastructure or not baseline_summary["complete"] or totals["fail"]))


def main():
    parser = ArgumentParser(description=__doc__)
    for path in ("baseline", "expanded", "baseline-report", "nine-hop-report", "output"):
        parser.add_argument("--" + path, required=True, type=Path)
    return aggregate(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
