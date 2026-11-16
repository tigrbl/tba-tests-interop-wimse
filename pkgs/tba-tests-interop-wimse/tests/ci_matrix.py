"""Shard a freshly qualified inventory and audit the resulting JUnit files."""

import argparse
from collections import Counter
import csv
import gzip
from hashlib import sha256
import json
from pathlib import Path
from xml.etree.ElementTree import ParseError

from expanded_blockers import case_key, rows
from tba_tests_interop_wimse.evidence import audit_pytest_report
from tba_tests_interop_wimse.native_expansion import expanded_plan


PUBLISHED_COUNT = 142_844
GROUPS = ("workload_executions", "planned_executions")
STATUSES = ("passed", "failed", "blocked", "setup-failure", "not-run")


def indexed_by_case(executions):
    indexed = {case_key(row): row for row in executions}
    if len(indexed) != len(executions) or len({row["id"] for row in executions}) != len(executions):
        raise ValueError("Inventory contains duplicate logical cases or execution IDs")
    return indexed


def read_inventory(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def prepare(args):
    published = indexed_by_case(rows(read_inventory(args.manifest)))
    if len(published) != PUBLISHED_COUNT:
        raise ValueError(f"Expected {PUBLISHED_COUNT} published IDs, got {len(published)}")
    if args.execution_id:
        published = {key: row for key, row in published.items() if row["id"] == args.execution_id}
        if not published:
            raise ValueError("Execution ID is outside the published inventory")
    peers = json.loads(args.snapshot.read_text(encoding="utf-8"))["peers"]
    inventory = expanded_plan(peers, include_candidates=True, include_native=True, include_executions=True)
    runtime = indexed_by_case(rows(inventory))
    if missing := published.keys() - runtime.keys():
        raise ValueError(f"Qualified inventory does not cover {len(missing)} published cases")

    shards = [[] for _ in range(1 if args.execution_id else args.shards)]
    for group in GROUPS:
        eligible = sorted(
            (published[key]["id"], row["id"]) for row in inventory[group]
            if (key := case_key(row)) in published
        )
        if not args.execution_id and len(eligible) < len(shards):
            raise ValueError(f"Too many shards for {group}")
        for index, (canonical, current) in enumerate(eligible):
            shards[index % len(shards)].append([canonical, current])

    args.output.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.output / "runtime.json.gz", "wt", encoding="utf-8") as stream:
        json.dump({group: inventory[group] for group in GROUPS}, stream)
    for index, pairs in enumerate(shards):
        (args.output / f"shard-{index}.json").write_text(
            json.dumps([current for _, current in pairs]), encoding="utf-8",
        )
    with gzip.open(args.output / "mapping.json.gz", "wt", encoding="utf-8") as stream:
        json.dump(shards, stream)
    (args.output / "scope.json").write_text(json.dumps({
        "execution_id": args.execution_id,
        "published_manifest_sha256": digest(args.manifest),
        "qualification_sha256": digest(args.snapshot),
    }) + "\n", encoding="utf-8")
    print(json.dumps(list(range(len(shards)))))


def aggregate(args):
    shards = read_inventory(args.plan / "mapping.json.gz")
    pairs = [pair for shard in shards for pair in shard]
    published = indexed_by_case(rows(read_inventory(args.manifest)))
    if len(published) != PUBLISHED_COUNT:
        raise ValueError(f"Expected {PUBLISHED_COUNT} published IDs, got {len(published)}")
    scope_path = args.plan / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8")) if scope_path.is_file() else {}
    if scope and scope["published_manifest_sha256"] != digest(args.manifest):
        raise ValueError("Published manifest digest differs from the planned run")
    if execution_id := scope.get("execution_id"):
        published = {key: row for key, row in published.items() if row["id"] == execution_id}
        if len(published) != 1:
            raise ValueError("Scoped execution ID is outside the published inventory")
    expected = {row["id"] for row in published.values()}
    if (len(pairs) != len(expected) or {canonical for canonical, _ in pairs} != expected
            or len({current for _, current in pairs}) != len(expected)):
        raise ValueError("Shard plan does not account for every selected published ID exactly once")
    runtime = indexed_by_case(rows(read_inventory(args.plan / "runtime.json.gz")))
    expected_pairs = {(canonical["id"], runtime[key]["id"]) for key, canonical in published.items()}
    if set(map(tuple, pairs)) != expected_pairs:
        raise ValueError("Shard plan contains incorrect published-to-runtime mappings")
    runtime = {row["id"]: row for row in runtime.values()}
    counts = Counter()
    errors = []
    blocked = Counter()
    reports = {}
    peer_results = {}
    authgent_report = args.plan / "authgent/results.xml"
    if (args.plan / "authgent/error.txt").exists():
        errors.append("Authgent runtime did not produce a complete report; see the plan artifact")
    if authgent_report.exists():
        authgent_rows = [row for _, current in pairs if (row := runtime[current]).get("hops")
                         and isinstance(row["hops"], list) and row["hops"][0].get("support") == "authgent"]
        try:
            authgent = audit_pytest_report(authgent_rows, authgent_report)
            if not authgent_rows or not authgent["complete"]:
                raise ValueError("Authgent evidence does not cover the selected Authgent runtime rows")
            peer_results.update(authgent["results"])
            reports["authgent"] = digest(authgent_report)
        except (OSError, ValueError, KeyError, ParseError) as error:
            errors.append(f"Authgent: {error}")
    args.output.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.output / "results.csv.gz", "wt", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("execution_id", "runtime_id", "shard", "status", "reason", "evidence"))
        for index, pairs in enumerate(shards):
            report = args.reports / f"interop-shard-{index}" / "results.xml"
            try:
                audit = audit_pytest_report(
                    [runtime[current] for _, current in pairs], report, allow_unrecorded=True,
                )
                reports[str(index)] = digest(report)
                if audit["unrecorded"]:
                    errors.append(f"Shard {index}: {audit['unrecorded']} JUnit items lack runtime evidence")
            except (OSError, ValueError, KeyError, ParseError) as error:
                errors.append(f"Shard {index}: {error}")
                audit = {"results": {}}
            for canonical, current in pairs:
                result = audit["results"].get(current, {"status": "not-run", "attempts": []})
                evidence = f"interop-shard-{index}/results.xml" if result["attempts"] else ""
                if current in peer_results and result["status"] in {"blocked", "not-run"}:
                    result = peer_results[current]
                    evidence = "authgent/results.xml"
                status = result["status"]
                attempts = result["attempts"]
                reason = attempts[-1].get("reason", "") if attempts else "No validated JUnit result"
                counts[status] += 1
                if status == "blocked":
                    category = reason.split(":", 1)[0].replace("qualification pending (", "Qualification pending for ")
                    blocked[category if reason.startswith("qualification pending") else reason] += 1
                writer.writerow((canonical, current, index, status, reason, evidence))
    summary = {"total": len(expected), "shards": len(shards),
               "scope": "single" if scope.get("execution_id") else "full",
               "counts": {status: counts[status] for status in STATUSES}, "errors": errors,
               "complete": not errors and not counts["not-run"],
               "blocked_reasons": dict(blocked.most_common())}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    provenance = {**scope, "mapping_sha256": digest(args.plan / "mapping.json.gz"),
                  "runtime_sha256": digest(args.plan / "runtime.json.gz"),
                  "results_sha256": digest(args.output / "results.csv.gz"), "junit_sha256": reports}
    (args.output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    lines = ["## WIMSE interoperability", "", f"Selected published cases: **{len(expected):,}** across {len(shards)} shards.",
             "", "| Outcome | Cases |", "| --- | ---: |"]
    lines.extend(f"| {status} | {counts[status]:,} |" for status in STATUSES)
    if blocked:
        lines.extend(("", "### Most common blockers", "",
                      *[f"- {count:,} — {reason}" for reason, count in blocked.most_common(10)]))
    if errors:
        lines.extend(("", "### Report errors", *[f"- {error}" for error in errors]))
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return int(bool(errors or counts["failed"] or counts["setup-failure"] or counts["not-run"]
                    or (args.require_all_pass and counts["blocked"])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("prepare")
    plan.add_argument("--manifest", required=True, type=Path)
    plan.add_argument("--snapshot", required=True, type=Path)
    plan.add_argument("--shards", required=True, type=int, choices=(1, 4, 8, 16, 32, 64))
    plan.add_argument("--output", required=True, type=Path)
    plan.add_argument("--execution-id", help="Run one exact published ID instead of the full matrix")
    collect = commands.add_parser("aggregate")
    collect.add_argument("--manifest", required=True, type=Path)
    collect.add_argument("--plan", required=True, type=Path)
    collect.add_argument("--reports", required=True, type=Path)
    collect.add_argument("--output", required=True, type=Path)
    collect.add_argument("--require-all-pass", action="store_true")
    args = parser.parse_args()
    return prepare(args) if args.command == "prepare" else aggregate(args)


if __name__ == "__main__":
    raise SystemExit(main())
