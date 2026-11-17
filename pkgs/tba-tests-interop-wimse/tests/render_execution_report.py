"""Turn an audited full-matrix report into a self-contained browser view."""

from argparse import ArgumentParser
from base64 import b64encode
from collections import Counter, defaultdict
import csv
import gzip
from hashlib import sha256
from html import escape
import json
from pathlib import Path

from ci_full_matrix import GROUPS, read_inventory


PAGES_HIT_BADGE = (
    '<p><a href="https://hits.sh/tigrbl.github.io/tba-tests-interop-wimse/">'
    '<img alt="Results site hits" referrerpolicy="no-referrer" '
    'src="https://hits.sh/tigrbl.github.io/tba-tests-interop-wimse.svg?label=Results%20site%20hits">'
    '</a></p>'
)


def planned_hops(case):
    if "hops" in case:
        for hop in case["hops"]:
            caller, receiver = (hop.get(f"{side}_pin") for side in ("caller", "receiver"))
            yield {
                "operation": hop["operation"],
                "caller": hop["caller"],
                "receiver": hop["receiver"],
                "caller_pin": caller,
                "receiver_pin": receiver,
                "profile": hop.get("profile"),
                "identifier_scheme": hop.get("identifier_scheme"),
                "wic_issuer": hop.get("wic_issuer"),
                "wit_issuer": hop.get("wit_issuer"),
                "support": hop.get("support"),
            }
    else:
        for operation, pair in case["pairs"].items():
            caller, receiver = pair["caller"], pair["receiver"]
            yield {
                "operation": operation,
                "caller": "caller",
                "receiver": "receiver",
                "caller_pin": [caller["implementation"], caller.get("version"), caller.get("configuration")],
                "receiver_pin": [receiver["implementation"], receiver.get("version"), receiver.get("configuration")],
                "profile": caller.get("profile"),
                "identifier_scheme": caller.get("identifier_scheme"),
                "wic_issuer": caller.get("wic_issuer"),
                "wit_issuer": caller.get("wit_issuer"),
            }


def render(manifest, report, run_url, site_dir=None):
    summary = json.loads((report / "summary.json").read_text(encoding="utf-8"))
    if sha256(manifest.read_bytes()).hexdigest() != summary["manifest_sha256"]:
        raise ValueError("The report and manifest SHA-256 do not match")

    inventory = read_inventory(manifest)
    cases = {case["id"]: case for group in GROUPS for case in inventory[group]}
    del inventory
    rows = []
    counts = Counter()
    hop_counts = defaultdict(Counter)
    with gzip.open(report / "per-id.csv.gz", "rt", encoding="utf-8", newline="") as stream:
        for result in csv.DictReader(stream):
            execution_id = result["execution_id"]
            case = cases.pop(execution_id, None)
            if case is None:
                raise ValueError(f"Duplicate or unknown execution ID in the report: {execution_id}")
            hops = list(planned_hops(case))
            peers = sorted({pin[0] for hop in hops
                            for pin in (hop["caller_pin"], hop["receiver_pin"]) if pin})
            hop_count = case["hop_count"] if "hop_count" in case else len(hops)
            rows.append({
                **result,
                "hop_count": hop_count,
                "peers": peers,
                "hops": hops,
                "scenario": case.get("scenario_id", case.get("named_scenario_id", case.get("outcome_id"))),
                "expected": case.get("expected_result"),
                "expected_effects": case.get("expected_effects"),
            })
            counts[result["status"]] += 1
            hop_counts[hop_count][result["status"]] += 1
    if cases or len(rows) != summary["total"] or counts != Counter(summary["counts"]):
        raise ValueError("The per-ID results do not reconcile with the manifest and report summary")

    data = json.dumps(
        {"rows": rows, "counts": summary["counts"], "run_url": run_url,
         "manifest_sha256": summary["manifest_sha256"]},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    encoded = b64encode(gzip.compress(data, compresslevel=6, mtime=0)).decode("ascii")
    template = Path(__file__).with_name("execution_report.html").read_text(encoding="utf-8")
    destination = site_dir if site_dir is not None else report
    if site_dir is not None:
        destination.mkdir(parents=True, exist_ok=True)
        write_landing_page(destination, counts, hop_counts, run_url)
        template = template.replace("<!-- SUMMARY_LINK -->", '<p><a href="./">Back to results summary</a></p>')
        template = template.replace("<!-- PAGE_HITS -->", PAGES_HIT_BADGE)
    output = destination / "results.html"
    output.write_text(template.replace("<!-- REPORT_DATA -->", encoded), encoding="utf-8")
    return output


def write_landing_page(destination, counts, hop_counts, run_url):
    status_order = ("pass", "fail", "blocked")
    table_rows = []
    for hop, outcomes in sorted(hop_counts.items()):
        cells = [sum(outcomes.values()), *(outcomes[status] for status in status_order)]
        table_rows.append(
            f'<tr><th scope="row"><a href="results.html?hops={hop}"'
            f' aria-label="Search {hop}-hop executions">{hop}</a></th>'
            + "".join(f"<td>{value:,}</td>" for value in cells)
            + "</tr>"
        )
    source = ""
    if run_url.startswith("https://github.com/"):
        source = f'<p>Source: <a href="{escape(run_url, quote=True)}">audited hosted run</a>.</p>'
    page = Path(__file__).with_name("execution_summary.html").read_text(encoding="utf-8")
    replacements = {
        "TOTAL": f"{sum(counts.values()):,}",
        "PASSED": f'{counts["pass"]:,}',
        "FAILED": f'{counts["fail"]:,}',
        "BLOCKED": f'{counts["blocked"]:,}',
        "HOP_ROWS": "\n".join(table_rows),
        "SOURCE": source,
        "PAGE_HITS": PAGES_HIT_BADGE,
    }
    for marker, value in replacements.items():
        page = page.replace(f"<!-- {marker} -->", value)
    (destination / "index.html").write_text(page, encoding="utf-8")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--run-url", default="")
    parser.add_argument("--site-dir", type=Path, help="Build a static site with a summary and execution browser")
    args = parser.parse_args()
    print(render(args.manifest, args.report, args.run_url, args.site_dir))


if __name__ == "__main__":
    main()
