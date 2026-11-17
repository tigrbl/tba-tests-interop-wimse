"""Turn an audited full-matrix report into a self-contained browser view."""

from argparse import ArgumentParser
from base64 import b64encode
from collections import Counter
import csv
import gzip
from hashlib import sha256
import json
from pathlib import Path

from ci_full_matrix import GROUPS, read_inventory


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


def render(manifest, report, run_url):
    summary = json.loads((report / "summary.json").read_text(encoding="utf-8"))
    if sha256(manifest.read_bytes()).hexdigest() != summary["manifest_sha256"]:
        raise ValueError("The report and manifest SHA-256 do not match")

    inventory = read_inventory(manifest)
    cases = {case["id"]: case for group in GROUPS for case in inventory[group]}
    del inventory
    rows = []
    counts = Counter()
    with gzip.open(report / "per-id.csv.gz", "rt", encoding="utf-8", newline="") as stream:
        for result in csv.DictReader(stream):
            execution_id = result["execution_id"]
            case = cases.pop(execution_id, None)
            if case is None:
                raise ValueError(f"Duplicate or unknown execution ID in the report: {execution_id}")
            hops = list(planned_hops(case))
            peers = sorted({pin[0] for hop in hops
                            for pin in (hop["caller_pin"], hop["receiver_pin"]) if pin})
            rows.append({
                **result,
                "hop_count": case["hop_count"] if "hop_count" in case else len(hops),
                "peers": peers,
                "hops": hops,
                "scenario": case.get("scenario_id", case.get("named_scenario_id", case.get("outcome_id"))),
                "expected": case.get("expected_result"),
                "expected_effects": case.get("expected_effects"),
            })
            counts[result["status"]] += 1
    if cases or len(rows) != summary["total"] or counts != Counter(summary["counts"]):
        raise ValueError("The per-ID results do not reconcile with the manifest and report summary")

    data = json.dumps(
        {"rows": rows, "counts": summary["counts"], "run_url": run_url,
         "manifest_sha256": summary["manifest_sha256"]},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    encoded = b64encode(gzip.compress(data, compresslevel=6, mtime=0)).decode("ascii")
    template = Path(__file__).with_name("execution_report.html").read_text(encoding="utf-8")
    output = report / "results.html"
    output.write_text(template.replace("<!-- REPORT_DATA -->", encoded), encoding="utf-8")
    return output


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--run-url", default="")
    args = parser.parse_args()
    print(render(args.manifest, args.report, args.run_url))


if __name__ == "__main__":
    main()
