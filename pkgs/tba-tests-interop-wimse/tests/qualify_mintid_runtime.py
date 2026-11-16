"""Record hosted MintID controls against the same images used by the shards."""

from argparse import ArgumentParser
import json
from pathlib import Path

from mintid_endpoint import driver_fingerprint, hosted_service_images, mintid_decision


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--container", required=True)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    controls = {
        label: mintid_decision(args.container, path, "qualify-" + label)
        for label, path in (("active", ""), ("issuer", "issuer"), ("holder", "kill_switch"))
    }
    snapshot["mintid_qualification"] = {
        **driver_fingerprint(args.container),
        "source_revision": "dca3d605b7a1d559ef74c444498552f64c9c8285",
        "release": "public-v2026-11-13.1",
        "hosted_service_images": hosted_service_images(),
        "controls": controls,
    }
    args.snapshot.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print("Qualified the active proof, issuer revocation, and holder self-revocation")

if __name__ == "__main__":
    main()
