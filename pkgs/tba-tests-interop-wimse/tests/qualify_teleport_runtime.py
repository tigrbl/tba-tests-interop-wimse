"""Add live Teleport Workload API controls to a combined qualification snapshot."""

import argparse
import json
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory

from support.spire_issuer import docker
from support.teleport_endpoint import ISSUER, TeleportWorkloadAPI, fingerprint
from support.wimsey_endpoint import CONFIGURATION


IMAGE = "sha256:a09b7585c2e314a09441787d2c522aa7c901b566e15a3602efc9c979e791e029"
RELEASE = "18.11.4"
PROFILES = ("wic-mtls", "wic-mtls-wpt", "wic-mtls-http-signature")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--container", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    version = docker("exec", args.container, "tbot", "version").stdout.strip()
    if version.split()[:3] != ["Teleport", f"v{RELEASE}", "git:v18.11.4-0-g34583b39"]:
        raise ValueError(f"Unexpected Teleport executable version: {version}")
    with TemporaryDirectory() as directory:
        agent = TeleportWorkloadAPI(args.container, directory)
        if agent.image() != IMAGE:
            raise ValueError("Container does not run the pinned Teleport image")
        material = agent.fetch(enrolled=True)
        certificate = fingerprint(material)
        if agent.fetch(enrolled=False) is not None:
            raise ValueError("Teleport authorized the unregistered workload")
    evidence = "teleport_qualification"
    snapshot[evidence] = {
        "image": IMAGE,
        "release": RELEASE,
        "version_output": version,
        "identity": "spiffe://example.org/workload-0",
        "control_certificate_sha256": certificate,
        "unregistered_uid_refused": True,
    }
    snapshot["peers"].setdefault("qualified_support", {})[f"enforcing:wic_issuer:{ISSUER}"] = {
        "implementation": "teleport-tbot",
        "version": IMAGE,
        "configuration": CONFIGURATION,
        "evidence": evidence,
        "bindings": [
            {"profile": profile, "identifier_schemes": ["spiffe"], "configuration": CONFIGURATION}
            for profile in PROFILES
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if (bridge := args.snapshot.with_suffix(".cred")).is_dir():
        copytree(bridge, args.output.with_suffix(".cred"))
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(snapshot, stream, indent=2)


if __name__ == "__main__":
    main()
