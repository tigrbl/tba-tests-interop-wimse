"""Refresh native endpoint and issuer qualification on the actual lab transport."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory

from support.qualification_overlay import wic_source_digest
from support.typed_workload_chain import native_workload_hop
from support.wimsey_endpoint import CONFIGURATION
from tba_tests_interop_wimse.native_expansion import (
    BASELINE_WORKLOAD_RECORD, COMBINED_RECORD, COMBINED_SCOPE, NATIVE_ISSUERS,
)


TRANSPORT = "wic-mtls"
COMPOSED = ("wic-mtls-wpt", "wic-mtls-http-signature")
APPLICATION = ("wit-wpt", "wit-http-signature")
PROFILES = tuple((profile, scheme) for profile in (TRANSPORT, *COMPOSED) for scheme in ("wimse", "spiffe")) + tuple(
    (profile, "none") for profile in APPLICATION
)


def qualify_native(snapshot, output):
    peers = snapshot["peers"]
    fingerprint = "sha256:" + wic_source_digest()
    fields = ("implementation", "role", "profile", "identifier_scheme", "configuration", "version")
    capabilities = {
        (row["profile"], row["identifier_scheme"], row["role"]): row
        for row in peers["capabilities"] if row["implementation"] == "tba"
        and row.get("version") == fingerprint and row["configuration"] == CONFIGURATION
        and row["status"] == "qualified"
    }
    for profile, scheme in PROFILES:
        if any((profile, scheme, role) not in capabilities for role in ("caller", "receiver")):
            raise ValueError(f"Missing fresh TbA endpoint qualification: {profile}/{scheme}")

    observations = []

    def check(directory, scope, profile, scheme, variant, layer, wic, wit):
        hop = dict(profile=profile, identifier_scheme=scheme, wic_issuer=wic, wit_issuer=wit)
        case = dict(variant=variant, layer=layer, target_hop="enforcing", hops={"enforcing": hop})
        with native_workload_hop(directory, case, hop,
                                 {"caller_name": "workload", "receiver_name": "workload/server"}) as fixture:
            result = fixture.observe()
        expected = ("allow", 1) if variant == "valid-peer" else ("deny", 0)
        if (result.hop, result.decision, result.effects) != ("enforcing", *expected):
            raise ValueError(f"Native control {scope}/{profile}/{scheme}/{variant} failed: {result}")
        observations.append(dict(scope=scope, profile=profile, scheme=scheme, variant=variant,
                                 observation=asdict(result)))

    with TemporaryDirectory(dir=output) as directory:
        for profile, scheme in PROFILES:
            wic, wit = ("none" if scheme == "none" else "baseline"), ("none" if profile == TRANSPORT else "baseline")
            transport = profile == TRANSPORT
            layer = "tls" if transport else "application"
            for variant in ("valid-peer", "wrong-anchor" if transport else "wrong-proof-key"):
                check(directory, "baseline", profile, scheme, variant, layer, wic, wit)
        for profile, scheme in PROFILES:
            if profile == TRANSPORT:
                continue
            for variant in ("valid-peer", "wrong-anchor", "wrong-proof-key"):
                check(directory, "tba-wit-svid", profile, scheme, variant, "operation",
                      "none" if scheme == "none" else "baseline", "tba-wit-svid")
        for profile in (TRANSPORT, *COMPOSED):
            for variant in ("valid-peer", "wrong-anchor", "wrong-server-identity"):
                check(directory, "tba-x509-svid", profile, "spiffe", variant, "tls", "tba-x509-svid",
                      "none" if profile == TRANSPORT else "baseline")
        for profile in COMPOSED:
            for variant, layer in (("valid-peer", "operation"), ("wrong-anchor", "tls"),
                                   ("wrong-proof-key", "application")):
                check(directory, COMBINED_SCOPE, profile, "spiffe", variant, layer, "tba-x509-svid", "tba-wit-svid")

    evidence = "native-controls.json"
    (output / evidence).write_text(json.dumps(observations, indent=2), encoding="utf-8")
    for scope, key in (("baseline", BASELINE_WORKLOAD_RECORD), (COMBINED_SCOPE, COMBINED_RECORD),
                       *((issuer, record) for issuer, (_, record) in NATIVE_ISSUERS.items())):
        profiles = sorted({(row["profile"], row["scheme"]) for row in observations if row["scope"] == scope})
        if scope == "baseline":
            profiles = [(*profile, CONFIGURATION) for profile in profiles]
        peers[key] = dict(version=fingerprint, profiles=profiles, evidence=evidence)
    for profile, scheme in PROFILES:
        pair = {role: {field: capabilities[profile, scheme, role][field] for field in fields}
                for role in ("caller", "receiver")}
        baseline = dict(**pair, outcome="pass", evidence=evidence)
        if baseline not in peers["baselines"]:
            peers["baselines"].append(baseline)
    return len(observations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=False)
    count = qualify_native(snapshot, args.output)
    target = args.output / "qualification.json"
    if (source := args.snapshot.with_suffix(".cred")).is_dir():
        shutil.copytree(source, target.with_suffix(".cred"))
    target.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    print(f"Passed {count} native endpoint and issuer controls")


if __name__ == "__main__":
    main()
