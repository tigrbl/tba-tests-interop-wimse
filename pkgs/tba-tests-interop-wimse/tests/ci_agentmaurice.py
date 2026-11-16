"""Qualify and run the pinned AgentMaurice workload in disposable Ubuntu labs."""

from argparse import ArgumentParser
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
import json
from pathlib import Path
from queue import Empty
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from types import SimpleNamespace
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from ci_matrix import has_agentmaurice
from run_agentmaurice_matrix import ALLOW, INBOUND, OUTBOUND, OUTBOUND_RESIDUAL, PROFILES, Lab, LiveTbAReceiver, gzip_json
from run_agentmaurice_policy import BindingMissing, scenario_fixture, scenario_map, typed_policy
from run_agentmaurice_typed import open_adapter
from support.agentmaurice_endpoint import BINARY_SHA256, CONFIGURATION
from support.agentmaurice_policy import PolicyBridge
from support.spire_issuer import spire_issuer
from support.wpt_fixture import public_jwk
from tba_tests_interop_wimse.hop_runner import hop_mismatches
from tba_tests_interop_wimse.observations import Observation, mismatches


PEER = "agentmaurice"
APP = "rust@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0"
NATS = "nats@sha256:71092f77d707a4a81b12aca5096d6b2d2e07ad16aa57c84066940a17af74f61a"
PROBE_ERRORS = (AssertionError, Empty, KeyError, OSError, RuntimeError, ValueError, subprocess.SubprocessError)


def docker(*args, check=True):
    return subprocess.run(["docker", *map(str, args)], check=check, text=True,
                          capture_output=True, timeout=180)


@contextmanager
def lab_container(assets, jwks, fixtures):
    name = "interop-maurice-" + uuid4().hex
    nats = name + "-nats"
    entry = "while [ ! -e /tmp/boot ]; do sleep 1; done; exec sh /fixture/agentmaurice_lab.sh"
    with ExitStack() as stack:
        stack.callback(docker, "rm", "-f", name, check=False)
        docker("run", "-d", "--name", name, "--network", "none",
               "--mount", f"type=bind,src={assets / 'release'},dst=/release,readonly",
               "--mount", f"type=bind,src={assets / 'deno'},dst=/deno,readonly",
               "--mount", f"type=bind,src={jwks},dst=/input/issuer.jwks,readonly",
               "--mount", f"type=bind,src={fixtures},dst=/fixture,readonly",
               APP, "sh", "-c", entry)
        stack.callback(docker, "rm", "-f", nats, check=False)
        docker("run", "-d", "--name", nats, "--network", f"container:{name}",
               NATS, "-js", "-a", "127.0.0.1")
        docker("exec", name, "touch", "/tmp/boot")
        deadline = monotonic() + 120
        while monotonic() < deadline:
            if docker("exec", name, "test", "-f", "/tmp/lab-ready", check=False).returncode == 0:
                yield name
                return
            if docker("inspect", "--format", "{{.State.Running}}", name).stdout.strip() != "true":
                break
            sleep(1)
        logs = docker("logs", "--tail", "25", name, check=False)
        raise RuntimeError(f"AgentMaurice lab did not become ready. {logs.stdout} {logs.stderr}")


def lab_inputs(directory, *, spire=None):
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = {**public_jwk(private), "kid": "tba-test-issuer"}
    path = directory / "issuer.pem"
    path.write_bytes(private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    jwks = directory / "issuer.jwks"
    keys = [jwk] if spire is None else [jwk, spire]
    jwks.write_text(json.dumps({"keys": keys}), encoding="ascii")
    return path, private, jwks


def qualify(args, directory, stack):
    spire = stack.enter_context(spire_issuer(directory))
    token, proof_key, signer = spire.mint_wit("spiffe://example.org/tba-workload")
    _, key, jwks = lab_inputs(directory, spire=signer)
    container = stack.enter_context(lab_container(args.assets, jwks, args.fixtures))
    lab = Lab(container)
    lab.validate_spire_wit(token, proof_key)
    controls = {}
    with LiveTbAReceiver(lab) as receiver:
        for profile, mode in PROFILES.items():
            controls[profile] = {
                "tba_to_agentmaurice": lab.inbound(mode, "valid-peer", key),
                "agentmaurice_to_tba": receiver.observe(mode, "valid-peer"),
                "spire_to_agentmaurice": lab.spire_inbound(mode, key, token, proof_key),
            }
    result = {"version": "v2.2.18", "binary_sha256": BINARY_SHA256,
              "configuration": CONFIGURATION, "directions": controls}
    validate_qualification(result)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def validate_qualification(result):
    if result["binary_sha256"] != BINARY_SHA256 or result["configuration"] != CONFIGURATION:
        raise ValueError("AgentMaurice qualification pin mismatch")
    for profile in PROFILES:
        control = result["directions"][profile]
        for direction, expected in (("tba_to_agentmaurice", 200), ("agentmaurice_to_tba", 201)):
            observed = control[direction]
            if (observed["statuses"], observed["effects"]) != ([expected], 1):
                raise ValueError(f"AgentMaurice baseline qualification failed for {profile}: {direction}")


def direct(row, case, adapter, spire_credential):
    if set(row["pairs"]) != {"enforcing"}:
        return None
    pair = row["pairs"]["enforcing"]
    if {item["implementation"] for item in pair.values()} != {"tba", PEER}:
        return None
    profile = pair["caller"]["profile"]
    variant = case["variant"]
    inbound = pair["receiver"]["implementation"] == PEER
    issuer = case["hops"]["enforcing"]["wit_issuer"]
    if issuer == "spire-wit-svid" and inbound and variant == "valid-peer":
        token, proof_key = spire_credential
        lab = adapter.labs[0]
        lab.validate_spire_wit(token, proof_key)
        wire = lab.spire_inbound(PROFILES[profile], adapter.issuer, token, proof_key)
        decision = "allow" if wire["statuses"] == [200] and wire["effects"] == 1 else "deny"
        return Observation(decision, "enforcing", effects=wire["effects"],
                           reason=wire["journal"][-1]["reason"], measurements={"agentmaurice": wire})
    if issuer != "baseline" or variant not in (INBOUND if inbound else OUTBOUND | OUTBOUND_RESIDUAL):
        return None
    mode = PROFILES[profile]
    if inbound:
        wire = adapter.labs[0].inbound(mode, variant, adapter.issuer)
    else:
        wire = adapter.receivers[0].observe(mode, variant)
    duplicate = variant == "duplicate-presentation"
    decision = "allow-then-deny" if duplicate else "allow" if variant in ALLOW else "deny"
    events = ("initial-allow", "initial-effect", "duplicate-refused") if duplicate else ()
    return Observation(decision, "enforcing", events, effects=wire["effects"],
                       additional_effects=wire.get("additional_effects", 0), measurements={"agentmaurice": wire})


def record_observation(row, scenarios, adapter, spire_credential):
    if "pairs" not in row:
        # An expected refusal proves a prefix only if the live result later
        # matches the frozen decision hop and effect count.
        prefix_stop = row["decision_hop"]
        if row["expected_effects"] == 0 and prefix_stop < len(row["hops"]):
            prefix = {**row, "hops": row["hops"][:prefix_stop]}
            if all(hop["operation"] in {"call", "check", "delegate", "redeem-delegation",
                                       "source-exchange", "destination-exchange", "emilia-check"}
                   for hop in prefix["hops"]):
                row = prefix
        elif row["hops"][-1]["operation"] in {"redthread-check", "omniarx-check"}:
            raise BindingMissing(f"Missing live verifier for {row['hops'][-1]['support']}")
        if any(hop.get("wit_issuer") != "baseline" for hop in row["hops"]
               if any(hop.get(role + "_pin", [None])[0] == PEER for role in ("caller", "receiver"))):
            raise BindingMissing("AgentMaurice lacks the selected SPIRE WIT-SVID and proof-key binding")
        if len(adapter.participants(row["hops"])) > len(adapter.labs):
            raise BindingMissing("Additional AgentMaurice workload deployment required")
        blocker = adapter.blocker(row)
        if not blocker:
            return adapter.observe(row)
        if any(hop["operation"] in {"delegate", "redeem-delegation", "source-exchange",
                                     "destination-exchange", "boundary-call", "broker"} for hop in row["hops"]):
            return typed_policy(adapter, row)
        raise BindingMissing(blocker)
    case = scenarios[row["scenario_id"]]
    observed = direct(row, case, adapter, spire_credential)
    if observed is not None:
        return asdict(observed)
    if any(case["hops"][name]["wit_issuer"] != "baseline" for name, pair in row["pairs"].items()
           if any(endpoint["implementation"] == PEER for endpoint in pair.values())):
        raise BindingMissing("AgentMaurice lacks the selected SPIRE WIT-SVID and proof-key binding")
    return asdict(scenario_fixture(adapter, case, row))


def discrepancies(row, observation, scenarios):
    if "pairs" not in row:
        return hop_mismatches(row, observation)
    return mismatches(scenarios[row["scenario_id"]], Observation(**observation))


def execute(args, directory, stack, rows):
    qualification = json.loads(args.qualification.read_text(encoding="utf-8"))
    validate_qualification(qualification)
    scenarios = scenario_map()
    spire_credential = signer = None
    if any("pairs" in row and row["scenario_id"].startswith("01:valid-peer:")
           and set(row["pairs"]) == {"enforcing"} and row["direction"] == "forward"
           and row["pairs"]["enforcing"]["receiver"]["implementation"] == PEER
           and scenarios[row["scenario_id"]]["hops"]["enforcing"]["wit_issuer"] == "spire-wit-svid"
           for _, row in rows):
        spire = stack.enter_context(spire_issuer(directory))
        token, proof_key, signer = spire.mint_wit("spiffe://example.org/tba-workload")
        spire_credential = token, proof_key
    issuer, _, jwks = lab_inputs(directory, spire=signer)
    containers = [stack.enter_context(lab_container(args.assets, jwks, args.fixtures)) for _ in range(2)]
    root = args.snapshot.parent
    bins = root / "wimsey/target/debug"
    adapter_args = SimpleNamespace(
        snapshot=args.snapshot, issuer=issuer, container=containers, token_refusals_only=False,
        wimsey=bins / "wimsey", wpt=bins / "tba-wimsey-wpt-bridge", cofide=root / "cofide-bridge",
        cred=args.snapshot.with_suffix(".cred") / "cred_bridge.mjs",
        go_spiffe=root / "go-spiffe", defakto=root / "defakto/verify.mjs",
        emilia=root / "emilia/check.mjs", mintid_container=None,
    )
    adapter = open_adapter(adapter_args, stack, directory, bridge_factory=PolicyBridge)
    with args.output.open("x", encoding="utf-8") as stream:
        for index, (published, row) in enumerate(rows, 1):
            record = {"execution_id": row["id"], "published_id": published, "binary_sha256": BINARY_SHA256,
                      "configuration": CONFIGURATION}
            try:
                observation = record_observation(row, scenarios, adapter, spire_credential)
                errors = discrepancies(row, observation, scenarios)
                record.update(status="failed" if errors else "passed", observation=observation,
                              reason="; ".join(errors + ([observation["reason"]] if errors and observation.get("reason") else [])))
            except BindingMissing as error:
                record.update(status="blocked", reason=str(error))
                if error.evidence is not None:
                    record["prefix_evidence"] = error.evidence
            except PROBE_ERRORS as error:
                record.update(status="failed", reason=str(error) or type(error).__name__)
            stream.write(json.dumps(record) + "\n")
            stream.flush()
            if index % 50 == 0 or index == len(rows):
                print(f"Recorded AgentMaurice results for {index}/{len(rows)} IDs", flush=True)


def selected(plan, shard):
    pairs = dict(gzip_json(plan / "mapping.json.gz")[shard])
    selected_ids = set(pairs.values())
    runtime = gzip_json(plan / "runtime.json.gz")
    candidates = {row["id"]: row for group in runtime.values() for row in group
                  if row["id"] in selected_ids and has_agentmaurice(row)}
    return [(published, candidates[current]) for published, current in pairs.items() if current in candidates]


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--shard", type=int)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--qualification", type=Path)
    args = parser.parse_args()
    args.assets = args.assets.resolve()
    args.fixtures = Path(__file__).resolve().parent / "support"
    if args.plan is not None:
        if args.shard is None or args.snapshot is None or args.qualification is None:
            parser.error("--plan requires --shard, --snapshot, and --qualification")
        rows = selected(args.plan, args.shard)
        if not rows:
            return
    with ExitStack() as stack:
        directory = Path(stack.enter_context(TemporaryDirectory()))
        if args.plan is None:
            qualify(args, directory, stack)
        else:
            execute(args, directory, stack, rows)


if __name__ == "__main__":
    main()
