"""Run direct AgentMaurice cases from the frozen WIMSE manifest.

This runner uses a dedicated, already deployed loopback lab. It records the
published ID separately from the manifest's runtime ID.
"""

import argparse
from contextlib import ExitStack
import csv
import gzip
import json
from pathlib import Path
from queue import Empty, Queue
import subprocess
from threading import Thread
from time import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from tba_concrete_jwt import decode_jwt_unverified
from tba_profile_workload_proof_wimse_wpt import authenticate_wpt_request
from tba_provider_jose_cryptography.public_jws import verify_public_jws
from tba_provider_replay_memory import MemoryReplayCheckProvider

from support.agentmaurice_endpoint import (
    AUDIENCE, BINARY_SHA256, BODY, CONFIGURATION, baseline_wit, workflow_headers, workflow_request,
)
from support.wpt_fixture import public_jwk
from tba_tests_interop_wimse.resource import WriteLedger
from tba_tests_interop_wimse.signatures import authenticate_signature, sign_request

PROFILES = {"wit-wpt": "wpt", "wit-http-signature": "http-sig"}
INBOUND = {"valid-peer", "untrusted-domain", "wrong-anchor", "missing-proof",
           "wrong-proof-key", "wrong-audience", "first-presentation", "duplicate-presentation"}
OUTBOUND = {"valid-peer", "untrusted-domain", "wrong-anchor", "wrong-audience", "first-presentation"}
ALLOW = {"valid-peer", "first-presentation"}
OUTBOUND_RESIDUAL = {"missing-proof", "wrong-proof-key", "duplicate-presentation"}


def gzip_json(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def direct_rows(inventory, manifest, mapping, *, spire=False, outbound_residual=False):
    catalog = {row["id"]: row for row in gzip_json(manifest)["workload_executions"]}
    runtime = dict(pair for shard in gzip_json(mapping) for pair in shard)
    issuer = "spire-wit-svid" if spire else "baseline"
    with inventory.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            if row["path"] != "call" or row["agentmaurice_wit_issuers"] != issuer:
                continue
            published_id = row["execution_id"]
            execution = catalog[runtime[published_id]]
            if execution["hop_count"] != 1 or tuple(execution["pairs"]) != ("enforcing",):
                continue
            pair = execution["pairs"]["enforcing"]
            caller, receiver = pair["caller"]["implementation"], pair["receiver"]["implementation"]
            if {caller, receiver} != {"agentmaurice", "tba"}:
                continue
            variant = execution["scenario_id"].split(":")[1]
            inbound = receiver == "agentmaurice"
            if spire and (not inbound or variant != "valid-peer"):
                continue
            if outbound_residual and (inbound or variant not in OUTBOUND_RESIDUAL):
                continue
            if not spire and not outbound_residual and variant not in (INBOUND if inbound else OUTBOUND):
                continue
            yield {
                "published_id": published_id, "runtime_id": execution["id"],
                "direction": "inbound" if inbound else "outbound", "variant": variant,
                "profile": pair["caller"]["profile"], "hop": "enforcing", "wit_issuer": issuer,
            }


class Lab:
    def __init__(self, container):
        self.command = ["docker", "exec", "-i", container]
        actual = self.run("sha256sum", "/tmp/maurice").stdout.split()[0]
        if actual != BINARY_SHA256:
            raise ValueError("Unexpected AgentMaurice binary")
        self.agent = self.run("cat", "/tmp/test-id").stdout.strip()
        self.path = f"/api/v2/agents/{self.agent}/workflows/text-stats/executions"

    def run(self, *args, input=None):
        return subprocess.run([*self.command, *args], input=input, text=True, capture_output=True,
                              timeout=45, check=True)

    def journal(self):
        reply = self.run("/tmp/maurice", "wimse", "log", "--data-dir", "/tmp/one", "--json")
        return [json.loads(line) for line in reply.stdout.splitlines() if line.strip()]

    def validate_spire_wit(self, token, key):
        decoded = decode_jwt_unverified(token)
        protected, claims = decoded.jws.protected_headers, decoded.claims
        if (protected.get("typ") != "wit+jwt"
                or claims.get("sub") != "spiffe://example.org/tba-workload"
                or claims["exp"] <= time()
                or claims["cnf"]["jwk"] != public_jwk(key)):
            raise ValueError("Unexpected SPIRE WIT-SVID identity, expiry, or binding key")
        trust = json.loads(self.run("cat", "/tmp/tba-issuer.jwks.json").stdout)["keys"]
        issuer, = (item for item in trust
                   if item.get("kid") == protected["kid"] and item.get("use") == "wit-svid")
        verify_public_jws(token, issuer)

    def request(self, headers, *, path=None, body=BODY):
        reply = self.run("/tmp/bin/deno", "run", "--allow-net=127.0.0.1:5000", "/tmp/request.ts",
                         input=workflow_request(path or self.path, headers, body=body))
        return json.loads(reply.stdout)

    def inbound(self, mode, variant, issuer):
        offset = len(self.journal())
        if variant == "wrong-anchor":
            issuer = ec.generate_private_key(ec.SECP256R1())
        if variant == "untrusted-domain":
            token, key = baseline_wit(issuer, "wimse://foreign.example/tba-workload")
        else:
            token, key = baseline_wit(issuer)
        if variant == "wrong-proof-key":
            key = ec.generate_private_key(ec.SECP256R1())
        audience = AUDIENCE + "/different" if variant == "wrong-audience" else AUDIENCE
        headers = workflow_headers(mode, self.path, token, key, audience=audience,
                                   missing=variant == "missing-proof")
        replies = [self.request(headers)]
        if variant == "duplicate-presentation":
            replies.append(self.request(headers))
        journal = self.journal()[offset:]
        decisions = [entry["decision"] for entry in journal]
        effects = len({reply["execution_id"] for reply in replies
                       if reply.get("state") == "completed" and reply.get("execution_id")})
        statuses = [reply["status"] for reply in replies]
        expected = [True, False] if variant == "duplicate-presentation" else [variant in ALLOW]
        allowed = [status == 200 for status in statuses]
        if (allowed != expected or effects != sum(expected)
                or any(status not in (200, 400, 401, 403) for status in statuses)):
            raise ValueError(f"Unexpected workflow observations {replies!r} {journal!r}")
        reasons = {
            "valid-peer": [""], "untrusted-domain": ["untrusted-trust-domain"],
            "wrong-anchor": ["wit-invalid"], "missing-proof": ["proof-missing"],
            "wrong-proof-key": ["proof-invalid"], "wrong-audience": ["audience-mismatch"],
            "first-presentation": [""], "duplicate-presentation": ["", "replay"],
        }
        if (decisions != ["accept" if value else "reject" for value in expected]
                or [entry["reason"] for entry in journal] != reasons[variant]):
            raise ValueError(f"Unexpected decision journal {journal!r}")
        return {"statuses": statuses, "effects": effects, "journal": journal}

    def spire_inbound(self, mode, issuer, token, key):
        offset = len(self.journal())
        control_token, control_key = baseline_wit(issuer)
        ordinary = self.request(workflow_headers(mode, self.path, control_token, control_key))
        if (ordinary["status"], ordinary.get("state")) != (200, "completed"):
            raise ValueError(f"Ordinary WIT positive control failed: {ordinary!r}")
        presented = self.request(workflow_headers(mode, self.path, token, key))
        journal = self.journal()[offset:]
        return {"statuses": [presented["status"]], "effects": int(presented.get("state") == "completed"),
                "ordinary_control_status": ordinary["status"], "journal": journal}


class LiveTbAReceiver:
    def __init__(self, lab):
        self.lab = lab

    def __enter__(self):
        self.bridge = subprocess.Popen(
            [*self.lab.command, "/tmp/bin/deno", "run", "--allow-net=127.0.0.1:15001",
             "--allow-read=/tmp/receiver-cert.pem,/tmp/receiver-key.pem", "/tmp/receiver.ts"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        self.packets = Queue()
        Thread(target=self.read_packets, daemon=True).start()
        if self.receive() != {"ready": True}:
            raise ValueError("Loopback receiver did not start")
        return self

    def __exit__(self, *_):
        self.bridge.stdin.close()
        try:
            self.bridge.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.bridge.terminate()
        self.bridge.wait(timeout=5)

    def read_packets(self):
        for line in self.bridge.stdout:
            self.packets.put(json.loads(line))

    def receive(self):
        return self.packets.get(timeout=30)

    def decide(self, status):
        self.bridge.stdin.write(json.dumps({"status": status}) + "\n")
        self.bridge.stdin.flush()

    @staticmethod
    def authenticate(mode, request, settings):
        if mode == "wpt":
            return authenticate_wpt_request(request["headers"].items(), **settings).claims["sub"]
        return authenticate_signature(request["headers"].items(), method="POST",
                                      path=request["path"], **settings)

    @staticmethod
    def substitute_proof(mode, request):
        key = ec.generate_private_key(ec.SECP256R1())
        headers = request["headers"]
        token = headers["workload-identity-token"]
        if mode == "wpt":
            proof = workflow_headers(mode, request["path"], token, key, audience=request["url"])
            headers["authorization"] = proof["authorization"]
        else:
            proof = sign_request(key, token, "POST", request["path"], request["url"], int(time()))
            headers.update(proof)

    def replay(self, mode, original, settings, ledger):
        args = [*self.lab.command, "/tmp/bin/deno", "run", "--allow-net=127.0.0.1:15001",
                "--allow-read=/tmp/receiver-ca.pem", "/tmp/replay.ts"]
        with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) as replay:
            replay.stdin.write(json.dumps(original))
            replay.stdin.close()
            replay.stdin = None
            try:
                request = None
                for _ in range(100):
                    try:
                        request = self.packets.get(timeout=0.1)
                        break
                    except Empty:
                        if replay.poll() is not None:
                            break
                if request is None:
                    if replay.poll() is None:
                        replay.kill()
                    stdout, stderr = replay.communicate()
                    raise ValueError(f"Retransmission did not reach the loopback receiver: {stdout} {stderr}")
                assert (request["method"], request["url"], request["body"]) == (
                    original["method"], original["url"], original["body"]
                )
                for name in ("workload-identity-token", "authorization", "signature", "signature-input"):
                    assert request["headers"].get(name) == original["headers"].get(name)
                try:
                    identity = self.authenticate(mode, request, {**settings, "now": time()})
                except ValueError as error:
                    reason = str(error)
                    self.decide(401)
                else:
                    ledger.commit(identity)
                    self.decide(201)
                    raise ValueError("Receiver accepted the duplicate proof")
                stdout, stderr = replay.communicate(timeout=30)
                if replay.returncode or json.loads(stdout) != 401 or "replay" not in reason.lower():
                    raise ValueError(f"Duplicate proof did not reach a replay refusal: {reason} {stderr}")
                return reason
            finally:
                if replay.poll() is None:
                    replay.kill()

    def observe(self, mode, variant, *, commit=True):
        args = [*self.lab.command, "/tmp/maurice", "--config", "/tmp/cli/context.yaml",
                "test", "workflow", "call", "interop-outbound", "--agent-id", self.lab.agent,
                "--runtime-url", "http://127.0.0.1:5000", "--arg", f"mode={mode}",
                "--arg", "resource=writes", "--arg", "context={}", "--json"]
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as call:
            try:
                request = self.receive()
            except Empty as error:
                call.kill()
                stdout, stderr = call.communicate()
                raise ValueError(f"No protected request reached the receiver: {stdout} {stderr}") from error
            trust = json.loads(self.lab.run(
                "/tmp/maurice", "wimse", "trust-bundle", "export", "--data-dir", "/tmp/one", "--json"
            ).stdout)["keys"]
            if variant == "untrusted-domain":
                trust_by_domain = {}
            elif variant == "wrong-anchor":
                trust_by_domain = {"example.org": [{**public_jwk(ec.generate_private_key(ec.SECP256R1())),
                                                   "kid": item["kid"]} for item in trust]}
            else:
                trust_by_domain = {"example.org": trust}
            audience = request["url"] + "/different" if variant == "wrong-audience" else request["url"]
            if request["method"] != "POST" or request["path"] != "/writes" or request["body"]:
                raise ValueError("Unexpected outbound protected operation")
            if variant == "missing-proof":
                request["headers"].pop("authorization" if mode == "wpt" else "signature")
            elif variant == "wrong-proof-key":
                self.substitute_proof(mode, request)
            settings = dict(audience=audience, trust_by_domain=trust_by_domain, now=time(),
                            replay_store=MemoryReplayCheckProvider())
            ledger = WriteLedger()
            status, reason, identity = 201, "", None
            try:
                identity = self.authenticate(mode, request, settings)
            except ValueError as error:
                status, reason = 401, str(error)
            else:
                if variant == "scope-refused":
                    status, reason = 403, "operation-scope-refused"
                elif commit:
                    ledger.commit(identity)
                else:
                    status = 200
            effects = len(ledger.snapshot())
            self.decide(status)
            stdout, stderr = call.communicate(timeout=45)
        if call.returncode:
            raise ValueError(f"Workflow invocation failed: {stdout} {stderr}")
        invocation = json.loads(stdout)
        execution = invocation["execution"]
        data = execution.get("data") or execution.get("output")
        if execution["state"] != "completed" or data["status"] != status:
            raise ValueError(f"Workflow did not return the live receiver decision: {execution}")
        if effects != int((variant in ALLOW or variant == "duplicate-presentation") and commit):
            raise ValueError(f"Unexpected TbA decision: {identity} {reason}")
        if identity is not None:
            metadata = json.loads(self.lab.run("/tmp/maurice", "wimse", "identity", "show", "--agent",
                                              self.lab.agent, "--data-dir", "/tmp/one", "--json").stdout)
            if identity not in (metadata.get("identifier"), metadata.get("sub"),
                                metadata.get("claims", {}).get("sub")):
                raise ValueError(f"Verified workload did not match the runtime identity: {identity} {metadata}")
        if variant == "duplicate-presentation":
            reason = self.replay(mode, request, settings, ledger)
            return {"statuses": [status, 401], "effects": effects, "identity": identity,
                    "reason": reason, "additional_effects": len(ledger.snapshot()) - effects}
        return {"statuses": [status], "effects": effects, "identity": identity, "reason": reason}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "manifest", "mapping", "issuer", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--spire-wit", type=Path, help="Real SPIRE WIT-SVID in the loaded JWKS")
    parser.add_argument("--spire-key", type=Path, help="PEM private proof key for the disposable WIT-SVID")
    parser.add_argument("--remaining-outbound-proofs", action="store_true")
    args = parser.parse_args()
    if bool(args.spire_wit) != bool(args.spire_key):
        parser.error("--spire-wit and --spire-key must be used together")
    spire = bool(args.spire_wit)
    if spire and args.remaining_outbound_proofs:
        parser.error("Choose the SPIRE controls or the remaining baseline outbound controls")
    rows = list(direct_rows(args.inventory, args.manifest, args.mapping, spire=spire,
                            outbound_residual=args.remaining_outbound_proofs))
    if not rows or len({row["published_id"] for row in rows}) != len(rows):
        raise ValueError("Empty or non-unique selection")
    lab = Lab(args.container)
    issuer = load_pem_private_key(args.issuer.read_bytes(), None)
    token = args.spire_wit.read_text(encoding="ascii").strip() if spire else None
    key = load_pem_private_key(args.spire_key.read_bytes(), None) if spire else None
    if spire:
        lab.validate_spire_wit(token, key)
    failed = 0
    with args.output.open("x", encoding="utf-8") as output, ExitStack() as stack:
        receiver = None if spire else stack.enter_context(LiveTbAReceiver(lab))
        for row in rows:
            try:
                mode = PROFILES[row["profile"]]
                if spire:
                    evidence = lab.spire_inbound(mode, issuer, token, key)
                    row.update(result="passed" if evidence["statuses"] == [200] and evidence["effects"] == 1
                               else "failed", evidence=evidence)
                    failed += row["result"] == "failed"
                elif row["direction"] == "inbound":
                    row.update(result="passed", evidence=lab.inbound(mode, row["variant"], issuer))
                else:
                    row.update(result="passed", evidence=receiver.observe(mode, row["variant"]))
            except (ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
                row.update(result="failed", error=str(error))
                failed += 1
            output.write(json.dumps({**row, "configuration": CONFIGURATION,
                                     "binary_sha256": BINARY_SHA256}) + "\n")
            output.flush()
            print(row["direction"], row["profile"], row["variant"], row["result"], flush=True)
    return min(failed, 1)


if __name__ == "__main__":
    raise SystemExit(main())
