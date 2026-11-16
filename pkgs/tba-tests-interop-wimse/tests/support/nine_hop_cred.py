"""Cred proof and token operations for the loopback B_CHAIN fixture."""

from base64 import b64encode
from functools import partial
import json
import os
from pathlib import Path
import subprocess
from threading import Lock
from time import time
from urllib.parse import urlsplit

from nine_hop_runtime import PeerBinding


REVISION = "586e1a76f487c2376e0ba0a4687bb2de8d3eb588"
PIN = ("cred", REVISION, "shared-python-tls-direct-ca-ledger-v1")
DRIVER = "wimse://peer.ietf127.example/client"
COORDINATOR = "wimse://rich.ietf127.example/agent/coordinator"
RESEARCH = "wimse://rich.ietf127.example/agent/research"
DOMAIN_A_ISSUER = "http://maurice.ietf127.example:5051"
DOMAIN_B_ISSUER = "http://rich.ietf127.example:5061"


def stage_source(checkout, directory):
    directory.mkdir(parents=True, exist_ok=True)
    builder = Path(__file__).with_name("nine_hop_cred_build.mjs")
    subprocess.run(["node", str(builder), str(checkout), str(directory)], check=True, timeout=30)
    return directory / "nine_hop_cred.mjs"


class _Bridge:
    def __init__(self, script):
        self.process = subprocess.Popen(
            ["node", str(script)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, encoding="utf-8",
        )
        self.lock = Lock()

    def close(self):
        with self.lock:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process.stdout.close()

    def call(self, command, **data):
        with self.lock:
            self.process.stdin.write(json.dumps({"command": command, **data}) + "\n")
            self.process.stdin.flush()
            line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("Cred nine-hop process stopped")
        result = json.loads(line)
        if "error" in result:
            raise RuntimeError(f"Cred nine-hop operation errored ({result['error']})")
        if "denied" in result:
            raise ValueError(result["denied"])
        return result


class _Operations:
    def __init__(self, wimse, bridge):
        self.wimse = wimse
        self.bridge = bridge
        self.driver_identity = None
        self.seen = {}
        self.prune_after = 0
        self.replay_lock = Lock()

    @staticmethod
    def _keys(jwks):
        return jwks["keys"] if "keys" in jwks else [jwks]

    def _private_key(self, key):
        public = self.wimse.jwk_from_public(key.public_key())
        private = (key.private_numbers().private_value.to_bytes(32, "big")
                   if public["kty"] == "EC" else key.private_bytes_raw())
        return {**public, "d": self.wimse.b64u(private)}

    @staticmethod
    def _request(method, path, headers, body):
        target = urlsplit(path)
        return {
            "method": method, "path": target.path, "query": target.query,
            "headers": {name.lower(): value for name, value in headers.items()},
            "body": b64encode(body).decode("ascii"),
        }

    def driver_http_sig(self, method, url, body, wit, wkey, **options):
        # The reference driver enrolls a fresh confirmation key for each
        # request. Use the first enrollment throughout this B_CHAIN.
        path = urlsplit(url).path
        if path.endswith("/workflows/text-stats/executions"):
            self.driver_identity = (wit, wkey)
        elif path not in ("/oauth/token", "/coordinate"):
            raise ValueError("Unexpected Cred B_CHAIN driver route")
        if self.driver_identity is None:
            raise RuntimeError("Cred driver has no B_CHAIN ingress enrollment")
        return self.http_sig(method, url, body, *self.driver_identity, **options)

    def http_sig(self, method, url, body, wit, wkey, *, aud, headers=None,
                 content_type="application/json"):
        headers = {name.lower(): value for name, value in (headers or {}).items()}
        if body:
            headers["content-type"] = content_type
        signed = self.bridge.call(
            "http-sign", request=self._request(method, url, headers, body),
            audience=aud, key=self._private_key(wkey), wit=wit,
        )
        return self.wimse.Req(method, url, signed["headers"], body)

    def wpt_request(self, method, url, body, wit, wkey, *, aud, alg, txn_token, headers=None,
                    content_type="application/json"):
        headers = {name.lower(): value for name, value in (headers or {}).items()}
        if headers.get("txn-token") != txn_token or not txn_token:
            raise ValueError("WPT requires the presented B_CHAIN Txn-Token")
        key = self._private_key(wkey)
        if alg != key["alg"] and {alg, key["alg"]} != {"Ed25519", "EdDSA"}:
            raise ValueError("Unexpected WPT algorithm")
        proof = self.bridge.call(
            "wpt-sign", wit=wit, key=key, audience=aud, transaction=txn_token,
        )["proof"]
        headers.update({"authorization": f"WPT {proof}", "workload-identity-token": wit})
        if body:
            headers["content-type"] = content_type
        return self.wimse.Req(method, url, headers, body)

    def _verify(self, profile, subject, method, path_and_query, headers, body, trust_jwks,
                *, expected_aud, seen_nonces=None, now=None):
        request = self._request(method, path_and_query, headers, body)
        options = {}
        now = int(time()) if now is None else now
        if profile == "wpt":
            scheme, _, proof = request["headers"].get("authorization", "").partition(" ")
            if scheme != "WPT" or not proof or not request["headers"].get("txn-token"):
                return False, 401, "proof-invalid", None
            options["proof"] = proof
        try:
            verified = self.bridge.call(
                f"{profile}-verify", request=request, audience=expected_aud, now=now,
                trust={domain: self._keys(keys) for domain, keys in trust_jwks.items()},
                **options,
            )
            if verified["subject"] != subject:
                return False, 403, "unexpected-workload", None
            with self.replay_lock:
                if now >= self.prune_after:
                    self.seen = {key: exp for key, exp in self.seen.items() if exp > now}
                    self.prune_after = now + 60
                replay_key = (expected_aud, subject, verified["nonce"])
                if self.seen.get(replay_key, 0) > now:
                    return False, 401, "replay", None
                self.seen[replay_key] = verified["expires"]
        except ValueError:
            return False, 401, "proof-invalid", None
        return True, 200, "accept", {
            "peer_id": verified["subject"], "wit_claims": verified["witClaims"],
            "mechanism": "http-sig" if profile == "http" else "wpt",
        }

    def _verify_token(self, profile, subject, token, jwks, *, expected_typ, expected_aud, now=None):
        if expected_typ != profile:
            raise ValueError("Unexpected Cred token profile")
        claims = self.bridge.call(
            "transaction-verify" if profile == "txntoken+jwt" else "access-verify",
            token=token, keys=self._keys(jwks), audience=expected_aud,
            now=int(time()) if now is None else now,
        )["claims"]
        if subject and claims.get("req_wl") != subject:
            raise ValueError("Txn-Token does not bind the verified workload")
        issuer = DOMAIN_A_ISSUER if subject == DRIVER else DOMAIN_B_ISSUER
        scope = {"files:read"} if subject == RESEARCH else {"files:read", "files:list"}
        if (claims.get("iss") != issuer or set(claims["scope"].split()) != scope
                or claims.get("tctx") != {"file": "Q3.pdf"}):
            raise ValueError("Token issuer, scope or file context does not match B_CHAIN")
        return claims

    def bindings(self):
        return {
            "driver": PeerBinding({"http_sig": self.driver_http_sig}, PIN),
            "ingress": PeerBinding({
                "verify_wimse_proof": partial(self._verify, "http", DRIVER),
                "verify_jwt": partial(self._verify_token, "txntoken+jwt", DRIVER),
            }, PIN),
            "coordinator": PeerBinding({
                "verify_wimse_proof": partial(self._verify, "http", DRIVER),
                "verify_jwt": partial(self._verify_token, "at+jwt", None),
                "http_sig": self.http_sig,
            }, PIN),
            "research": PeerBinding({
                "verify_wimse_proof": partial(self._verify, "http", COORDINATOR),
                "verify_jwt": partial(self._verify_token, "txntoken+jwt", COORDINATOR),
                "wpt_request": self.wpt_request,
            }, PIN),
            "file-tool": PeerBinding({
                "verify_wimse_proof": partial(self._verify, "wpt", RESEARCH),
                "verify_jwt": partial(self._verify_token, "txntoken+jwt", RESEARCH),
            }, PIN),
        }


def build_bindings(context):
    path = context.get("cred_checkout") or os.environ.get("TBA_WIMSE_CRED_CHECKOUT")
    if not path:
        return {}
    checkout = Path(path).resolve()
    git = ["git", "-C", str(checkout)]
    revision = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    status = subprocess.check_output([*git, "status", "--porcelain", "--untracked-files=no"], text=True)
    if revision != REVISION or status:
        raise ValueError("Cred requires a clean checkout at the pinned revision")
    script = stage_source(checkout, Path(context["workdir"]) / "cred")
    bridge = _Bridge(script)
    context["stack"].callback(bridge.close)
    return _Operations(context["wimse"], bridge).bindings()
