"""B_CHAIN role bindings for the pinned Cofide HTTP message proof implementation.

The shared runner owns WIT issuance and trust anchors, token exchange, transaction
policy, and workflow logic. The Go bridge owns body digest and message signing
or verification; the alternate wire form authenticates the configured authority
rather than emitting the unsupported wimse-aud signature parameter.
"""

from base64 import b64encode
from contextvars import ContextVar
import json
import os
from pathlib import Path
from secrets import token_urlsafe
import subprocess
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization


PIN = (
    "cofide",
    "7984a60105002dc65b31e9cd08572cd5d10ed9d6",
    "shared-python-tls-direct-ca-ledger-v1",
)
BRIDGE_ENV = "TBA_WIMSE_NINE_HOP_COFIDE_BRIDGE"
DRIVER_SUBJECT = "wimse://peer.ietf127.example/client"


class ProofRefused(ValueError):
    """The pinned proof implementation declined a request."""


class Proof:
    def __init__(self, wimse, binary):
        self.wimse = wimse
        self.binary = Path(binary).resolve(strict=True)

    def _call(self, command, method, target, audience, headers, body, **payload):
        if method != "POST" or not target.startswith("/") or not body:
            raise ValueError("Cofide binding is limited to B_CHAIN POST requests with a body")
        response = subprocess.run(
            [str(self.binary)], check=True, capture_output=True, text=True, timeout=10,
            input=json.dumps(dict(
                command=command, method=method, target=target, audience=audience, headers=headers,
                body=b64encode(body).decode("ascii"), **payload,
            )),
        )
        result = json.loads(response.stdout)
        if "denied" in result:
            raise ProofRefused(result["denied"])
        return result

    def http_sig(self, method, url, body, wit, wkey, *, aud, headers=None, content_type="application/json"):
        parts = urlsplit(url)
        if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.fragment:
            raise ValueError("Cofide binding requires a disposable loopback endpoint")
        headers = {name.lower(): value for name, value in (headers or {}).items()}
        headers.update({
            "content-type": content_type, "workload-identity-token": wit, "host": urlsplit(aud).netloc,
        })
        target = parts.path + ("?" + parts.query if parts.query else "")
        key = wkey.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        )
        proof = self._call(
            "sign", method, target, aud, headers, body,
            privateKey=b64encode(key).decode("ascii"), nonce=token_urlsafe(24),
        )
        headers.update({name.lower(): value for name, value in proof.items()})
        return self.wimse.Req(method, url, headers, body)

    def verify_wimse_proof(self, method, path_and_query, headers, body, trust_jwks, *,
                           expected_aud, seen_nonces=None, now=None):
        lower = {name.lower(): value for name, value in headers.items()}
        wit = lower.get("workload-identity-token")
        if not all((wit, lower.get("signature"), lower.get("signature-input"))):
            return False, 401, "proof-missing", None
        try:
            _, presented, _, _ = self.wimse.parse_jwt(wit)
            trust_domain = self.wimse._valid_wimse_id(presented.get("sub"))
            claims = self.wimse.verify_jwt(wit, trust_jwks[trust_domain], expected_typ="wit+jwt", now=now)
            sender = claims["sub"]
            jwk = claims["cnf"]["jwk"]
        except (ValueError, TypeError, KeyError):
            return False, 400, "wit-invalid", None
        try:
            proof = self._call("verify", method, path_and_query, expected_aud, lower, body, publicKey=jwk)
        except ProofRefused:
            return False, 400, "proof-invalid", None
        if seen_nonces is not None:
            nonce = proof["nonce"]
            if nonce in seen_nonces:
                return False, 400, "replay", None
            seen_nonces.add(nonce)
        return True, 200, "accept", {
            "peer_id": sender, "wid": sender, "wit_claims": claims, "mechanism": "http-sig",
        }


class Driver:
    def __init__(self, proof):
        self.proof = proof
        self.workload = ContextVar("cofide_driver_workload", default=None)

    def http_sig(self, method, url, body, wit, wkey, **kwargs):
        path = urlsplit(url).path
        if self.proof.wimse.parse_jwt(wit)[1].get("sub") != DRIVER_SUBJECT:
            raise ValueError("Unexpected B_CHAIN driver identity")
        if path.endswith("/workflows/text-stats/executions"):
            # The pinned driver offers a fresh WIT at each hop. Keep the same
            # proof key and WIT for this assignment, refreshing at next ingress.
            self.workload.set((wit, wkey))
        elif path not in ("/oauth/token", "/coordinate"):
            raise ValueError("Unexpected B_CHAIN driver route")
        workload = self.workload.get()
        if workload is None:
            raise ValueError("B_CHAIN driver did not initialize its ingress workload")
        return self.proof.http_sig(method, url, body, *workload, **kwargs)


def build_bindings(context):
    from nine_hop_runtime import PeerBinding

    binary = os.environ.get(BRIDGE_ENV)
    if not binary:
        return {}
    proof = Proof(context["wimse"], binary)
    return {
        "driver": PeerBinding({"http_sig": Driver(proof).http_sig}, PIN),
        "ingress": PeerBinding({"verify_wimse_proof": proof.verify_wimse_proof}, PIN),
        "coordinator": PeerBinding({
            "http_sig": proof.http_sig, "verify_wimse_proof": proof.verify_wimse_proof,
        }, PIN),
    }
