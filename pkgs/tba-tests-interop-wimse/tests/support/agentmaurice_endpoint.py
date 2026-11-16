"""Wire helpers for the AgentMaurice v2.2.18 workflow endpoint."""

from base64 import b64encode
from hashlib import sha256
import json
from secrets import token_urlsafe
from time import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tba_primitives_identity import base64url_encode
from tba_profile_workload_proof_wimse_http_signature.request import TAG, signing_base

from support.wpt_fixture import public_jwk, sign_es256_jwt, sign_wpt_claims


AUDIENCE = "https://receiver.example.org"
WORKLOAD = "wimse://example.org/tba-workload"
BODY = b'{"inputs":{"text":"interop"}}'
CONFIGURATION = "agentmaurice-v2.2.18-workflow-loopback-v1"
BINARY_SHA256 = "a2b79f0565e05b8a2de1692d102e808b5b69e65954f2ea8aa7963e1bf8544bff"


def baseline_wit(issuer, subject=WORKLOAD):
    now = int(time())
    key = ec.generate_private_key(ec.SECP256R1())
    token = sign_es256_jwt(issuer, {
        "iss": "https://tba.example.org",
        "sub": subject,
        "cnf": {"jwk": public_jwk(key)},
        "iat": now,
        "exp": now + 120,
        "jti": token_urlsafe(16),
    }, {"typ": "wit+jwt", "alg": "ES256", "kid": "tba-test-issuer"})
    return token, key


def workflow_headers(mode, path, token, key, *, audience=AUDIENCE, missing=False, body=BODY,
                     transaction=None, signed_path=None, signed_authority=None):
    now = int(time())
    values = {"content-type": "application/json", "workload-identity-token": token}
    if transaction is not None:
        values["txn-token"] = transaction
    if missing:
        return values
    if mode == "wpt":
        claims = {
            "aud": audience, "iat": now, "exp": now + 60, "jti": token_urlsafe(16),
            "wth": base64url_encode(sha256(token.encode("ascii")).digest()),
        }
        if transaction is not None:
            claims["tth"] = base64url_encode(sha256(transaction.encode("ascii")).digest())
        proof = sign_wpt_claims(key, claims, "ES256")
        return {**values, "authorization": f"WPT {proof}"}
    if mode != "http-sig":
        raise ValueError(f"Unknown proof mode {mode}")
    # AgentMaurice authenticates a JSON workflow invocation. Its protocol
    # endpoint requires a signed Content-Digest for that request body.
    values["content-digest"] = f"sha-256=:{b64encode(sha256(body).digest()).decode('ascii')}:"
    fields = ("@method", "@path", "@query")
    if signed_authority is not None:
        fields += ("@authority",)
    fields += ("content-type", "content-digest")
    if transaction is not None:
        fields += ("txn-token",)
    fields += ("workload-identity-token",)
    names = " ".join(f'"{name}"' for name in fields)
    params = (f'({names});created={now};expires={now + 60};nonce="{token_urlsafe(16)}"'
              f';tag="{TAG}";wimse-aud="{audience}"')
    raw = signing_base("POST", signed_path or path, values, fields, params, authority=signed_authority)
    r, s = utils.decode_dss_signature(key.sign(raw, ec.ECDSA(hashes.SHA256())))
    signature = b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode("ascii")
    return {**values, "signature-input": f"wimse={params}", "signature": f"wimse=:{signature}:"}


def workflow_request(path, headers, *, body=BODY):
    return json.dumps({"path": path, "headers": headers, "body": body.decode("utf-8")})
