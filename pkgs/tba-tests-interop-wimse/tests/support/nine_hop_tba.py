"""Bind the pinned TbA proof and JOSE implementations to B_CHAIN."""

from base64 import b64encode
from contextvars import ContextVar
from hashlib import sha256
from math import isfinite
from secrets import token_urlsafe
from time import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tba_concrete_jwt import decode_jwt_unverified
from tba_profile_workload_credential_wimse_wit import verify_wit
from tba_profile_workload_credential_wimse_wit.issuance import issue_wit
from tba_profile_workload_proof_wimse_http_signature.request import (
    FIELDS,
    _authenticate_signature,
    _sign_request,
    normalize,
)
from tba_profile_workload_proof_wimse_wpt import authenticate_wpt_request, present_wit
from tba_provider_jose_cryptography.jws import JwsCryptographyProvider, sign_compact_jwt
from tba_provider_jose_cryptography.public_jws import verify_public_jws
from tba_provider_replay_memory import MemoryReplayCheckProvider

from nine_hop_runtime import PeerBinding


PIN = (
    "tba",
    "sha256:a4eeb55ad83b39b74e2ee5a9ecadb5cb42f03bb810e21622acca953f2e9b1d19",
    "shared-python-tls-direct-ca-ledger-v1",
)
DOMAIN_A = "http://maurice.ietf127.example:5051"
DOMAIN_B = "http://rich.ietf127.example:5061"
GRANT_AUDIENCE = DOMAIN_B + "/oauth/token"
COORDINATOR_AUDIENCE = "http://rich.ietf127.example:5060"
RESEARCH_AUDIENCE = "http://rich.ietf127.example:5062"
COORDINATOR_SUBJECT = "wimse://rich.ietf127.example/agent/coordinator"
RESEARCH_SUBJECT = "wimse://rich.ietf127.example/agent/research"
DRIVER_SUBJECT = "wimse://peer.ietf127.example/client"
INITIAL_SCOPE = {"files:read", "files:list"}


def _now(now):
    return int(time()) if now is None else now


def _json_digest(body):
    return "sha-256=:" + b64encode(sha256(body).digest()).decode("ascii") + ":"


def _scope(claims):
    return set(claims.get("scope", "").split())


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


class _Issuer:
    def __init__(self, fixture, name, *trust_bundles):
        self.kid = name + "-tba"
        key = Ed25519PrivateKey.generate()
        self.signer = JwsCryptographyProvider({self.kid: key})
        public = fixture.jwk_from_public(key.public_key(), kid=self.kid, alg="EdDSA")
        for bundle in trust_bundles:
            bundle["keys"][:] = [jwk for jwk in bundle["keys"] if jwk.get("kid") != self.kid]
            bundle["keys"].append(public)

    def issue(self, typ, *, iss, aud, txn, sub, scope, tctx, ttl, now, **extra):
        instant = _now(now)
        claims = {
            "iss": iss, "aud": aud, "txn": txn, "sub": sub, "scope": scope,
            "tctx": tctx or {}, "iat": instant, "exp": instant + ttl, **extra,
        }
        return sign_compact_jwt(
            self.signer, claims,
            headers={"alg": "EdDSA", "typ": typ, "kid": self.kid},
            key_reference=self.kid,
        )


def _verify_jwt(token, jwks, *, expected_typ, expected_aud=None, now=None):
    parsed = decode_jwt_unverified(token)
    protected, claims = parsed.jws.protected_headers, parsed.claims
    candidates = [key for key in jwks["keys"] if key.get("kid") == protected.get("kid")]
    _require(len(candidates) == 1, "JWT signing key must resolve uniquely")
    verify_public_jws(token, candidates[0])
    _require(protected.get("typ") == expected_typ, "JWT type mismatch")
    instant = _now(now)
    iat, expires = claims.get("iat"), claims.get("exp")
    _require(
        all(type(value) in (int, float) and isfinite(value) for value in (iat, expires))
        and iat <= instant < expires,
        "JWT validity period mismatch",
    )
    audiences = claims.get("aud")
    if isinstance(audiences, str):
        audiences = [audiences]
    _require(expected_aud is None or isinstance(audiences, list) and expected_aud in audiences,
             "JWT audience mismatch")
    _require(bool(claims.get("txn") and claims.get("sub")) and _scope(claims) <= INITIAL_SCOPE
             and "files:read" in _scope(claims) and claims.get("tctx") == {"file": "Q3.pdf"},
             "JWT transaction claims mismatch")
    return claims


def _path(url):
    target = urlsplit(url)
    return target.path + ("?" + target.query if target.query else "")


class _Bindings:
    def __init__(self, fixture, domain_a, domain_b):
        self.fixture = fixture
        self.replay = MemoryReplayCheckProvider()
        self.subject = ContextVar("nine_hop_tba_verified_subject", default=None)
        self.driver_identity = ContextVar("nine_hop_tba_driver_identity", default=None)
        self.tts_a = _Issuer(fixture, "tts_a", domain_a.TTS_A_JWKS)
        self.as_a = _Issuer(fixture, "as_a", domain_a.AS_A_JWKS, domain_b.as_a_jwks)
        self.as_b = _Issuer(fixture, "as_b", domain_b.as_b_jwks)
        self.tts_b = _Issuer(fixture, "tts_b", domain_b.tts_b_jwks)
        self.rich = _Issuer(fixture, "rich", domain_b.rich_jwks)

    def sign_driver(self, method, url, body, wit, wkey, **kwargs):
        if urlsplit(url).path.endswith("/workflows/text-stats/executions"):
            self.driver_identity.set((wit, wkey))
        identity = self.driver_identity.get()
        _require(identity is not None, "driver must establish its identity at ingress")
        return self.sign_http(method, url, body, *identity, **kwargs)

    def sign_http(self, method, url, body, wit, wkey, *, aud, headers=None,
                  content_type="application/json"):
        _require(method == "POST" and bool(body), "expected a B_CHAIN POST with a body")
        fields = {
            **(headers or {}),
            "content-type": content_type,
            "content-digest": _json_digest(body),
        }
        signed = _sign_request(
            wkey, wit, method, _path(url), _now(None), extra_headers=fields,
            authority=None, derived=FIELDS, binding="wimse-aud", value=aud,
        )
        return self.fixture.Req(method, url, signed, body)

    def verify_proof(self, method, path_and_query, headers, body, trust_jwks, *,
                     expected_aud, now=None, seen_nonces=None):
        instant = _now(now)
        pairs = tuple(headers.items())
        trusted = {domain: tuple(bundle["keys"]) for domain, bundle in trust_jwks.items()}
        self.subject.set(None)
        try:
            if urlsplit(path_and_query).path == "/files/read":
                selected = authenticate_wpt_request(
                    pairs, audience=expected_aud, trust_by_domain=trusted, now=instant,
                    replay_store=self.replay,
                )
                subject = selected.claims["sub"]
                mechanism = "wpt"
                _require(subject == RESEARCH_SUBJECT, "file reader is not the Research workload")
            else:
                covered = normalize(pairs)
                _require(method == "POST" and bool(body) and
                         covered.get("content-type") == "application/json" and
                         covered.get("content-digest") == _json_digest(body),
                         "request content digest mismatch")
                signature_input = covered.get("signature-input", "")
                if ';keyid="wimse"' in signature_input:
                    authority = urlsplit(expected_aud).netloc
                    hosts = [value for name, value in pairs if name.lower() == "host"]
                    _require(hosts == [authority], "signed Cofide authority mismatch")
                    profile = {
                        "authority": authority, "derived": ("@method", "@request-target", "@authority"),
                        "binding": "keyid", "expected_binding": "wimse", "required_algorithm": "ES256",
                    }
                else:
                    profile = {
                        "authority": None, "derived": FIELDS,
                        "binding": "wimse-aud", "expected_binding": expected_aud,
                    }
                subject = _authenticate_signature(
                    pairs, method=method, path=path_and_query, now=instant,
                    trust_by_domain=trusted, replay_store=self.replay,
                    verify_credential=verify_wit, **profile,
                )
                mechanism = "http-sig"
            self.subject.set(subject)
            return True, 200, "accept", {"peer_id": subject, "mechanism": mechanism}
        except (KeyError, ValueError):
            return False, 401, "tba-proof-rejected", None

    def sign_wpt(self, method, url, body, wit, wkey, *, aud, alg, headers=None,
                 content_type="application/json", txn_token=None):
        _require(txn_token is not None and (headers or {}).get("Txn-Token") == txn_token,
                 "expected the same narrowed transaction token in both WPT inputs")
        # This pinned JOSE signer offers EdDSA, so provision a fresh native
        # Research WIT with an EdDSA confirmation key for the outgoing proof.
        instant = _now(None)
        workload = Ed25519PrivateKey.generate()
        credential = issue_wit(
            self.rich.signer, subject=RESEARCH_SUBJECT,
            confirmation_jwk=self.fixture.jwk_from_public(workload.public_key(), alg="EdDSA"),
            issuer_key_reference=self.rich.kid, issuer_key_id=self.rich.kid,
            issuer_algorithm="EdDSA", issued_at=instant, expires_at=instant + 300,
        )
        presented = present_wit(
            JwsCryptographyProvider({"research": workload}), credential,
            workload_key_reference="research", target_uri=aud, now=instant,
            transaction_token=txn_token,
        )
        return self.fixture.Req(method, url, {"Content-Type": content_type, **presented}, body)

    def issue_transaction(self, key, *, kid, iss, aud, txn, sub, scope, req_wl, tctx=None,
                          ttl=120, now=None):
        issuer = self.tts_a if iss == DOMAIN_A else self.tts_b
        binding = {
            (DOMAIN_A, "maurice.ietf127.example", DRIVER_SUBJECT): INITIAL_SCOPE,
            (DOMAIN_B, "rich.ietf127.example", COORDINATOR_SUBJECT): INITIAL_SCOPE,
            (DOMAIN_B, "rich.ietf127.example", RESEARCH_SUBJECT): {"files:read"},
        }
        _require(binding.get((iss, aud, req_wl)) == set(scope.split()) and
                 tctx == {"file": "Q3.pdf"} and bool(sub and txn),
                 "unexpected transaction issuance parameters")
        return issuer.issue(
            "txntoken+jwt", iss=iss, aud=aud, txn=txn, sub=sub, scope=scope, tctx=tctx,
            ttl=ttl, now=now, req_wl=req_wl,
        )

    def issue_grant(self, key, *, kid, iss, aud, sub, scope, txn, tctx=None, ttl=60, now=None):
        _require((iss, aud) == (DOMAIN_A, GRANT_AUDIENCE) and set(scope.split()) == INITIAL_SCOPE,
                 "unexpected source exchange claims")
        return self.as_a.issue(
            "jwt-chg+jwt", iss=iss, aud=aud, txn=txn, sub=sub, scope=scope, tctx=tctx,
            ttl=ttl, now=now, jti=token_urlsafe(16),
        )

    def issue_access(self, key, *, kid, iss, aud, sub, scope, txn, tctx=None, ttl=120, now=None):
        _require(iss == DOMAIN_B and set(aud) == {COORDINATOR_AUDIENCE, RESEARCH_AUDIENCE}
                 and set(scope.split()) == INITIAL_SCOPE, "unexpected destination exchange claims")
        return self.as_b.issue(
            "at+jwt", iss=iss, aud=aud, txn=txn, sub=sub, scope=scope, tctx=tctx,
            ttl=ttl, now=now, jti=token_urlsafe(16),
        )

    def verify_grant(self, token, jwks, **kwargs):
        claims = _verify_jwt(token, jwks, **kwargs)
        _require(claims.get("iss") == DOMAIN_A and bool(claims.get("jti")) and
                 _scope(claims) == INITIAL_SCOPE, "unexpected cross-domain grant")
        return claims

    def verify_issuer_b_input(self, token, jwks, **kwargs):
        claims = _verify_jwt(token, jwks, **kwargs)
        _require(claims.get("iss") == DOMAIN_B and _scope(claims) == INITIAL_SCOPE,
                 "unexpected Domain B issuer input")
        if kwargs["expected_typ"] == "at+jwt":
            _require(claims.get("aud") == [COORDINATOR_AUDIENCE, RESEARCH_AUDIENCE],
                     "incoming access token audience mismatch")
        else:
            _require(claims.get("req_wl") == COORDINATOR_SUBJECT,
                     "prior token is not bound to the Coordinator")
        return claims

    def verify_coordinator_access(self, token, jwks, **kwargs):
        claims = _verify_jwt(token, jwks, **kwargs)
        _require(claims.get("iss") == DOMAIN_B and _scope(claims) == INITIAL_SCOPE,
                 "unexpected Coordinator access token")
        return claims

    def verify_bound_transaction(self, token, jwks, **kwargs):
        claims = _verify_jwt(token, jwks, **kwargs)
        subject = self.subject.get()
        scope = {"files:read"} if subject == RESEARCH_SUBJECT else INITIAL_SCOPE
        issuer = DOMAIN_A if subject == DRIVER_SUBJECT else DOMAIN_B
        _require(subject is not None and claims.get("req_wl") == subject and
                 claims.get("iss") == issuer and _scope(claims) == scope,
                 "transaction workload binding mismatch")
        return claims


def build_bindings(context):
    """Load after the shared runner provisions and imports the fixture keys."""
    b = _Bindings(context["wimse"], context["domain_a"], context["domain_b"])
    operations = {
        "driver": {"http_sig": b.sign_driver},
        "issuer-a": {"issue_txn_token": b.issue_transaction},
        "ingress": {"verify_wimse_proof": b.verify_proof, "verify_jwt": b.verify_bound_transaction},
        "exchange-a": {
            "verify_wimse_proof": b.verify_proof, "verify_jwt": b.verify_bound_transaction,
            "issue_chain_grant": b.issue_grant,
        },
        "exchange-b": {"verify_jwt": b.verify_grant, "issue_access_token": b.issue_access},
        "coordinator": {
            "verify_wimse_proof": b.verify_proof, "verify_jwt": b.verify_coordinator_access,
            "http_sig": b.sign_http,
        },
        "issuer-b": {"verify_jwt": b.verify_issuer_b_input, "issue_txn_token": b.issue_transaction},
        "research": {
            "verify_wimse_proof": b.verify_proof, "verify_jwt": b.verify_bound_transaction,
            "wpt_request": b.sign_wpt,
        },
        "file-tool": {"verify_wimse_proof": b.verify_proof, "verify_jwt": b.verify_bound_transaction},
    }
    return {role: PeerBinding(ops, PIN) for role, ops in operations.items()}
