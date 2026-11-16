"""Real Authgent issuance and transaction consumption for the typed matrix."""

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
from secrets import token_urlsafe
from socket import socket
import subprocess
from time import monotonic, sleep, time
from urllib.error import HTTPError, URLError

from tba_concrete_jwt import decode_jwt_unverified
from tba_provider_jose_cryptography.public_jws import verify_public_jws

from qualify_authgent_runtime import AUTHGENT_REVISION, EXCHANGE, TOKEN_TYPE, json_request, register
from support.cred_endpoint import call_bridge
from support.typed_hop_adapters import observe_http
from support.typed_service_bindings import TypedServiceBindings


AUDIENCE = "example.org"
SCOPES = {
    "calendar.forward": ["forward"],
    "calendar.write": ["write"],
    "calendar.exchange": ["exchange"],
}
PARENT_SCOPE = " ".join(SCOPES)
OUTSIDE_SCOPE = "calendar.admin"


def fingerprint(token):
    return sha256(token.encode("ascii")).hexdigest()


@contextmanager
def authgent_issuer(python, checkout, output):
    root = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain",
                                     "--untracked-files=no"], text=True)
    installed = subprocess.check_output([
        str(python), "-c",
        'from importlib.metadata import distribution; print(distribution("authgent-server").read_text("direct_url.json"))',
    ], text=True)
    if root != AUTHGENT_REVISION or dirty or json.loads(installed)["url"] != (checkout / "server").as_uri():
        raise ValueError(f"Install Authgent from the clean checkout at {AUTHGENT_REVISION}")
    with socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("AUTHGENT_", "PYTHONPATH", "PYTHONHOME"))}
    env.update(AUTHGENT_SERVER_URL=base, AUTHGENT_TXN_TOKEN_TRUST_DOMAIN=AUDIENCE,
               AUTHGENT_DATABASE_URL="sqlite+aiosqlite:///:memory:", AUTHGENT_REGISTRATION_POLICY="open",
               AUTHGENT_SECRET_KEY=token_urlsafe(64), PYTHONIOENCODING="utf-8")
    with (output / "issuer.log").open("w", encoding="utf-8") as log:
        issuer = subprocess.Popen(
            [str(python), "-m", "uvicorn", "authgent_server.app:create_app", "--factory",
             "--host", "127.0.0.1", "--port", str(port)],
            cwd=output, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = monotonic() + 30
            while True:
                try:
                    jwks = json_request(base, "/.well-known/jwks.json")["keys"]
                    break
                except URLError:
                    if issuer.poll() is not None or monotonic() >= deadline:
                        raise RuntimeError("Authgent did not become ready. See issuer.log.") from None
                    sleep(.25)
            yield TbaTransactionCaller(base, jwks)
        finally:
            if issuer.poll() is None:
                issuer.terminate()
            issuer.wait(timeout=15)


class TbaTransactionCaller:
    """Request and verify transaction JWTs from the loopback OAuth issuer."""

    def __init__(self, base, jwks):
        self.base, self.jwks = base, jwks
        self.parent = register(base, "TbA subject", ["client_credentials"], PARENT_SCOPE)
        self.client = register(base, "TbA transaction caller", [EXCHANGE], f"{PARENT_SCOPE} {OUTSIDE_SCOPE}")

    def verify(self, token, *, audience=AUDIENCE):
        if not token:
            raise ValueError("missing transaction token")
        decoded = decode_jwt_unverified(token)
        headers, claims = decoded.jws.protected_headers, decoded.claims
        keys = [key for key in self.jwks if key["kid"] == headers.get("kid")]
        if headers.get("typ") != "txntoken+jwt" or len(keys) != 1:
            raise ValueError("untrusted transaction token")
        verify_public_jws(token, keys[0])
        if (claims["iss"], claims["aud"]) != (self.base, audience):
            raise ValueError("transaction issuer or audience mismatch")
        if not claims["iat"] <= time() < claims["exp"]:
            raise ValueError("transaction token outside its validity period")
        if (claims["sub"], claims["req_wl"]) != (
            f"client:{self.parent['client_id']}", f"client:{self.client['client_id']}",
        ) or not claims["txn"]:
            raise ValueError("transaction does not identify the registered TbA clients")
        return claims

    def exchange(self, origin, scopes):
        subject = json_request(self.base, "/token", form={
            **self.parent, "grant_type": "client_credentials", "scope": PARENT_SCOPE,
        })["access_token"]
        try:
            response = json_request(self.base, "/token", form={
                **self.client, "grant_type": EXCHANGE, "subject_token": subject,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": TOKEN_TYPE, "audience": AUDIENCE, "scope": " ".join(sorted(scopes)),
                "request_details": json.dumps({"origin": origin}),
            })
        except HTTPError as error:
            with error:
                body = json.load(error)
                if (error.code != 403 or body.get("error") != "access_denied"
                        or "access_token" in body or "refresh_token" in body):
                    raise
            return None, {"http_status": 403, "oauth_error": "access_denied"}
        if (response.get("issued_token_type") != TOKEN_TYPE or response.get("token_type") != "N_A"
                or response.get("refresh_token") is not None):
            raise ValueError("invalid Authgent transaction-token response")
        token = response["access_token"]
        claims = self.verify(token)
        if set(claims["scope"].split()) != set(scopes) or claims["tctx"]["origin"] != origin:
            raise ValueError("issuer changed the requested transaction scope or context")
        return token, {"http_status": 200, "issued_transaction_sha256": fingerprint(token)}


class AuthgentServices(TypedServiceBindings):
    bindings = {**TypedServiceBindings.bindings, "authgent-issue": {"authgent"}}

    def __init__(self, hops, caller, cred_verifier, outcome):
        super().__init__(hops)
        self.caller = caller
        self.cred_verifier = cred_verifier
        self.origin = hops[0]["caller"]
        self.transaction = None
        self.handoff = None
        self.verified = {}
        self.scope_fault_hop = outcome.partition(":")[0] if outcome.endswith(":operation-scope-refused") else None

    def operation(self, index):
        return "forward" if index < len(self.hops) - 1 else "write"

    def support_request(self, index, fault):
        hop = self.hops[index]
        if hop["operation"] == "authgent-issue":
            scopes = set(SCOPES)
            if fault:
                scopes = {OUTSIDE_SCOPE}
            elif self.scope_fault_hop:
                scopes.remove(f"calendar.{self.operation(int(self.scope_fault_hop) - 1)}")
            self.transaction, evidence = self.caller.exchange(self.origin, scopes)
            if self.transaction is None:
                return {**self.refusal("transaction-token-request-refused"), **evidence}
            self.handoff = self.transaction
            return self.accepted("transaction-token-issued", **evidence)
        if hop["operation"] == "source-exchange":
            def accept(payload):
                token = payload["transaction"]
                try:
                    claims = self.caller.verify(token, audience="other.example" if fault else AUDIENCE)
                except ValueError as error:
                    if str(error) != "transaction issuer or audience mismatch":
                        raise
                    return self.refusal("source-transaction-token-refused")
                if claims["tctx"]["origin"] != payload["actor"] or "calendar.exchange" not in claims["scope"].split():
                    return self.refusal("source-transaction-token-refused")
                digest = fingerprint(token)
                return self.accepted("destination-authorization-grant-issued", grant=self.destination.issue(
                    payload["actor"], "exchange", nonce=digest,
                ), verified_transaction_sha256=digest)

            reply = self.exchange_observation({"transaction": self.handoff, "actor": hop["caller"]}, accept)
            self.grant = reply.pop("grant", None)
            if self.grant:
                reply["issued_grant_sha256"] = fingerprint(self.grant)
            reply["presented_transaction_sha256"] = fingerprint(self.handoff)
            return reply
        if hop["operation"] == "destination-exchange":
            grant = self.source.issue(hop["caller"], "exchange") if fault else self.grant

            def redeem(payload):
                try:
                    claims = self.claims(self.destination, payload["grant"], payload["actor"], {"exchange"})
                    if claims.get("nonce") != fingerprint(self.transaction):
                        raise ValueError("grant is for another transaction")
                except ValueError:
                    return self.refusal("authorization-grant-refused")
                return self.accepted("destination-access-token-issued",
                                     verified_transaction_sha256=claims["nonce"],
                                     token=self.resource.issue(payload["actor"], "write"))

            reply = self.exchange_observation({"grant": grant, "actor": hop["caller"]}, redeem)
            access = reply.pop("token", None)
            if access:
                self.claims(self.resource, access, hop["caller"], {"write"})
                reply["issued_access_token_sha256"] = fingerprint(access)
            return {**reply, "presented_grant_sha256": fingerprint(grant)}
        return super().support_request(index, fault)

    @staticmethod
    def exchange_observation(payload, evaluate):
        reply = observe_http(payload, evaluate)
        assert reply.pop("reached_hops") == reply.pop("decision_hop") == 1
        assert reply.pop("effects") == 0
        return reply

    def headers(self, index, fault, fixture):
        return {"txn-token": self.handoff}

    def authorize(self, index, identity, headers, fault, fixture):
        values = headers.get_all("txn-token", ())
        if len(values) != 1:
            raise ValueError("expected a single transaction token")
        token = values[0]
        expected = self.hops[index]["caller"]
        receiver = self.hops[index]["receiver_pin"][0]
        if receiver == "cred":
            verified = call_bridge(self.cred_verifier, token=token, jwks=self.caller.jwks,
                                   audience=AUDIENCE, scopeMap=SCOPES)
            claims, operations = verified["claims"], verified["operations"]
        else:
            claims = self.caller.verify(token)
            operations = [action for scope in claims["scope"].split() for action in SCOPES.get(scope, ())]
        if identity.rsplit("/", 1)[-1] != expected or claims["tctx"]["origin"] != self.origin:
            raise ValueError("transaction route does not match the authenticated workload")
        if token != self.transaction or claims["iss"] != self.caller.base:
            raise ValueError("transaction handoff differs from the issued token")
        required = self.operation(index)
        self.verified[index] = {
            "verified_transaction_sha256": fingerprint(token),
            "transaction_verifier": receiver, "required_operation": required,
            "verified_scopes": claims["scope"].split(), "authenticated_caller": identity,
        }
        if not operations or required not in operations:
            raise ValueError("operation-scope-refused")
        self.handoff = token

    def workload_evidence(self, index):
        return self.verified.get(index, {})
