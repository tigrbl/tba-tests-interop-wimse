"""Report the pinned Authgent issuer's compatibility with B_CHAIN issuance."""
from argparse import ArgumentParser
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError

from authgent_matrix_runtime import authgent_issuer
from qualify_authgent_runtime import AUTHGENT_REVISION, EXCHANGE, TOKEN_TYPE, json_request, register
from tba_concrete_jwt import decode_jwt_unverified
from tba_provider_jose_cryptography.public_jws import verify_public_jws


ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
SCOPE = "files:read files:list"


def issuance(issuer, audience, identity, label):
    parent = register(issuer.base, "B_CHAIN subject", ["client_credentials"], SCOPE)
    client = register(issuer.base, label, [EXCHANGE], SCOPE)
    access = json_request(issuer.base, "/token", form={
        **parent, "grant_type": "client_credentials", "scope": SCOPE,
    })["access_token"]
    request = {
        **client, "grant_type": EXCHANGE, "subject_token": access,
        "subject_token_type": ACCESS_TOKEN, "requested_token_type": TOKEN_TYPE,
        "audience": audience, "scope": SCOPE,
        "request_details": json.dumps({"file": "Q3.pdf"}),
    }
    response = json_request(issuer.base, "/token", form=request)
    if response["issued_token_type"] != TOKEN_TYPE or response.get("refresh_token"):
        raise ValueError("Unexpected token exchange response")
    serialized = response["access_token"]
    token = decode_jwt_unverified(serialized)
    headers, claims = token.jws.protected_headers, token.claims
    key, = [key for key in issuer.jwks if key["kid"] == headers["kid"]]
    verify_public_jws(serialized, key)
    if (headers["typ"] != "txntoken+jwt" or claims["iss"] != issuer.base
            or claims["aud"] != audience or set(claims["scope"].split()) != set(SCOPE.split())
            or not claims["txn"] or claims["tctx"] != {"file": "Q3.pdf"}):
        raise ValueError("Unexpected signed transaction claims")
    result = {
        "http_status": 200, "signature_verified": True,
        "requesting_workload_matches_wit_subject": claims["req_wl"] == identity,
        "requesting_workload_is_registered_client": claims["req_wl"] == f"client:{client['client_id']}",
    }
    return serialized, result


def qualify(python, checkout):
    with TemporaryDirectory(ignore_cleanup_errors=True) as source, TemporaryDirectory(ignore_cleanup_errors=True) as destination:
        with authgent_issuer(python, checkout, Path(source), audience="maurice.ietf127.example") as issuer:
            _, hop1 = issuance(issuer, "maurice.ietf127.example", "wimse://peer.ietf127.example/client", "Driver")
        with authgent_issuer(python, checkout, Path(destination), audience="rich.ietf127.example") as issuer:
            parent, hop6 = issuance(
                issuer, "rich.ietf127.example", "wimse://rich.ietf127.example/agent/coordinator", "Coordinator",
            )
            research = register(issuer.base, "Research", [EXCHANGE], "files:read")
            try:
                json_request(issuer.base, "/token", form={
                    **research, "grant_type": EXCHANGE, "subject_token": parent,
                    "subject_token_type": TOKEN_TYPE, "requested_token_type": TOKEN_TYPE,
                    "audience": "rich.ietf127.example", "scope": "files:read",
                })
            except HTTPError as error:
                with error:
                    failure = json.load(error)
                hop8 = {"http_status": error.code, "oauth_error": failure["error"],
                        "description": failure.get("error_description")}
            else:
                raise ValueError("Authgent accepted a prior transaction token. Qualify its replacement claims.")
    return {"revision": AUTHGENT_REVISION, "hop_1": hop1, "hop_6": hop6, "hop_8": hop8}


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--authgent-python", type=Path, required=True)
    parser.add_argument("--authgent-checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.authgent_python.resolve(), args.authgent_checkout.resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
