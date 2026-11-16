"""Run the pinned authgent issuer against Cred's published final-hop controls."""

import argparse
from importlib.metadata import distribution
import json
import os
from pathlib import Path
from secrets import token_urlsafe
from socket import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


AUTHGENT_REVISION = "8341cf932c9816dc666f2a6577b6776bd6f3b978"
CRED_REVISION = "586e1a76f487c2376e0ba0a4687bb2de8d3eb588"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE = "urn:ietf:params:oauth:token-type:txn_token"
AUDIENCE = "domain-b.example"
SCOPE = "calendar.read"


def json_request(base, path, *, form=None, body=None):
    data, headers = None, {}
    if form is not None:
        data = urlencode(form).encode()
    elif body is not None:
        data, headers = json.dumps(body).encode(), {"Content-Type": "application/json"}
    with urlopen(Request(base + path, data=data, headers=headers), timeout=3) as response:
        return json.load(response)


def register(base, name, grants, scope):
    registration = json_request(base, "/register", body={"client_name": name, "grant_types": grants, "scope": scope})
    return {field: registration[field] for field in ("client_id", "client_secret")}


def issue_controls(base):
    parent = register(base, "interop-parent", ["client_credentials"], SCOPE)
    caller = register(base, "interop-exchange", [EXCHANGE, "client_credentials"], SCOPE + " calendar.write")
    subject = json_request(base, "/token", form={
        "grant_type": "client_credentials", "scope": SCOPE, **parent,
    })["access_token"]
    exchange = {
        **caller, "grant_type": EXCHANGE, "subject_token": subject,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type": TOKEN_TYPE, "audience": AUDIENCE, "scope": SCOPE,
    }
    try:
        json_request(base, "/token", form={**exchange, "scope": "calendar.write"})
    except HTTPError as error:
        refusal = error.code
        if refusal != 403 or json.load(error).get("error") != "access_denied":
            raise
    else:
        raise ValueError("authgent allowed a scope outside the subject token")

    tokens = []
    for user in ("alice", "alice", "alice", "bob"):
        result = json_request(base, "/token", form={**exchange, "request_details": json.dumps({"user": user})})
        if result.get("issued_token_type") != TOKEN_TYPE or result.get("refresh_token") is not None:
            raise ValueError("authgent returned an invalid transaction-token response")
        tokens.append(result["access_token"])
    return tokens, refusal


def qualify(authgent, cred, output):
    installed = json.loads(distribution("authgent-server").read_text("direct_url.json") or "{}")
    if (installed.get("url") != (authgent / "server").as_uri()
            or subprocess.check_output(["git", "-C", str(authgent), "rev-parse", "HEAD"], text=True).strip()
            != AUTHGENT_REVISION):
        raise ValueError(f"Install the authgent server from the checkout at {AUTHGENT_REVISION}")
    revision = subprocess.check_output(["git", "-C", str(cred), "rev-parse", "HEAD"], text=True).strip()
    if revision != CRED_REVISION:
        raise ValueError(f"Expected the Cred fixture at {CRED_REVISION}")
    output.mkdir(parents=True, exist_ok=False)
    with socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    with TemporaryDirectory(dir=output) as run_dir, (output / "issuer.log").open("w", encoding="utf-8") as log:
        work = Path(run_dir)
        env = {key: value for key, value in os.environ.items() if not key.startswith("AUTHGENT_")}
        env.update(AUTHGENT_SERVER_URL=base, AUTHGENT_TXN_TOKEN_TRUST_DOMAIN=AUDIENCE,
                   AUTHGENT_DATABASE_URL="sqlite+aiosqlite:///:memory:",
                   AUTHGENT_REGISTRATION_POLICY="open", AUTHGENT_SECRET_KEY=token_urlsafe(64),
                   PYTHONIOENCODING="utf-8")
        issuer = subprocess.Popen([sys.executable, "-m", "uvicorn", "authgent_server.app:create_app",
                                   "--factory", "--host", "127.0.0.1", "--port", str(port)],
                                  cwd=output, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = monotonic() + 30
            while True:
                try:
                    jwks = json_request(base, "/.well-known/jwks.json")
                    break
                except URLError:
                    if issuer.poll() is not None or monotonic() >= deadline:
                        raise RuntimeError("The authgent lab failed to become ready; see issuer.log") from None
                    sleep(0.25)
            tokens, refusal = issue_controls(base)
            jwks_file, alices, bob = (work / name for name in ("jwks.json", "alice.json", "bob.txt"))
            jwks_file.write_text(json.dumps(jwks), encoding="utf-8")
            alices.write_text(json.dumps(tokens[:3]), encoding="utf-8")
            bob.write_text(tokens[3], encoding="utf-8")
            node = ["node"]
            if os.name == "nt":
                loader = work / "windows-imports.mjs"
                loader.write_text(
                    "import { registerHooks } from 'node:module';\n"
                    "import { pathToFileURL } from 'node:url';\n"
                    "import { win32 } from 'node:path';\n"
                    "registerHooks({resolve(s, c, next) {\n"
                    "  const fromImport = c.conditions.includes('import');\n"
                    "  return next(fromImport && win32.isAbsolute(s) ? pathToFileURL(s).href : s, c);\n"
                    "}});\n",
                    encoding="utf-8",
                )
                node.extend(["--import", loader.as_uri()])
            result = subprocess.run(
                [*node, str(cred / "scripts/hackathon/interop/txn-final-hop.mjs"),
                 str(jwks_file), str(alices), "tctx.user", str(bob)],
                check=False, capture_output=True, encoding="utf-8", timeout=180,
                env={**os.environ, "TEMP": run_dir, "TMP": run_dir, "TMPDIR": run_dir},
            )
            (output / "cred.log").write_text(result.stdout + result.stderr, encoding="utf-8")
            controls = [line for line in result.stdout.splitlines() if line.startswith("PASS ")]
            if len(controls) != 6 or "RESULT: PASS" not in result.stdout:
                raise ValueError("The Cred endpoint did not report all six transaction-token controls passing")
            # Cred removes its SQLite state before Node closes the final file handle on Windows.
            cleanup_error = bool(os.name == "nt" and result.returncode == 1
                                 and "EPERM" in result.stderr and "at Object.rmSync" in result.stderr
                                 and "txn-final-hop.mjs" in result.stderr and "cred-txn-interop-" in result.stderr)
            if not cleanup_error:
                result.check_returncode()
            record = dict(authgent_revision=AUTHGENT_REVISION, cred_revision=revision,
                          scope_refusal_status=refusal, cred_controls=controls, cred_windows_cleanup_error=cleanup_error)
            (output / "controls.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        finally:
            issuer.terminate()
            issuer.wait(timeout=15)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authgent-checkout", required=True, type=Path,
                        help=f"Checkout at {AUTHGENT_REVISION} installed in this interpreter")
    parser.add_argument("--cred-checkout", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    qualify(args.authgent_checkout.resolve(), args.cred_checkout.resolve(), args.output.resolve())
