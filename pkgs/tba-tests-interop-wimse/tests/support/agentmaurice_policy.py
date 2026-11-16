"""Drive application policy through the pinned AgentMaurice workflow runtime."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from contextlib import contextmanager
from hashlib import sha256
import json
from queue import Empty, Queue
from secrets import token_urlsafe
import subprocess
from threading import Lock
from time import time
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import ec
from tba_profile_workload_proof_wimse_wpt import authenticate_wpt_request
from tba_provider_replay_memory import MemoryReplayCheckProvider
from tba_tests_interop_wimse.observations import Observation
from tba_tests_interop_wimse.resource import WriteLedger
from tba_tests_interop_wimse.signatures import authenticate_signature

from run_agentmaurice_matrix import LiveTbAReceiver
from support.agentmaurice_endpoint import baseline_wit, workflow_headers, workflow_request
from support.wic_support_cases import request
from support.wpt_fixture import public_jwk


class Headers(dict):
    def get(self, name, default=None):
        return super().get(name.lower(), default)

    def __contains__(self, name):
        return super().__contains__(name.lower())


class PolicyBridge(LiveTbAReceiver):
    def __init__(self, lab):
        super().__init__(lab)
        self.lock = Lock()
        self.waiting = {}
        self.identity = f"wimse://example.org/agent/{lab.agent}"
        command = ("/tmp/maurice", "wimse", "trust-bundle", "export", "--data-dir", "/tmp/one", "--json")
        self.trust = {"example.org": json.loads(lab.run(*command).stdout)["keys"]}
        self.alternate = {"example.org": [
            {**public_jwk(ec.generate_private_key(ec.SECP256R1())), "kid": key["kid"]}
            for key in self.trust["example.org"]
        ]}

    def outbound(self, mode, resource, headers, *, workflow="interop-outbound"):
        try:
            response = self.lab.run("/tmp/maurice", "--config", "/tmp/cli/context.yaml",
                                    "test", "workflow", "call", workflow, "--agent-id", self.lab.agent,
                                    "--runtime-url", "http://127.0.0.1:5000", "--arg", f"mode={mode}",
                                    "--arg", f"resource={resource}", "--arg", f"context={json.dumps(headers)}", "--json")
        except subprocess.CalledProcessError as error:
            try:
                detail = json.loads(error.stdout.splitlines()[0])["error"]
            except (IndexError, ValueError, KeyError):
                raise ValueError(f"AgentMaurice workflow CLI exited {error.returncode}") from error
            raise ValueError(detail["message"]) from error
        return json.loads(response.stdout)["execution"]

    def read_packets(self):
        for line in self.bridge.stdout:
            packet = json.loads(line)
            ticket = packet.get("headers", {}).get("x-tba-policy-ticket")
            with self.lock:
                self.waiting.get(ticket, self.packets).put(packet)

    @contextmanager
    def response_queue(self, ticket):
        inbox = Queue()
        with self.lock:
            self.waiting[ticket] = inbox
        try:
            yield inbox
        finally:
            with self.lock:
                self.waiting.pop(ticket)

    def send_decision(self, packet, status, output):
        with self.lock:
            result = {"request_id": packet["request_id"], "status": status, "body": output}
            self.bridge.stdin.write(json.dumps(result) + "\n")
            self.bridge.stdin.flush()

    def authenticate_packet(self, hop, packet, inputs, path, method, anchor):
        assert packet["method"] == method and packet["path"] == path and not packet["body"]
        observed = Headers(packet["headers"])
        hop.last_packet = packet
        hop.forwarded_transaction = "txn-token" in observed
        components = observed.get("signature-input", "").partition(")")[0]
        hop.covers_authority = '"@authority"' in components
        if any(observed.get(name) != value for name, value in inputs.items()):
            raise RuntimeError("AgentMaurice did not forward the policy context")
        settings = dict(audience=packet["url"], trust_by_domain=anchor, now=time(),
                        replay_store=MemoryReplayCheckProvider())
        if hop.mode == "wpt":
            subject = authenticate_wpt_request(observed.items(), **settings).claims["sub"]
        else:
            subject = authenticate_signature(observed.items(), method=method, path=path, **settings)
        assert subject == self.identity
        return observed

    def check_path_rewrite(self, original):
        ticket = original["headers"]["x-tba-policy-ticket"]
        with self.response_queue(ticket) as inbox, ThreadPoolExecutor(max_workers=1) as pool:
            invocation = pool.submit(
                self.lab.run, "/tmp/bin/deno", "run", "--allow-net=127.0.0.1:15001",
                "--allow-read=/tmp/receiver-ca.pem", "/fixture/agentmaurice_outbound_replay.ts",
                input=json.dumps({**original, "rewrite_path": True}),
            )
            try:
                packet = inbox.get(timeout=10)
            except Empty as error:
                raise ValueError("rewritten request did not reach the signature verifier") from error
            try:
                assert packet["method"] == original["method"] and packet["path"] == "/rewritten"
                assert all(packet["headers"][header] == original["headers"][header]
                           for header in ("signature", "signature-input", "workload-identity-token"))
                authenticate_signature(
                    packet["headers"].items(), method=packet["method"], path=packet["path"],
                    audience=original["url"], trust_by_domain=self.trust,
                    now=time(), replay_store=MemoryReplayCheckProvider(),
                )
            except ValueError as error:
                reason = str(error)
            else:
                raise ValueError("the original HTTP signature validated on the rewritten route")
            finally:
                self.send_decision(packet, 401, {"decision": "deny"})
            assert json.loads(invocation.result().stdout) == 401
            return reason

    def sequence(self, hop, headers, preflight, before_commit, authorize, ledger):
        nonce = token_urlsafe(16)
        inputs = {name.lower(): value for name, value in headers.items()}
        inputs["x-tba-policy-ticket"] = nonce
        ports = []
        with self.response_queue(nonce) as inbox, ThreadPoolExecutor(max_workers=1) as pool:
            invocation = pool.submit(self.outbound, hop.mode, "effects", inputs,
                                     workflow="interop-policy-sequence")
            for read, path, method, policy in (
                (True, "/effects", "GET", preflight),
                (False, "/writes", "POST", authorize),
            ):
                while True:
                    try:
                        packet = inbox.get(timeout=0.2)
                        break
                    except Empty:
                        if invocation.done():
                            invocation.result()
                            raise ValueError(f"AgentMaurice sequence ended before {method} {path}")
                status, output = 403, {"decision": "deny", "reason": "policy-fixture-error"}
                try:
                    observed = self.authenticate_packet(hop, packet, inputs, path, method, self.trust)
                    ports.append(packet["peer"]["port"])
                    status, output = self.authorize(hop, policy, observed, ledger, read, None)
                    if read and status == 200:
                        before_commit()
                finally:
                    self.send_decision(packet, status, output)
                if read and status != 200:
                    raise ValueError("AgentMaurice did not pass the sequence preflight")
            completed = invocation.result()
            assert completed["state"] == "completed"
            assert completed["data"] == {"status": status, "outcome": output}
        return {"http_status": status, "response": output}, ports

    def inbound(self, hop, credential, headers, transaction):
        path = self.lab.path.replace("/text-stats/", "/interop-policy/")
        body = json.dumps({"inputs": {"mode": hop.mode, "context": headers}},
                          separators=(",", ":")).encode()
        token, key = credential
        signed_path = self.lab.path if hop.change_signed_path else None
        proof = workflow_headers(hop.mode, path, token, key, body=body, transaction=transaction,
                                 signed_path=signed_path, signed_authority=hop.signed_authority)
        if hop.substitute_transaction is not None:
            proof["txn-token"] = hop.substitute_transaction
        if hop.session is not None:
            hop.session.stdin.write(workflow_request(path, proof, body=body) + "\n")
            hop.session.stdin.flush()
            line = hop.session.stdout.readline()
            if not line:
                raise ValueError("persistent loopback session ended without a workflow response")
            return json.loads(line)
        return self.lab.request(proof, path=path, body=body)

    def transaction(self, hop, *, readback, headers, authorize, ledger):
        resource = "policy" if hop.inbound else "effects" if readback else "writes"
        method = "GET" if resource == "effects" else "POST"
        nonce = token_urlsafe(16)
        inputs = {name.lower(): value for name, value in headers.items()}
        inputs["x-tba-policy-ticket"] = nonce
        transaction = inputs.pop("txn-token", None) if hop.inbound else None
        if transaction is not None:
            # The protected workflow authenticates the real request. Its own
            # callback carries the verified input through an application header.
            inputs["x-tba-policy-transaction"] = hop.substitute_transaction or transaction
        bad_trust = hop.wrong_anchor and not readback
        issuer = ec.generate_private_key(ec.SECP256R1()) if bad_trust else hop.issuer
        credential = baseline_wit(issuer, hop.identity) if hop.inbound else None
        token_digest = "sha256:" + sha256(credential[0].encode()).hexdigest() if credential else None
        with self.response_queue(nonce) as inbox, ThreadPoolExecutor(max_workers=1) as pool:
            invocation = (pool.submit(self.inbound, hop, credential, inputs, transaction)
                          if hop.inbound else pool.submit(self.outbound, hop.mode, resource, inputs))
            while True:
                try:
                    packet = inbox.get(timeout=0.2)
                    break
                except Empty:
                    try:
                        result = invocation.result(timeout=0)
                    except TimeoutError:
                        continue
                    negative = (bad_trust or hop.substitute_transaction or hop.change_signed_path
                                or hop.signed_authority == "original.example.org:5000")
                    if hop.inbound and negative and result["status"] in (400, 401, 403):
                        raw = self.lab.run("tail", "-n", "1", "/tmp/one/logs/wimse-decisions.jsonl").stdout
                        journal = json.loads(raw)
                        assert journal["decision"] == "reject" and journal["direction"] == "inbound"
                        if bad_trust:
                            assert journal["reason"] == "wit-invalid", journal
                        hop.wire_status = result["status"]
                        return {"http_status": 401 if result["status"] == 400 else result["status"],
                                "response": {"decision": "deny", "reason": journal["reason"]}}
                    failure = (result.get("data") or {}).get("error") or result.get("error")
                    raise ValueError(
                        f"AgentMaurice returned HTTP {result['status']} before reaching the policy gate"
                        + (f": {failure}" if failure else "")
                    )
            path = "/" + resource
            status, output = 403, {"decision": "deny", "reason": "policy-fixture-error"}
            try:
                anchor = self.alternate if bad_trust and not hop.inbound else self.trust
                try:
                    observed = self.authenticate_packet(hop, packet, inputs, path, method, anchor)
                except ValueError as error:
                    status, output = 401, {"decision": "deny", "reason": str(error)}
                    if not bad_trust:
                        raise
                else:
                    if transaction is not None:
                        observed["txn-token"] = observed.get("x-tba-policy-transaction")
                    status, output = self.authorize(hop, authorize, observed, ledger, readback, token_digest)
            finally:
                self.send_decision(packet, status, output)
            completed = invocation.result()
            hop.connection_observation = completed.get("connection") if hop.inbound else packet.get("peer")
            data = completed.get("data") or completed.get("output")
            assert completed["state"] == "completed" and data["status"] == status
            assert data["outcome"] == output
            return {"http_status": status, "response": output}

    def authorize(self, hop, authorize, observed, ledger, readback, token_digest):
        if hop.inbound:
            # AgentMaurice records inbound admission before calling the policy gate.
            journal = self.lab.run("tail", "-n", "12", "/tmp/one/logs/wimse-decisions.jsonl")
            acceptance, = (entry for entry in map(json.loads, journal.stdout.splitlines())
                           if entry["direction"] == "inbound" and entry.get("wit_sha256") == token_digest)
            assert acceptance["decision"] == "accept"
            assert acceptance["peer_id"] == hop.identity
        try:
            data = authorize(hop.identity, observed) if authorize else None
        except ValueError as error:
            return 403, {"decision": "deny", "reason": str(error)}
        if not readback:
            ledger.commit(hop.identity)
        status = 200 if readback else 201
        return status, {"decision": "allow", "identity": hop.identity, "writes": list(ledger.snapshot()),
                        **(data or {})}


class AgentMauricePolicyHop:
    context_token_header = "X-Destination-Access-Token"

    def __init__(self, bridge, issuer, mode, inbound, names, *, wrong_anchor=False):
        self.bridge, self.issuer, self.mode, self.inbound = bridge, issuer, mode, inbound
        self.identity = f"wimse://example.org/{names['caller_name']}" if inbound else bridge.identity
        self.server_identity = bridge.identity if inbound else f"wimse://example.org/{names['receiver_name']}"
        self.wrong_anchor = wrong_anchor
        self.substitute_transaction = None
        self.change_signed_path = False
        self.signed_authority = None
        self.covers_authority = False
        self.session = None
        self.connection_observation = None
        self.last_packet = None
        self.wire_status = None
        self.forwarded_transaction = False

    @contextmanager
    def persistent(self):
        if not self.inbound:
            yield
            return
        lab = self.bridge.lab
        args = [*lab.command, "/tmp/bin/deno", "run", "--allow-net=127.0.0.1:5000",
                "/fixture/agentmaurice_session.ts"]
        with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as session:
            self.session = session
            try:
                yield
            finally:
                self.session = None
                session.stdin.close()
                try:
                    session.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    session.kill()

    @contextmanager
    def running(self, *, authorize_write=None, authorize_read=None):
        ledger = WriteLedger()

        def send(host, port, dns, *, readback=False, headers=None):
            assert host == "127.0.0.1" and port == 15001
            return self.bridge.transaction(
                self, readback=readback, headers=headers or {},
                authorize=authorize_read if readback else authorize_write, ledger=ledger,
            )

        yield SimpleNamespace(request=send), SimpleNamespace(server_port=15001, ledger=ledger)

    def observe(self, *, authorize_write=None, headers=None, check_response=None):
        with self.running(authorize_write=authorize_write) as endpoint:
            response = request(endpoint, **(headers or {}))
            if check_response:
                check_response(response)
            body = response["response"]
            return Observation(body["decision"], "enforcing", effects=len(endpoint[1].ledger.snapshot()),
                               reason=body.get("reason", body.get("identity", "")))
