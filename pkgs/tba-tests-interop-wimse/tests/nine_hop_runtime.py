"""Dispatch the pinned operations owned by each nine-hop peer binding."""
from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from importlib import import_module
from threading import Lock
from urllib.parse import urlsplit


PEERS = ("tba", "cred", "cofide", "agentmaurice")
PRIMITIVES = (
    "issue_wit", "issue_txn_token", "issue_chain_grant", "issue_access_token",
    "verify_jwt", "verify_wimse_proof", "http_sig", "wpt_request",
)
REQUIRED = {
    "driver": {"http_sig"},
    "issuer-a": {"issue_txn_token"},
    "ingress": {"verify_wimse_proof"},
    "exchange-a": {"verify_wimse_proof", "verify_jwt", "issue_chain_grant"},
    "exchange-b": {"verify_jwt", "issue_access_token"},
    "coordinator": {"verify_wimse_proof", "http_sig"},
    "issuer-b": {"verify_jwt", "issue_txn_token"},
    "research": {"verify_wimse_proof", "wpt_request"},
    "file-tool": {"verify_wimse_proof"},
}


@dataclass(frozen=True)
class PeerBinding:
    operations: dict
    # Exact matrix pin (implementation, revision, configuration).
    pin: tuple


def load_bindings(context):
    bindings = {}
    for peer in PEERS:
        name = f"support.nine_hop_{peer}"
        try:
            module = import_module(name)
        except ModuleNotFoundError as error:
            if error.name == name:
                continue
            raise
        factory = getattr(module, "build_bindings", None)
        if factory is None:
            continue
        for role, binding in factory(context).items():
            if role not in REQUIRED or binding.pin[0] != peer:
                raise ValueError(f"{peer} registered an invalid nine-hop role: {role}")
            if not REQUIRED[role].issubset(binding.operations):
                raise ValueError(f"{peer} {role} has incomplete binding operations")
            bindings[(role, binding.pin)] = binding
    return bindings


class Runtime:
    def __init__(self, bindings, wimse):
        self.bindings = bindings
        self.wimse = wimse
        self.active_role = ContextVar("nine_hop_role", default=None)
        self.assignment = {}
        self.execution_id = None
        self.observed = Counter()
        self.lock = Lock()

    def binding(self, role):
        return self.bindings.get((role, self.assignment.get(role)))

    @contextmanager
    def role(self, role):
        token = self.active_role.set(role)
        try:
            yield
        finally:
            self.active_role.reset(token)

    def count(self, role, operation):
        with self.lock:
            self.observed[(role, operation)] += 1

    def wrap_handler(self, base, select_role):
        runtime = self

        class Handler(base):
            def do_POST(self):
                with runtime.role(select_role(urlsplit(self.path).path)):
                    return super().do_POST()

        return Handler

    def patch_primitives(self):
        # Constructors and verifiers receive the same bytes the reference
        # receives. An installed peer operation owns its return value.
        for name in PRIMITIVES:
            setattr(self.wimse, name, self.wrap_primitive(name, getattr(self.wimse, name)))
        send = self.wimse.send

        def send_case(request, case=None, timeout=15):
            return send(request, case=self.execution_id, timeout=timeout)

        self.wimse.send = send_case

    def wrap_primitive(self, name, original):
        def invoke(*args, **kwargs):
            role = self.active_role.get()
            binding = self.binding(role)
            operation = binding.operations.get(name) if binding else None
            if operation is None:
                return original(*args, **kwargs)
            result = operation(*args, **kwargs)
            self.count(role, name)
            return result
        return invoke
