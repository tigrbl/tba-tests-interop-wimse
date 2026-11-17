"""Use the pinned RICH wire implementation in the generic resource fixture."""
from contextlib import contextmanager
from functools import lru_cache
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import time

from tba_concrete_jwt import decode_jwt_unverified
from tba_tests_interop_wimse.httpsig import SignatureCaller, SignatureReceiver
from tba_tests_interop_wimse.qualification import pair_has_baseline
from tba_tests_interop_wimse.rich_expansion import RICH, rich_capabilities
from tba_tests_interop_wimse.signatures import ATTRIBUTE, PARAMS
from tba_tests_interop_wimse.wpt import WptCaller, audience

from support.typed_workload_chain import TypedWorkloadChain, native_workload_hop
from support.wimsey_signature_endpoint import WimseySignatureAdapter
from support.wimsey_wpt import CONTEXT_HEADER, token_hash, wpt_endpoints
from support.wpt_fixture import WptFixture


REVISION = "49d29ca31d248af4a169176969e712c673f11ef9"
ENDPOINT = {"caller": "caller_pin", "receiver": "receiver_pin"}
PIN_FIELDS = ("implementation", "version", "configuration")
NONCE = re.compile(r';nonce="([A-Za-z0-9_+/=-]{11,128})"')


@lru_cache(maxsize=1)
def rich_source():
    root = Path(os.environ["TBA_WIMSE_RICH_CHECKOUT"]).resolve()
    command = ["git", "-C", str(root)]
    if subprocess.check_output([*command, "rev-parse", "HEAD"], text=True).strip() != REVISION:
        raise ValueError("RICH checkout does not match the published revision")
    if subprocess.check_output([*command, "status", "--porcelain", "--untracked-files=no"], text=True):
        raise ValueError("RICH checkout has modified tracked files")
    name = "pinned_rich_wimse"
    spec = importlib.util.spec_from_file_location(name, root / "peers/wimse.py")
    source = importlib.util.module_from_spec(spec)
    sys.modules[name] = source
    spec.loader.exec_module(source)
    return source


def pin(endpoint):
    return tuple(endpoint.get(key) for key in PIN_FIELDS)


def is_rich(hop):
    return any(hop.get(field, (None,))[0] == RICH for field in ENDPOINT.values())


class RichSignatureCaller(SignatureCaller):
    def present(self, dns_name, port, *, readback=False, extra_headers=None, signed_path=None, signed_authority=None):
        if signed_authority is not None:
            raise ValueError("RICH HTTP signatures do not cover @authority")
        path = "/effects" if readback else "/writes"
        request = rich_source().http_sig(
            "GET" if readback else "POST", audience(dns_name, port, signed_path or path), b"",
            self.wit, self.signer, aud=audience(dns_name, port, path), headers=extra_headers,
        )
        return {name.lower(): value for name, value in request.headers.items()}


class RichSignatureReceiver(SignatureReceiver):
    def authenticate_proof(self, request, path):
        headers = request.headers
        if any(len(headers.get_all(name, ())) != 1
               for name in ("workload-identity-token", "signature-input", "signature")):
            raise ValueError("expected a single WIT and HTTP signature")
        if headers.get("Transfer-Encoding") or headers.get("Content-Length", "0") != "0":
            raise ValueError("signature fixture accepts bodyless requests only")
        signature = headers["signature-input"]
        nonce = NONCE.search(signature)
        parsed = PARAMS.fullmatch(signature)
        covered = signature.split(")", 1)[0]
        for bound in ("Authorization", "Txn-Token"):
            if len(headers.get_all(bound, ())) > 1 or headers.get(bound) and f'"{bound.lower()}"' not in covered:
                raise ValueError("signature does not bind the authorization header")
        if nonce is None or parsed is None:
            raise ValueError("invalid signature parameters")
        trusted = {domain: {"keys": keys} for domain, keys in self.trust_by_domain.items()}
        now = time()
        attributes = dict(ATTRIBUTE.findall(parsed["attributes"]))
        try:
            created, expires = (int(attributes[name]) for name in ("created", "expires"))
        except (KeyError, ValueError) as error:
            raise ValueError("invalid signature timestamps") from error
        if not (created <= int(now) < expires and 0 < expires - created <= 300):
            raise ValueError("signature is outside its validity window")
        ok, _, reason, verified = rich_source().verify_wimse_proof(
            request.command, path, dict(headers.items()), b"", trusted,
            expected_aud=audience(self.dns_name, self.server_port, path), now=int(now),
        )
        if not ok:
            raise ValueError(f"RICH HTTP signature rejected: {reason}")
        identity = verified["peer_id"]
        if not self.replay_store.check_and_store(f"rich-httpsig:{identity}:{nonce[1]}", now=int(now), ttl_s=expires-int(now)):
            raise ValueError("RICH HTTP signature replay rejected")
        return identity


class RichWptCaller(WptCaller):
    def present(self, dns_name, port, *, readback=False, extra_headers=None):
        path = "/effects" if readback else "/writes"
        target = audience(dns_name, port, path)
        headers = {name.lower(): value for name, value in (extra_headers or {}).items()}
        if {"authorization", "workload-identity-token"} & headers.keys():
            raise ValueError("WPT proof headers are reserved")
        context = headers.get(CONTEXT_HEADER)
        request = rich_source().wpt_request(
            "GET" if readback else "POST", target, b"", self.wit, self.signer,
            alg=decode_jwt_unverified(self.wit).claims["cnf"]["jwk"]["alg"], aud=target,
            headers=headers, txn_token=headers.get("txn-token"),
            claims_extra={"oth": {CONTEXT_HEADER: token_hash(context)}} if context is not None else None,
        )
        return request.headers


def rich_fixture(directory, case, hop, names):
    caller, receiver = (hop[field] for field in ENDPOINT.values())
    # The proof identifies the actual invoking workload. The application observes
    # the corresponding fixture identity and records its effects independently.
    identity = f"wimse://example.org/{names.get('caller_name', 'workload')}"
    if hop["profile"] == "wit-wpt":
        if caller[0] != RICH or caller[2] != "research" or receiver[0] != "tba":
            raise ValueError("unsupported RICH WPT direction")
        _, proof_receiver = wpt_endpoints(None, None, None, spire=False)
        options = {"proof_caller": RichWptCaller, "proof_receiver": proof_receiver}
    else:
        options = {
            "signature_caller": RichSignatureCaller if caller[0] == RICH else SignatureCaller,
            "signature_receiver": RichSignatureReceiver if receiver[0] == RICH else SignatureReceiver,
        }
    fixture = WptFixture(directory, case, identity=identity, **options)
    fixture.server_identity = f"wimse://example.org/{names.get('receiver_name', 'resource')}"
    return fixture


def qualify_rich(peers, directory):
    rich_source()
    caps = rich_capabilities(peers["implementations"][RICH])
    baselines = []
    for cap in caps:
        role, profile = cap["role"], cap["profile"]
        other = "receiver" if role == "caller" else "caller"
        tba = next(c for c in peers["capabilities"] if c["implementation"] == "tba"
                   and c["role"] == other and c["profile"] == profile and c["identifier_scheme"] == "none"
                   and c["status"] == "qualified")
        pair = {role: {**cap, "status": "qualified"}, other: tba}
        hop = {"profile": profile, "identifier_scheme": "none", "wic_issuer": "none",
               "wit_issuer": "baseline", **{field: pin(pair[side]) for side, field in ENDPOINT.items()}}
        case = {"scenario_id": "01", "variant": "valid-peer", "layer": "operation",
                "hops": {"enforcing": hop}, "target_hop": "enforcing"}
        with TemporaryDirectory(dir=directory) as work:
            observed = rich_fixture(Path(work), case, hop, {}).observe()
        if (observed.decision, observed.effects) != ("allow", 1):
            raise ValueError(f"RICH baseline failed for {role} {cap['configuration']} {profile}: {observed}")
        baselines.append({
            **pair, "outcome": "pass", "evidence": "rich-generic-qualification.json",
            "observation": {"decision": observed.decision, "effects": observed.effects},
        })
    return baselines


class RichWorkloadLab(WimseySignatureAdapter):
    def __init__(self, directory, fallback, peers):
        self.directory, self.fallback, self.peers = directory, fallback, peers
        self.families = super().families | fallback.families

    def supports(self, case):
        return case["scenario_id"] in self.families

    def supports_execution(self, case, execution):
        if case["variant"] == "signed-authority-changed" and any(
            pair["caller"]["implementation"] == RICH for pair in execution["pairs"].values()
        ):
            return False
        return all(pair_has_baseline(self.peers, pair) for pair in execution["pairs"].values())

    def setup_key(self, case, execution):
        return (super().setup_key(case, execution),
                tuple(pin(endpoint) for pair in execution["pairs"].values() for endpoint in pair.values()))

    def hops(self, case, execution):
        hops = {name: {**hop, **{field: pin(execution["pairs"][name][side])
                                  for side, field in ENDPOINT.items()}}
                for name, hop in case["hops"].items()}
        return super().hops({**case, "hops": hops}, execution)

    @contextmanager
    def hop(self, case, direction, hop, names):
        if is_rich(hop):
            with TemporaryDirectory(dir=self.directory) as work:
                yield rich_fixture(Path(work), case, hop, names)
        elif hop["caller_pin"][0] == hop["receiver_pin"][0] == "tba":
            with native_workload_hop(self.directory, case, hop, names) as fixture:
                yield fixture
        else:
            direction = "forward" if hop["caller_pin"][0] == "tba" else "reverse"
            with self.fallback.hop(case, direction, hop, names) as fixture:
                yield fixture


class RichTypedChain(TypedWorkloadChain):
    @lru_cache(maxsize=None)
    def qualified(self, caller_pin, receiver_pin, profile, scheme, wic_issuer, wit_issuer):
        if RICH in (caller_pin[0], receiver_pin[0]):
            return (scheme, wic_issuer, wit_issuer) == ("none", "none", "baseline") and any(
                all(pin(row[role]) == endpoint and row[role]["profile"] == profile
                    for role, endpoint in (("caller", caller_pin), ("receiver", receiver_pin)))
                for row in self.peers["rich_generic_qualification"]
            )
        return super().qualified(caller_pin, receiver_pin, profile, scheme, wic_issuer, wit_issuer)
