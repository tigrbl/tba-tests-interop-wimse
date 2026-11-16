"""Run the remaining published AgentMaurice application-policy cases."""

from argparse import ArgumentParser
from contextlib import ExitStack
import csv
from dataclasses import asdict, replace
import json
from pathlib import Path
import subprocess
from traceback import extract_tb
from types import SimpleNamespace

from run_agentmaurice_matrix import PROFILES, gzip_json
from run_agentmaurice_typed import PEER, open_adapter, peer_for
from support.agentmaurice_endpoint import BINARY_SHA256
from support.agentmaurice_policy import AgentMauricePolicyHop, PolicyBridge
from support.signature_cases import SignatureHop
from support.typed_service_bindings import TypedServiceBindings
from support.wic_policy import POLICY_INPUTS, WicPolicyFixture
from support.wic_services import StatusAuthority, TokenIssuer
from support.wic_support_cases import WicSupportFixture, assert_ledger, request
from support.wpt_fixture import WptFixture
from tba_tests_interop_wimse.catalog import read_catalog
from tba_tests_interop_wimse.hop_runner import hop_mismatches
from tba_tests_interop_wimse.matrix import expand_scenarios
from tba_tests_interop_wimse.observations import Observation, mismatches
from tba_tests_interop_wimse.resource import WriteLedger

CONFIGURATION = "agentmaurice-v2.2.18-policy-loopback-v1"
CALLS = {"call": "operation-authorized", "boundary-call": "cross-domain-worker-admitted",
         "broker": "broker-authorized-credential-use"}


class BindingMissing(Exception):
    def __init__(self, reason, evidence=None):
        super().__init__(reason)
        self.evidence = evidence


def scenario_map():
    return {case["id"]: case for case in expand_scenarios(
        read_catalog("scenarios.toml"), read_catalog("factors.toml"), read_catalog("exclusions.toml")
    )}


def remaining_rows(args):
    eligible = {"blocked", "failed"} if args.include_failed else {"blocked"}
    with args.inventory.open(encoding="utf-8", newline="") as stream:
        selected = [row for row in csv.DictReader(stream) if row["result"] in eligible]
    assert len(selected) == len({row["execution_id"] for row in selected})
    mapping = dict(pair for shard in gzip_json(args.mapping) for pair in shard)
    manifest = gzip_json(args.manifest)
    plans = {row["id"]: row for group in ("workload_executions", "planned_executions")
             for row in manifest[group]}
    for row in selected:
        identifier = row["execution_id"]
        assert mapping[identifier] == row["runtime_id"]
        yield identifier, plans[row["runtime_id"]]


def bound_hop(stack, adapter, hop, case, names, *, slot=0, wrong=False):
    peer, direction = peer_for(hop)
    if peer == PEER:
        return AgentMauricePolicyHop(adapter.receivers[slot], adapter.issuer, PROFILES[hop["profile"]],
                                     direction == "forward", names, wrong_anchor=wrong)
    fixture = stack.enter_context(adapter.other_peers.hop(case, direction, hop, names))
    if isinstance(fixture, WptFixture):
        return SignatureHop(fixture, operation_variant="wrong-anchor" if wrong else "valid-peer")
    return fixture


def before_effect(support):
    ingress, enforcing = support.ingress, support.enforcing
    status = StatusAuthority()
    delegation = TokenIssuer("status-test-delegator", enforcing.server_identity)
    events = []

    def grant(identity, headers):
        assert identity == ingress.identity
        return {"delegation": delegation.issue(enforcing.identity, "write")}

    def authorize(identity, headers):
        claims = delegation.verify(headers.get("X-Delegation"))
        if (claims["sub"], claims["scope"]) != (identity, "write"):
            raise ValueError("delegation-refused")
        if not status.permitted():
            events.append("revocation-observed")
            raise ValueError("revoked-before-effect")

    def preflight(identity, headers):
        if headers.get("X-Delegation"):
            authorize(identity, headers)
            events.append("initial-allow")

    def before_commit():
        if support.variant == "revocation-before-effect":
            status.publish_revocation()

    def finish(result, server, *, same_transport_session):
        if result["http_status"] == 201:
            events.append("commit")
        else:
            assert result["response"].get("reason") == "revoked-before-effect"
            events.append("commit-refused")
        measurements = status.refusal() if result["http_status"] != 201 else {}
        measurements["same_transport_session"] = int(same_transport_session)
        return support.observation(result, server, events=tuple(events), measurements=measurements)

    with ingress.running(authorize_read=grant) as endpoint:
        initial = request(endpoint, read=True)
        assert initial["http_status"] == 200 and not endpoint[1].ledger.snapshot()
    header = initial["response"]["delegation"]
    if isinstance(ingress, AgentMauricePolicyHop) and not enforcing.inbound:
        ledger = WriteLedger()
        result, ports = enforcing.bridge.sequence(
            enforcing, {"X-Delegation": header}, preflight, before_commit, authorize, ledger,
        )
        same_transport = len(set(ports)) == 1
        # Scenario 12 requires an established mTLS session for profile C.
        # On WIT-only hops both operations instead prove the same identity
        # and carry the same delegation within one workflow execution.
        enforcing_profile = support.case["hops"]["enforcing"]
        if enforcing_profile["wic_issuer"] != "none" and not same_transport:
            raise BindingMissing("v2.2.18 opened distinct connections for the two requests in one workflow", {
                "observed_ports": ports, "events": events, "commit_status": result["http_status"],
                "effects": len(ledger.snapshot()),
            })
        return finish(result, SimpleNamespace(ledger=ledger), same_transport_session=same_transport)
    with (enforcing.running(authorize_write=authorize, authorize_read=preflight) as endpoint,
          enforcing.persistent()):
        initial = request(endpoint, read=True, X_Delegation=header)
        assert initial["http_status"] == 200 and not endpoint[1].ledger.snapshot()
        session = enforcing.connection_observation
        before_commit()
        result = request(endpoint, X_Delegation=header)
        next_session = enforcing.connection_observation
        if not session or not next_session or session["port"] != next_session["port"]:
            raise BindingMissing("v2.2.18 opened a second transport connection during the preflight-to-commit control")
        if enforcing.inbound:
            assert next_session["reused"]
        assert_ledger(endpoint)
        return finish(result, endpoint[1], same_transport_session=True)


def proxy_handoff(endpoint):
    authority = TokenIssuer("proxy-verifier", endpoint.server_identity)
    handoffs = []

    def authenticate_at_proxy(identity, headers):
        handoffs.append(authority.issue(identity, "write"))
        raise ValueError("proxy-verified-write")

    def authorize(identity, headers):
        claims = authority.verify(headers.get("X-Proxy-Verification"))
        if (claims["sub"], claims["scope"]) != (identity, "write"):
            raise ValueError("proxy handoff refused")

    with endpoint.running(authorize_write=authenticate_at_proxy) as proxy:
        first = request(proxy)
        assert first["response"]["reason"] == "proxy-verified-write"
        assert not proxy[1].ledger.snapshot()
    handoff, = handoffs
    return endpoint.observe(authorize_write=authorize, headers={"X-Proxy-Verification": handoff})


def outbound_path_rewrite(endpoint):
    def authenticate_at_proxy(identity, headers):
        raise ValueError("proxy-verified-write")

    verified = endpoint.observe(authorize_write=authenticate_at_proxy)
    assert verified.reason == "proxy-verified-write" and verified.effects == 0
    reason = endpoint.bridge.check_path_rewrite(endpoint.last_packet)
    assert "signature" in reason.lower()
    return Observation("deny", "enforcing", effects=0, reason=reason)


def scenario_fixture(adapter, case, row):
    family, variant = case["scenario_id"], case["variant"]
    maurice_hops = {
        key for key, pair in row["pairs"].items()
        if any(endpoint["implementation"] == PEER for endpoint in pair.values())
    }
    with ExitStack() as stack:
        fixtures = {}
        for index, (key, hop) in enumerate(case["hops"].items()):
            pair = row["pairs"][key]
            hop = {**hop, **{f"{role}_pin": (peer["implementation"], peer.get("version"), peer.get("configuration"))
                             for role, peer in pair.items()}}
            names = {"caller_name": f"workload-{index}", "receiver_name": f"workload-{index + 1}"}
            target = key == case["target_hop"] and variant == "trust-refused"
            local = {**case, "hops": {key: hop}, "target_hop": key, "variant": "valid-peer", "layer": "operation"}
            if target and case["layer"] == "tls":
                local.update(variant="wrong-server-identity", layer="tls")
            fixtures[key] = bound_hop(stack, adapter, hop, local, names,
                                      wrong=target and case["layer"] == "application")
        support = WicSupportFixture(case, fixtures)
        if family == "15":
            endpoint = support.enforcing
            if variant == "signed-path-changed" and endpoint.inbound:
                endpoint.change_signed_path = True
            elif variant == "signed-path-changed":
                return outbound_path_rewrite(endpoint)
            elif variant == "signed-authority-changed" and endpoint.inbound:
                endpoint.signed_authority = "127.0.0.1:5000"
                try:
                    assert endpoint.observe().decision == "allow"
                except ValueError as error:
                    raise BindingMissing("v2.2.18 refused the unmodified @authority signing control") from error
                endpoint.signed_authority = "original.example.org:5000"
            elif variant == "signed-authority-changed":
                assert endpoint.observe().decision == "allow"
                if not endpoint.covers_authority:
                    raise BindingMissing("the observed AgentMaurice HTTP signature did not cover @authority")
                raise BindingMissing("outbound authority rewrite requires a signed forwarding fixture")
            elif variant == "trusted-proxy-verification":
                return proxy_handoff(endpoint)
            elif variant != "unchanged":
                raise BindingMissing("the proxy must prove the rewritten authority or path and authenticate the handoff")
            return endpoint.observe()
        if family == "07":
            endpoint = support.enforcing
            authority = TokenIssuer("tba-transaction", endpoint.server_identity)
            token = authority.issue(endpoint.identity, "write")
            if variant == "token-binding-mismatch":
                if not endpoint.inbound:
                    raise BindingMissing("v2.2.18 reserves Txn-Token in wimseFetch, so no valid outbound proof can be substituted")
                endpoint.substitute_transaction = authority.issue(endpoint.identity, "write", nonce="substitute")

            def verify(identity, headers):
                claims = authority.verify(headers.get("Txn-Token"))
                if (claims["sub"], claims["scope"]) != (identity, "write"):
                    raise ValueError("transaction refused")

            return endpoint.observe(authorize_write=verify, headers={"Txn-Token": token})
        if family in POLICY_INPUTS:
            return WicPolicyFixture(support.enforcing, family, variant).observe()
        if family == "17":
            return support.approval()
        if family == "12" and "enforcing" in maurice_hops:
            return before_effect(support)
        result = support.observe()
        wire_status = getattr(support.enforcing, "wire_status", None)
        return replace(result, measurements={**result.measurements, "agentmaurice_wire_status": wire_status}) \
            if wire_status is not None else result


def typed_policy(adapter, row, *, observe_vendor_prefix=False):
    target, _, test = row["outcome_id"].partition(":")
    hops = row["hops"]
    for index, hop in enumerate(hops):
        if hop["operation"] not in CALLS and hop.get("support") not in TypedServiceBindings.bindings.get(
            hop["operation"], ()
        ):
            vendor_gate = hop["operation"] in {"redthread-check", "omniarx-check"}
            if not (observe_vendor_prefix and vendor_gate and index == len(hops) - 1):
                raise BindingMissing(f"missing live {hop['operation']} binding for {hop.get('support')}")
    service = TypedServiceBindings(hops)
    trace = []
    writes = 0
    slots = {name: i for i, name in enumerate(adapter.participants(hops))}
    for index, hop in enumerate(hops):
        operation = hop["operation"]
        if operation in {"redthread-check", "omniarx-check"}:
            assert trace and writes == 0
            raise BindingMissing(f"missing live {operation} binding for {hop['support']}", {
                "reached_hops": len(trace), "effects": writes, "trace": trace,
            })
        fault = test if str(index + 1) == target else ""
        record = {"hop": index + 1, "operation": operation, "caller": hop["caller"], "receiver": hop["receiver"]}
        trace.append(record)
        if operation not in CALLS:
            evidence = service.support_request(index, fault)
            record.update(evidence)
        elif fault == "peer-identity-refused" and any(
            hop[f"{side}_pin"][0] == PEER for side in ("caller", "receiver")
        ):
            name = hop["caller"] if hop["caller_pin"][0] == PEER else hop["receiver"]
            result, effects, evidence = adapter.maurice_call(hop, slots[name], fault, False)
            record.update(decision="deny" if effects == 0 and result != "operation-authorized" else "allow",
                          result=result, **evidence)
        else:
            names = dict(caller_name=hop["caller"], receiver_name=hop["receiver"])
            wrong = fault == "peer-identity-refused"
            local = {"scenario_id": "01", "hops": {"enforcing": hop}, "target_hop": "enforcing",
                     "variant": "wrong-anchor" if wrong and hop["profile"] == "wic-mtls" else "valid-peer",
                     "layer": "tls" if wrong and hop["profile"] == "wic-mtls" else "operation"}
            write = index == len(hops) - 1
            actor = hop["caller"] if hop["caller_pin"][0] == PEER else hop["receiver"]
            with ExitStack() as stack:
                fixture = bound_hop(stack, adapter, hop, local, names, slot=slots.get(actor, 0), wrong=wrong)
                admission = {"called": False}

                def authorize(identity, headers):
                    assert identity == fixture.identity
                    admission["called"] = True
                    return service.authorize(index, identity, headers, fault, fixture)

                policies = {"authorize_write" if write else "authorize_read": authorize}
                with fixture.running(**policies) as endpoint:
                    reply = request(endpoint, read=not write, **service.headers(index, fault, fixture))
                    changes = len(endpoint[1].ledger.snapshot())
                writes += changes
            body, status = reply["response"], reply["http_status"]
            if body["decision"] == "allow":
                assert admission["called"] and status == (201 if write else 200), reply
                result = CALLS[operation]
            else:
                assert body["decision"] == "deny" and status in (401, 403) and changes == 0, reply
                result = body["reason"] if admission["called"] else "peer-identity-refused"
            record.update(decision=body["decision"], result=result, status=status, reason=body.get("reason", ""))
        if record["decision"] == "deny":
            break
    return {"reached_hops": len(trace), "decision_hop": trace[-1]["hop"], "result": trace[-1]["result"],
            "effects": writes + service.effects, "trace": trace}


def main():
    parser = ArgumentParser(description=__doc__)
    for name in ("inventory", "manifest", "mapping", "issuer", "snapshot", "wimsey", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("wpt", "cofide", "cred", "go-spiffe", "defakto", "emilia"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--container", action="append", required=True)
    parser.add_argument("--family", action="append")
    parser.add_argument("--shards", type=int, default=1)
    parser.add_argument("--shard", type=int, default=0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", type=Path, action="append", default=[])
    parser.add_argument("--include-failed", action="store_true", help="Also rerun IDs with a recorded failure")
    parser.add_argument("--observe-vendor-prefix", action="store_true",
                        help="Record authenticated workload hops up to an unavailable final vendor gate")
    parser.add_argument("--sequence-only", action="store_true")
    args = parser.parse_args()
    args.mintid_container = None
    args.token_refusals_only = False
    scenarios = scenario_map()
    selected = list(remaining_rows(args))
    complete = {
        record["published_id"]
        for journal in args.resume
        for record in map(json.loads, journal.read_text(encoding="utf-8").splitlines())
        if record["result"] == "passed"
    }
    with ExitStack() as stack:
        adapter = open_adapter(args, stack, args.output.parent, bridge_factory=PolicyBridge)
        output = stack.enter_context(args.output.open("x", encoding="utf-8"))
        attempted = 0
        for index, (published, row) in enumerate(selected):
            if index % args.shards != args.shard or published in complete:
                continue
            family = row["scenario_id"].split(":")[0] if "scenario_id" in row else "typed"
            if args.sequence_only and (family != "12" or
                                      row["pairs"]["ingress"]["receiver"]["implementation"] != PEER or
                                      row["pairs"]["enforcing"]["caller"]["implementation"] != PEER):
                continue
            if args.family and family not in args.family:
                continue
            record = dict(published_id=published, runtime_id=row["id"], family=family,
                          binary_sha256=BINARY_SHA256, configuration=CONFIGURATION)
            try:
                if family == "typed":
                    observation = typed_policy(adapter, row, observe_vendor_prefix=args.observe_vendor_prefix)
                    errors = hop_mismatches(row, observation)
                else:
                    case = scenarios[row["scenario_id"]]
                    observed = scenario_fixture(adapter, case, row)
                    errors = mismatches(case, observed)
                    observation = asdict(observed)
                record.update(result="failed" if errors else "passed",
                              observation=observation, reason="; ".join(errors))
            except BindingMissing as error:
                record.update(result="blocked", reason=str(error))
                if error.evidence is not None:
                    record["evidence"] = error.evidence
            except (AssertionError, KeyError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                record.update(result="failed", reason=str(error) or type(error).__name__)
                site = extract_tb(error.__traceback__)[-1]
                record["failure_site"] = f"{Path(site.filename).name}:{site.lineno}:{site.name}"
            output.write(json.dumps(record) + "\n")
            output.flush()
            if record["result"] != "blocked":
                attempted += 1
                if attempted % 20 == 0:
                    print(f"Attempted {attempted} policy cases", flush=True)
            if args.limit and attempted >= args.limit:
                break


if __name__ == "__main__":
    main()
