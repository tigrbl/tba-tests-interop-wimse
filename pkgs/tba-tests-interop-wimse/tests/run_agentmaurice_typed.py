"""Execute frozen typed rows using the AgentMaurice workflow and pinned peer fixtures."""

import argparse
from contextlib import ExitStack
import csv
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from external_workload_selection import defakto_digest
from mintid_endpoint import MintIDBindings, driver_fingerprint
from run_agentmaurice_matrix import Lab, LiveTbAReceiver, PROFILES, gzip_json
from support.agentmaurice_endpoint import BINARY_SHA256, baseline_wit, workflow_headers
from support.cred_endpoint import bridge_digest
from support.emilia_endpoint import EmiliaBindings, bridge_digest as emilia_digest
from support.go_spiffe_endpoint import SpiffePeerAdapter
from support.signature_cases import SignatureHop
from support.spire_issuer import spire_wit_issuers
from support.typed_service_bindings import TypedServiceBindings
from support.typed_service_flow import StatusFlowServices
from support.wic_support_cases import request
from support.wimsey_signature_endpoint import PEER_SLOTS, WimseySignatureAdapter
from support.wpt_fixture import WptFixture
from tba_tests_interop_wimse.hop_runner import hop_mismatches
from tba_tests_interop_wimse.resource import WriteLedger

PEER = "agentmaurice"
CONFIGURATION = "agentmaurice-v2.2.18-typed-loopback-v1"
TOKEN_OPERATIONS = {
    "delegate": "delegation-widens-parent-scope",
    "redeem-delegation": "grant-not-bound-to-delegate",
    "source-exchange": "source-transaction-token-refused",
    "destination-exchange": "authorization-grant-refused",
}


def token_refusal_prefix(row):
    target, _, fault = row["outcome_id"].partition(":")
    if fault not in TOKEN_OPERATIONS.values() or not target.isdecimal():
        return False
    index = int(target)
    if not 0 < index <= len(row["hops"]):
        return False
    prefix = row["hops"][:index]
    return (
        TOKEN_OPERATIONS.get(prefix[-1]["operation"]) == fault
        and row["reached_hops"] == row["decision_hop"] == index
        and row["expected_effects"] == 0
        and all(hop["operation"] in TOKEN_OPERATIONS
                and hop.get("support") in TypedServiceBindings.bindings[hop["operation"]]
                for hop in prefix)
    )


def redthread_refusal_prefix(row):
    if row is None:
        return False
    hops = row["hops"]
    target, _, fault = row["outcome_id"].partition(":")
    return (
        len(hops) in {2, 3}
        and hops[-1]["operation"] == "redthread-check"
        and hops[-1].get("support") == "redthread"
        and all(hop["operation"] == "call" for hop in hops[:-1])
        and target.isdecimal()
        and 0 < int(target) < len(hops)
        and row["decision_hop"] == row["reached_hops"] == int(target)
        and row["expected_result"] == fault
        and fault in {"peer-identity-refused", "operation-scope-refused"}
        and row["expected_effects"] == 0
    )


def frozen_rows(args):
    completed = {json.loads(line)["published_id"] for line in args.baseline.read_text().splitlines()}
    mappings = dict(pair for shard in gzip_json(args.mapping) for pair in shard)
    manifest = gzip_json(args.manifest)
    typed = {row["id"]: row for row in manifest["planned_executions"]}
    workload = {row["id"]: row for row in manifest["workload_executions"]}
    with args.inventory.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            key = row["execution_id"]
            if (not args.redthread_refusals_only and row["agentmaurice_wit_issuers"] != "baseline") or key in completed:
                continue
            runtime = mappings[key]
            assert (runtime in typed) != (runtime in workload), runtime
            if args.redthread_refusals_only and not redthread_refusal_prefix(typed.get(runtime)):
                continue
            yield key, runtime, typed.get(runtime)


def peer_for(hop):
    caller, receiver = (hop[role + "_pin"][0] for role in ("caller", "receiver"))
    if caller == "tba":
        return receiver, "forward"
    if receiver != "tba":
        raise ValueError(f"Unbound workload endpoint pair {caller}, {receiver}")
    return caller, "reverse"


class TypedAgentMaurice:
    def __init__(self, labs, receivers, issuer, other_peers, emilia, mintid):
        self.labs = labs
        self.receivers = receivers
        self.issuer = issuer
        self.other_peers = other_peers
        self.emilia = emilia
        self.mintid = mintid

    def participants(self, hops):
        return sorted({hop[role] for hop in hops if hop["operation"] == "call"
                       for role in ("caller", "receiver") if hop[role + "_pin"][0] == PEER})

    def blocker(self, row):
        hops = row["hops"]
        if redthread_refusal_prefix(row):
            hops = hops[:row["decision_hop"]]
        if len(self.participants(hops)) > len(self.labs):
            return "additional AgentMaurice deployment required"
        target, _, fault = row["outcome_id"].partition(":")
        refused_prefix = (fault in {"peer-identity-refused", "operation-scope-refused"}
                          and row["decision_hop"] == row["reached_hops"] == int(target)
                          and row["expected_effects"] == 0)
        token_prefix = token_refusal_prefix(row)
        for index, hop in enumerate(hops, 1):
            operation = hop["operation"]
            if operation == "check" and hop.get("support") in StatusFlowServices.bindings["check"]:
                continue
            if operation == "emilia-check" and self.emilia and hop.get("support") == "emilia":
                continue
            if operation == "mintid-check" and self.mintid and hop.get("support") == "mintid":
                continue
            if token_prefix and operation in TOKEN_OPERATIONS:
                continue
            if (refused_prefix and index > row["decision_hop"] and index == len(hops)
                    and operation in {"mintid-check", "emilia-check", "redthread-check", "omniarx-check"}):
                continue
            if operation != "call":
                return f"typed {operation} binding for {hop.get('support', hop['receiver'])} required"
            peer, _ = peer_for(hop)
            profile = hop["profile"]
            if peer == PEER:
                if hop["wit_issuer"] == "spire-wit-svid" and redthread_refusal_prefix(row):
                    if hop["receiver_pin"][0] == PEER:
                        return f"hop {index}: AgentMaurice cannot authenticate and authorize the SPIFFE WIT-SVID subject"
                    return f"hop {index}: AgentMaurice has no verified outbound SPIRE WIT-SVID and proof-key binding"
                if profile not in PROFILES or hop["wit_issuer"] != "baseline":
                    return "unqualified AgentMaurice credential or proof profile"
            elif peer in self.other_peers.commands:
                if profile != "wic-mtls":
                    return f"unqualified {peer} application proof profile"
            elif PEER_SLOTS.get(profile) != peer:
                return f"missing pinned {peer} endpoint for {profile}"
            elif peer == "cred" and not self.other_peers.fallback.cred_bridge:
                return "pinned Cred bridge required"
            elif peer == "cofide" and not self.other_peers.fallback.cofide_bridge:
                return "pinned Cofide bridge required"
            elif peer == "combined-wpt-candidate" and not self.other_peers.fallback.wpt_bridge:
                return "pinned wimsey WPT bridge required"
        return ""

    def maurice_call(self, hop, slot, fault, commit):
        if hop["wit_issuer"] != "baseline":
            raise ValueError("AgentMaurice call has no binding for the selected WIT issuer")
        lab = self.labs[slot]
        mode = PROFILES[hop["profile"]]
        if hop["caller_pin"][0] == PEER:
            variant = {
                "peer-identity-refused": "wrong-anchor",
                "operation-scope-refused": "scope-refused",
                "": "valid-peer",
            }[fault]
            reply = self.receivers[slot].observe(mode, variant, commit=commit)
            status, = reply["statuses"]
            mapping = {200: "operation-authorized", 201: "operation-authorized",
                       401: "peer-identity-refused", 403: "operation-scope-refused"}
            return mapping[status], reply["effects"], {"http_status": status, **reply}
        path = lab.path
        if fault == "operation-scope-refused":
            path = path.replace("/text-stats/", "/interop-ungranted/")
        issuer = ec.generate_private_key(ec.SECP256R1()) if fault == "peer-identity-refused" else self.issuer
        subject = "wimse://example.org/" + hop["caller"]
        token, key = baseline_wit(issuer, subject)
        reply = lab.request(workflow_headers(mode, path, token, key), path=path)
        journal = json.loads(lab.run("tail", "-n", "1", "/tmp/one/logs/wimse-decisions.jsonl").stdout)
        reason = journal["reason"]
        status = reply["status"]
        if (status, journal["decision"], reason) == (200, "accept", ""):
            assert reply.get("state") == "completed" and reply.get("execution_id")
            assert journal["peer_id"] == subject
            result = "operation-authorized"
        elif status == 403 and reason == "not-authorized" and journal.get("peer_id") == subject:
            result = "operation-scope-refused"
        elif status in {400, 401} and reason == "wit-invalid":
            result = "peer-identity-refused"
        else:
            raise ValueError(f"Unexpected workflow decision {reply!r} {journal!r}")
        if result != "operation-authorized" and reply.get("state") == "completed":
            raise ValueError(f"Refused AgentMaurice request completed a workflow: {reply!r}")
        effects = int(commit and result == "operation-authorized")
        return result, effects, {"http_status": status, "workflow_execution": reply.get("execution_id"),
                                 "workflow_state": reply.get("state"), "journal": journal}

    def other_call(self, hop, fault, commit):
        peer, direction = peer_for(hop)
        wrong = fault == "peer-identity-refused"
        transport_fault = hop["profile"] == "wic-mtls" and wrong
        case = {"scenario_id": "01", "hops": {"enforcing": hop}, "target_hop": "enforcing",
                "variant": "wrong-anchor" if transport_fault else "valid-peer",
                "layer": "tls" if transport_fault else "operation"}
        names = {"caller_name": hop["caller"], "receiver_name": hop["receiver"]}

        def authorize(identity, headers):
            assert identity == fixture.identity
            if fault == "operation-scope-refused":
                raise ValueError("operation-scope-refused")

        with self.other_peers.hop(case, direction, hop, names) as fixture:
            if isinstance(fixture, WptFixture):
                variant = "wrong-anchor" if wrong else "valid-peer"
                fixture = SignatureHop(fixture, operation_variant=variant, read_variant=variant)
            policies = {"authorize_write" if commit else "authorize_read": authorize}
            with fixture.running(**policies) as endpoint:
                reply = request(endpoint, read=not commit)
                effects = len(endpoint[1].ledger.snapshot())
        body, status = reply["response"], reply["http_status"]
        if body["decision"] == "allow":
            assert status == (201 if commit else 200)
            result = "operation-authorized"
        elif body.get("reason") == "operation-scope-refused":
            assert status in (401, 403) and effects == 0, reply
            result = body["reason"]
        else:
            assert status in (401, 403) and effects == 0, reply
            result = "peer-identity-refused"
        return result, effects, {"http_status": status, "identity": body.get("identity"),
                                 "peer": peer, "reason": body.get("reason", "")}

    def observe(self, row):
        hops = row["hops"]
        slots = {name: index for index, name in enumerate(self.participants(hops))}
        target, _, fault = row["outcome_id"].partition(":")
        services = {"check": StatusFlowServices(hops)}
        if self.emilia:
            services["emilia-check"] = EmiliaBindings(hops, lambda: self.emilia)
        if self.mintid:
            services["mintid-check"] = MintIDBindings(hops, lambda: self.mintid)
        token_policy = TypedServiceBindings(hops) if token_refusal_prefix(row) else None
        trace = []
        effects = 0
        for index, hop in enumerate(hops):
            test_fault = fault if str(index + 1) == target else ""
            commit = index == len(hops) - 1
            if hop["operation"] in TOKEN_OPERATIONS and token_policy is not None:
                evidence = token_policy.support_request(index, test_fault)
                result, allowed = evidence["result"], evidence["decision"] == "allow"
            elif hop["operation"] in services:
                evidence = services[hop["operation"]].support_request(index, test_fault)
                result, allowed = evidence["result"], evidence["decision"] == "allow"
                if commit and allowed:
                    if "gate_observation" in evidence:
                        effects += evidence["gate_observation"]["effects"]
                    else:
                        ledger = WriteLedger()
                        ledger.commit(hop["caller"])
                        effects += len(ledger.snapshot())
            elif hop["operation"] == "call":
                maurice_role = next((role for role in ("caller", "receiver")
                                     if hop[role + "_pin"][0] == PEER), None)
                if maurice_role:
                    observed = self.maurice_call(hop, slots[hop[maurice_role]], test_fault, commit)
                else:
                    observed = self.other_call(hop, test_fault, commit)
                result, written, evidence = observed
                allowed = result == "operation-authorized"
                effects += written
            else:
                raise ValueError(f"Unexpected arrival at unbound {hop['operation']}")
            trace.append({"hop": index + 1, "caller": hop["caller"], "receiver": hop["receiver"],
                          "operation": hop["operation"], "result": result, **evidence})
            if not allowed:
                break
        return {"reached_hops": len(trace), "decision_hop": trace[-1]["hop"],
                "result": result, "effects": effects, "trace": trace}


def checked(path, digest, hasher=lambda path: sha256(path.read_bytes()).hexdigest()):
    if path is not None and hasher(path) != digest:
        raise ValueError(f"Runtime digest mismatch for {path}")
    return path


def open_adapter(args, stack, directory, *, bridge_factory=LiveTbAReceiver):
    snap = json.loads(args.snapshot.read_text(encoding="utf-8"))
    wimsey = checked(args.wimsey, snap["wimsey_binary_sha256"])
    wpt = checked(args.wpt, snap["wimsey_wpt_bridge_sha256"])
    cofide = checked(args.cofide, snap["cofide_bridge_sha256"])
    cred = checked(args.cred, snap["cred_bridge_sha256"], bridge_digest)
    emilia = checked(args.emilia, snap["emilia_qualification"]["bridge_sha256"], emilia_digest)
    issuer = stack.enter_context(spire_wit_issuers(directory))
    peers = WimseySignatureAdapter(directory, wimsey, issuer, wpt_bridge=wpt, cofide_bridge=cofide,
                                   cred_bridge=cred, wimse_signatures=True, wimse_wpt=True)
    commands = {}
    if args.go_spiffe:
        binary = checked(args.go_spiffe, snap["go_spiffe_qualification"]["binary_sha256"])
        commands["go-spiffe"] = [str(binary), "verify"]
    if args.defakto:
        bridge = checked(args.defakto, snap["defakto_qualification"]["bridge_sha256"], defakto_digest)
        commands["defakto"] = ["node", str(bridge)]
    others = SpiffePeerAdapter(peers, commands, snap["peers"])
    labs = [Lab(container) for container in args.container]
    receivers = [] if args.token_refusals_only else [
        stack.enter_context(bridge_factory(lab)) for lab in labs
    ]
    key = load_pem_private_key(args.issuer.read_bytes(), None)
    if args.mintid_container:
        print(json.dumps({"mintid": driver_fingerprint(args.mintid_container)}), flush=True)
    return TypedAgentMaurice(labs, receivers, key, others, emilia, args.mintid_container)


def open_redthread_prefix_adapter(args, stack):
    labs = [Lab(container) for container in args.container]
    receivers = [stack.enter_context(LiveTbAReceiver(lab)) for lab in labs]
    key = load_pem_private_key(args.issuer.read_bytes(), None)
    return TypedAgentMaurice(labs, receivers, key, None, None, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "manifest", "mapping", "issuer", "baseline", "snapshot", "wimsey", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("wpt", "cofide", "cred", "go-spiffe", "defakto", "emilia"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--container", action="append", required=True)
    parser.add_argument("--resume", type=Path, action="append", default=[])
    parser.add_argument("--select-published", type=Path, help="JSON list of published IDs to execute")
    parser.add_argument("--shards", type=int, default=1)
    parser.add_argument("--shard", type=int, default=0)
    parser.add_argument("--stop-file", type=Path)
    parser.add_argument("--token-refusals-only", action="store_true")
    parser.add_argument("--redthread-refusals-only", action="store_true",
                        help="Run pre-Redthread refusals and report missing bindings on reached hops")
    parser.add_argument("--mintid-container")
    parser.add_argument("--mintid-only", action="store_true")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if not 0 <= args.shard < args.shards:
        parser.error("--shard must select one of --shards")
    selected = list(frozen_rows(args))
    assert len(selected) == len({row[0] for row in selected})
    if args.select_published:
        requested = set(json.loads(args.select_published.read_text(encoding="utf-8")))
        if not requested <= {row[0] for row in selected}:
            raise ValueError("Selection contains IDs outside the remaining ordinary-WIT inventory")
        selected = [row for row in selected if row[0] in requested]
    already_passed = {
        row["published_id"] for journal in args.resume
        for row in map(json.loads, journal.read_text(encoding="utf-8").splitlines())
        if row["result"] == "passed"
    }
    attempted = 0
    with ExitStack() as stack:
        if args.redthread_refusals_only and all(
            hop["caller_pin"][0] == PEER or hop["receiver_pin"][0] == PEER
            for _, _, row in selected for hop in row["hops"][:-1]
        ):
            adapter = open_redthread_prefix_adapter(args, stack)
        else:
            adapter = open_adapter(args, stack, args.output.parent)
        output = stack.enter_context(args.output.open("x", encoding="utf-8"))
        for index, (published, runtime, row) in enumerate(selected):
            if args.stop_file and args.stop_file.exists():
                break
            multi_agent = row and len(adapter.participants(row["hops"])) > 1
            if (0 if multi_agent else index % args.shards) != args.shard:
                continue
            if published in already_passed:
                continue
            if args.token_refusals_only and (row is None or not token_refusal_prefix(row)):
                continue
            if args.mintid_only and (row is None or row["hops"][-1]["operation"] != "mintid-check"):
                continue
            record = {"published_id": published, "runtime_id": runtime, "binary_sha256": BINARY_SHA256,
                      "configuration": CONFIGURATION}
            try:
                reason = adapter.blocker(row) if row else "workload scenario binding required"
                if reason:
                    record.update(result="blocked", reason=reason)
                else:
                    attempted += 1
                    observation = adapter.observe(row)
                    mismatches = hop_mismatches(row, observation)
                    record.update(result="failed" if mismatches else "passed", observation=observation,
                                  reason="; ".join(mismatches))
            except (AssertionError, ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
                record.update(result="failed", reason=str(error) or type(error).__name__)
            output.write(json.dumps(record) + "\n")
            output.flush()
            if attempted and attempted % 50 == 0 and record["result"] != "blocked":
                print(f"Attempted {attempted} typed rows", flush=True)
            if args.limit is not None and attempted >= args.limit:
                break


if __name__ == "__main__":
    main()
