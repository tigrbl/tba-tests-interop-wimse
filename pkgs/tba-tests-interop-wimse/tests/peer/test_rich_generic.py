"""Execute one hosted shard of generic RICH workload and typed-hop cases."""
from hashlib import sha256
import json
import os
from pathlib import Path

import pytest

from tba_tests_interop_wimse.hop_runner import run_hop_execution
from tba_tests_interop_wimse.matrix import support_is_qualified
from tba_tests_interop_wimse.qualification import pair_has_baseline
from tba_tests_interop_wimse.rich_expansion import RICH
from tba_tests_interop_wimse.runner import run_inventory

from ci_full_matrix import read_inventory
from support.rich_generic import ENDPOINT, is_rich, pin


pytestmark = pytest.mark.skipif(not os.getenv("TBA_WIMSE_RICH_SELECTION"), reason="requires hosted RICH shard selection")


def current_endpoint(peers, endpoint, role):
    wanted = pin(endpoint)
    for cap in peers["capabilities"]:
        if cap["role"] != role or cap["profile"] != endpoint["profile"] or (
            cap["identifier_scheme"] != endpoint["identifier_scheme"]
        ) or cap["status"] != "qualified" or cap["implementation"] != wanted[0]:
            continue
        actual = pin(cap)
        if actual == wanted or (wanted[0] == "tba" and actual[2] == wanted[2]) or (
            wanted[0] in {"go-spiffe", "defakto"} and wanted[1] is None
        ):
            return cap
    return {**endpoint, "status": "pending"}


def workload_execution(row, case, lab):
    peers = lab.peers
    pairs = {name: {role: current_endpoint(peers, endpoint, role) for role, endpoint in pair.items()}
             for name, pair in row["pairs"].items()}
    pending = [f"{name}:{role}:{endpoint['implementation']}"
               for name, pair in pairs.items() for role, endpoint in pair.items() if endpoint["status"] != "qualified"]
    missing = [name for name, pair in pairs.items() if not pair_has_baseline(peers, pair)]
    roles = list(case["support_roles"])
    for name, hop in case["hops"].items():
        rich_pair = any(endpoint["implementation"] == RICH for endpoint in pairs[name].values())
        for kind in ("wic_issuer", "wit_issuer"):
            issuer = hop[kind]
            if issuer != "none" and not (rich_pair and kind == "wit_issuer" and issuer == "baseline"
                                         and name not in missing):
                roles.append(f"{name}:{kind}:{issuer}")
    support = [role for role in roles if not support_is_qualified(peers, role, pairs, case)]
    return {**row, "pairs": pairs, "status": "pending" if pending or missing or support else "qualified",
            "pending_endpoints": pending, "missing_baselines": missing, "pending_roles": support}


def typed_execution(row, peers):
    hops = []
    for hop in row["hops"]:
        hop = dict(hop)
        if "profile" in hop:
            for role, field in ENDPOINT.items():
                if field in hop:
                    name, version, configuration = hop[field]
                    endpoint = {
                        "implementation": name, "version": version, "configuration": configuration,
                        "profile": hop["profile"], "identifier_scheme": hop["identifier_scheme"],
                    }
                    hop[field] = pin(current_endpoint(peers, endpoint, role))
        hops.append(hop)
    return {**row, "hops": hops}


def typed_blocker(execution, chain):
    unqualified = set()
    for hop in execution["hops"]:
        if not all(field in hop for field in ("profile", "caller_pin", "receiver_pin")):
            continue
        caller, receiver = (tuple(hop[field]) for field in ENDPOINT.values())
        if not chain.qualified(caller, receiver, hop["profile"], hop["identifier_scheme"],
                               hop["wic_issuer"], hop["wit_issuer"]):
            unqualified.add(f"{caller[0]} -> {receiver[0]} ({hop['profile']})")
    if unqualified:
        return "unqualified workload directions: " + ", ".join(sorted(unqualified))
    return None


def test_rich_generic_shard(rich_generic_lab, typed_hop_adapters, peer_setup_cache):
    selected = json.loads(Path(os.environ["TBA_WIMSE_RICH_SELECTION"]).read_text(encoding="utf-8"))
    wanted = set(selected)
    manifest_path = Path(os.environ["TBA_WIMSE_RICH_MANIFEST"])
    plan = read_inventory(manifest_path)
    expected = {row["id"]: row for group in ("workload_executions", "planned_executions")
                for row in plan[group] if row["id"] in wanted}
    assert len(selected) == len(wanted) == len(expected)
    assert sha256(manifest_path.read_bytes()).hexdigest() == rich_generic_lab.qualification["manifest_sha256"]
    cases = {case["id"]: case for case in plan["scenario_definitions"]}
    with Path(os.environ["TBA_WIMSE_RICH_RESULTS"]).open("w", encoding="utf-8") as stream:
        for execution_id in selected:
            row = expected[execution_id]
            if "pairs" in row:
                case = cases[row["scenario_id"]]
                execution = workload_execution(row, case, rich_generic_lab)
                result, = run_inventory([case], [execution], {case["scenario_id"]: rich_generic_lab},
                                        setup_cache=peer_setup_cache)
            else:
                assert not row.get("named_scenario_id") and any(is_rich(hop) for hop in row["hops"])
                execution = typed_execution(row, rich_generic_lab.peers)
                result = run_hop_execution(execution, typed_hop_adapters)
                if result["status"] == "blocked":
                    chain = typed_hop_adapters[("call", "call", "call")]
                    result["reason"] = typed_blocker(execution, chain) or result["reason"]
            stream.write(json.dumps(result) + "\n")
            stream.flush()
