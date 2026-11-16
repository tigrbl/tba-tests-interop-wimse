"""Generate the additive RICH and IETF 127 nine-hop candidate inventory."""

from collections import Counter, defaultdict
import gzip
from hashlib import sha256
from itertools import product
import json

from .catalog import read_catalog
from .hop_expansion import hop_execution_id
from .native_expansion import expanded_plan


RICH = "rich-hackathon"
GROUPS = ("workload_executions", "planned_executions")
BASE_COUNT = 142_844
RICH_COUNTS = {"workload_executions": 1_136, "planned_executions": 5_102}


def frozen_peer_catalog(manifest):
    """Reuse published endpoint pins. Fall back to catalog-only capabilities."""
    peers = read_catalog("peers.toml")
    capabilities = {}
    fields = ("implementation", "role", "profile", "identifier_scheme")
    for row in manifest["workload_executions"]:
        for pair in row["pairs"].values():
            for endpoint in pair.values():
                key = tuple(endpoint[field] for field in fields)
                if capabilities.setdefault(key, endpoint) != endpoint:
                    raise ValueError(f"Conflicting endpoint pins in the frozen baseline: {key}")
                if endpoint["status"] == "qualified":
                    peers["implementations"][key[0]].pop("placeholder", None)
    for endpoint in peers["capabilities"]:
        capabilities.setdefault(tuple(endpoint[field] for field in fields), endpoint)
    peers["capabilities"] = list(capabilities.values())
    return peers


def rich_capabilities(implementation):
    return [
        {
            "implementation": RICH, "configuration": configuration,
            "version": implementation["candidate_revision"], "status": "pending",
            "role": direction, "profile": profile, "identifier_scheme": "none",
            "wit_issuers": workload["wit_issuers"],
        }
        for configuration, workload in implementation["workload_roles"].items()
        for direction in ("caller", "receiver")
        for profile in workload[f"{direction}_profiles"]
    ]


def rich_rows(manifest, peers):
    richer = {**peers, "capabilities": [
        *peers["capabilities"], *rich_capabilities(peers["implementations"][RICH]),
    ]}
    plan = expanded_plan(richer, include_candidates=True, include_native=True, include_executions=True)
    workload = [
        row for row in plan["workload_executions"]
        if any(endpoint["implementation"] == RICH for pair in row["pairs"].values() for endpoint in pair.values())
    ]
    typed = [
        row for row in plan["planned_executions"]
        if any(hop.get(f"{side}_pin", [None])[0] == RICH for hop in row["hops"] for side in ("caller", "receiver"))
    ]
    additions = dict(zip(GROUPS, (workload, typed)))
    for group, new in additions.items():
        regenerated = {row["id"] for row in plan[group]}
        if len(new) != RICH_COUNTS[group] or any(row["id"] not in regenerated for row in manifest[group]):
            raise ValueError(f"Unexpected RICH expansion or baseline drift in {group}")
    return additions


def named_role_choices(peers, scenario):
    implementations = {key: value for key, value in peers["implementations"].items()
                       if not value.get("placeholder") and key != RICH}
    matching_proofs = defaultdict(set)
    endpoint_pins = defaultdict(list)
    for row in peers["capabilities"]:
        name = row["implementation"]
        if (name in implementations and row["identifier_scheme"] == "none"
                and row["status"] != "unsupported" and "baseline" in row.get("wit_issuers", ["baseline"])):
            matching_proofs[name].add((row["role"], row["profile"]))
            endpoint_pins[name].append(row)

    choices = {}
    for role in scenario["roles"]:
        key = role["id"]
        if key in choices:
            raise ValueError(f"Duplicate role: {key}")
        eligible = []
        for name, implementation in sorted(implementations.items()):
            native = set(implementation.get("native_roles", ()))
            support = native | set(implementation.get("candidate_support_roles", ()))
            requirements = set(role.get("proofs", {}).items())
            if (name in role.get("exclude", ()) or not requirements <= matching_proofs[name]
                    or not set(role.get("native_roles", ())) <= native
                    or ("support_role" in role and role["support_role"] not in support)):
                continue
            override = scenario.get("pin_overrides", {}).get(name, {})
            version = override.get("version") or implementation.get("candidate_revision")
            configuration = override.get("configuration")
            known = endpoint_pins[name]
            versions = {row["version"] for row in known if row.get("version")}
            configs = {row["configuration"] for row in known if row.get("configuration")}
            if not version and len(versions) == 1:
                version = next(iter(versions))
            if not configuration and len(configs) == 1:
                configuration = next(iter(configs))
            if not version or not configuration:
                raise ValueError(f"Missing or ambiguous named-flow pin for {name} in {key}")
            eligible.append((name, version, configuration))
        if "demo" in role:
            eligible.append(("ietf127-demo", scenario["revision"], role["demo"]))
        if "rich" in role:
            pinned = peers["implementations"][RICH]
            workload = pinned["workload_roles"][role["rich"]]
            if any(profile not in workload[f"{side}_profiles"] for side, profile in role["proofs"].items()):
                raise ValueError(f"RICH workload does not match role {key}")
            eligible.append((RICH, pinned["candidate_revision"], role["rich"]))
        if not eligible:
            raise ValueError(f"No candidates for named role {key}")
        choices[key] = eligible
    return choices


def nine_hop_rows(peers, scenario):
    choices = named_role_choices(peers, scenario)
    template = scenario["hops"]
    if len(template) != 9 or {hop[side] for hop in template for side in ("caller", "receiver")} != choices.keys():
        raise ValueError("The named success case must bind all roles across nine hops")
    definitions = {role["id"]: role for role in scenario["roles"]}
    for hop in template:
        if "profile" in hop and any(definitions[hop[side]].get("proofs", {}).get(side) != hop["profile"]
                                    for side in ("caller", "receiver")):
            raise ValueError(f"Proof profile differs from the role contract at {hop['operation']}")
    rows = []
    colocated = 0
    for selection in product(*choices.values()):
        assignments = dict(zip(choices, selection))
        hops = [
            {
                **hop,
                **{f"{side}_pin": assignments[hop[side]] for side in ("caller", "receiver")},
                **({"identifier_scheme": "none", "wic_issuer": "none", "wit_issuer": "baseline"}
                   if "profile" in hop else {}),
            }
            for hop in template
        ]
        rows.append({
            "id": hop_execution_id(hops, "success"), "status": "planned",
            "named_scenario_id": scenario["id"], "hop_sequence_id": scenario["id"],
            "initial_input": scenario["initial_input"], "hops": hops,
            "outcome_id": "success", "reached_hops": len(hops), "decision_hop": len(hops),
            "expected_result": scenario["expected_result"], "expected_effects": scenario["expected_effects"],
        })
        colocated += all(assignments[left] == assignments[right] for left, right in scenario["colocated_roles"])
    if len(rows) != scenario["expected_assignments"] or colocated != scenario["expected_colocated_assignments"]:
        raise ValueError(f"Unexpected named expansion: {len(rows)} bindings, {colocated} co-located")
    return rows, choices, colocated


def extend_frozen_manifest(source):
    with gzip.open(source, "rt", encoding="utf-8") as stream:
        manifest = json.load(stream)
    base = [row["id"] for group in GROUPS for row in manifest[group]]
    if len(base) != BASE_COUNT or len(set(base)) != BASE_COUNT or manifest["total_runs"] != BASE_COUNT:
        raise ValueError(f"Expected the original {BASE_COUNT:,}-ID frozen manifest")
    peers = frozen_peer_catalog(manifest)
    additions = rich_rows(manifest, peers)
    scenario = read_catalog("nine_hop.toml")
    nine_hop, choices, colocated = nine_hop_rows(peers, scenario)
    ids = base + [row["id"] for group in GROUPS for row in additions[group]] + [row["id"] for row in nine_hop]
    if len(ids) != len(set(ids)):
        raise ValueError("Additive manifest would contain duplicate execution IDs")

    workload_counts = Counter(row["hop_sequence_id"] for row in additions["workload_executions"])
    typed_counts = Counter(row["hop_sequence_id"] for row in additions["planned_executions"])
    typed_assignments = defaultdict(set)
    for row in additions["planned_executions"]:
        typed_assignments[row["hop_sequence_id"]].add(hop_execution_id(row["hops"], "success"))
    for sequence in manifest["sequences"]:
        key = sequence["hop_sequence_id"]
        sequence["candidate_runs"] += workload_counts[key]
        sequence["new_planned_runs"] += typed_counts[key]
        sequence["compatible_assignments"] += len(typed_assignments[key])
    manifest["existing_runs"] += len(additions["workload_executions"])
    manifest["new_planned_runs"] += len(additions["planned_executions"])
    manifest["external_total_runs"] += sum(map(len, additions.values()))
    for group in GROUPS:
        manifest[group].extend(additions[group])
    manifest["planned_executions"].extend(nine_hop)
    manifest["total_runs"] = len(ids)
    manifest["additive_expansion"] = {
        "base_runs": BASE_COUNT, "base_sha256": sha256(source.read_bytes()).hexdigest(),
        "rich_workload_runs": len(additions["workload_executions"]),
        "rich_typed_runs": len(additions["planned_executions"]),
        "named_runs": len(nine_hop), "colocated_subset": colocated,
    }
    manifest["named_scenarios"] = {scenario["id"]: {**scenario, "role_candidates": choices}}
    return manifest
