import gzip
import csv
from itertools import product
import json
from pathlib import Path

from ci_nine_hop import report


MATRIX = Path(__file__).resolve().parents[1] / "matrix"
GROUPS = ("workload_executions", "planned_executions")


def read_inventory(filename):
    with gzip.open(MATRIX / filename, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def test_rich_expansion_preserves_baseline_and_materializes_every_named_assignment():
    original = read_inventory("wimse-interop-all-tba-executions.json.gz")
    expanded = read_inventory("wimse-interop-rich-nine-hop-executions.json.gz")
    for group in GROUPS:
        assert expanded[group][:len(original[group])] == original[group]

    ids = {row["id"] for group in GROUPS for row in expanded[group]}
    assert len(ids) == sum(len(expanded[group]) for group in GROUPS) == expanded["total_runs"] == 161_370
    assert len(expanded["workload_executions"]) - len(original["workload_executions"]) == 1_136

    scenario = expanded["named_scenarios"]["ietf127-b-chain"]
    roles = scenario["role_candidates"]
    expected = set(product(*(map(tuple, options) for options in roles.values())))
    observed = set()
    for row in expanded["planned_executions"]:
        if row.get("named_scenario_id") != scenario["id"]:
            continue
        assert row["outcome_id"] == "success"
        assert row["reached_hops"] == row["decision_hop"] == len(row["hops"]) == 9
        assert row["expected_effects"] == 1
        bindings = {}
        for hop, template in zip(row["hops"], scenario["hops"], strict=True):
            assert all(hop[key] == value for key, value in template.items())
            for side in ("caller", "receiver"):
                pin = tuple(hop[f"{side}_pin"])
                assert bindings.setdefault(hop[side], pin) == pin
        assignment = tuple(bindings[role] for role in roles)
        assert assignment not in observed
        observed.add(assignment)

    assert observed == expected and len(observed) == 12_288
    positions = {role: index for index, role in enumerate(roles)}
    colocated = sum(all(assignment[positions[left]] == assignment[positions[right]]
                        for left, right in scenario["colocated_roles"]) for assignment in observed)
    assert colocated == 3_072
    assert len(expanded["planned_executions"]) - len(original["planned_executions"]) - len(observed) == 5_102
    assert sum(map(len, roles.values())) == 27
    assert sum(len(roles[hop["caller"]]) * len(roles[hop["receiver"]]) for hop in scenario["hops"]) == 94


def test_reference_observation_is_attributed_to_the_pinned_demo_file_tool(tmp_path):
    name = "wimse-interop-rich-nine-hop-executions.json.gz"
    report(MATRIX / name, tmp_path, {"status": "pass"})
    with (tmp_path / "per-id.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    passed, = [row["execution_id"] for row in rows if row["status"] == "pass"]
    assert len(rows) == 12_288
    reference = next(row for row in read_inventory(name)["planned_executions"] if row["id"] == passed)
    assert reference["hops"][1]["receiver_pin"][0] == "agentmaurice"
    assert reference["hops"][-1]["receiver_pin"][0] == "ietf127-demo"
