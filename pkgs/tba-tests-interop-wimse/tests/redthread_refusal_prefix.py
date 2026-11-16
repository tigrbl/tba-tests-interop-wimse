"""Exercise upstream refusals on Redthread paths using the existing lab bindings."""

from support.typed_service_bindings import TypedServiceBindings
from support.typed_service_flow import TypedServiceFlow


STATUS = "redthread-check"
RECEIPT = "redthread-receipt-check"
REFUSALS = {
    STATUS: {"peer-identity-refused", "operation-scope-refused"},
    RECEIPT: {"delegation-widens-parent-scope"},
}
CALL_PATHS = (("call", STATUS), ("call", "call", STATUS))
DELEGATION_PATHS = (("delegate", RECEIPT), ("delegate", "delegate", RECEIPT))


class _UpstreamBindings(TypedServiceBindings):
    bindings = {**TypedServiceBindings.bindings, STATUS: {"redthread"}, RECEIPT: {"redthread"}}
    write_gates = {STATUS}

    def support_request(self, index, fault):
        if self.hops[index].get("support") == "redthread":
            raise AssertionError("Refusal did not stop the flow before Redthread dispatch")
        return super().support_request(index, fault)


class RedthreadRefusalPrefix(TypedServiceFlow):
    def __init__(self, workload_chain):
        super().__init__(workload_chain, _UpstreamBindings)

    def supports(self, execution):
        hops = execution["hops"]
        path = tuple(hop["operation"] for hop in hops)
        if path not in CALL_PATHS + DELEGATION_PATHS or hops[-1].get("support") != "redthread":
            return False
        target, _, reason = execution["outcome_id"].partition(":")
        if not target.isascii() or not target.isdecimal() or reason not in REFUSALS[path[-1]]:
            return False
        decision_hop = int(target)
        return (
            0 < decision_hop < len(hops)
            and execution["decision_hop"] == execution["reached_hops"] == decision_hop
            and execution["expected_result"] == reason
            and execution["expected_effects"] == 0
            and super().supports(execution)
        )
