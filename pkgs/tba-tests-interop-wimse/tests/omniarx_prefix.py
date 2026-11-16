"""Workload refusals on planned OmniArx paths that never reach the verifier."""

from support.typed_service_flow import StatusFlowServices, TypedServiceFlow


OPERATION = "omniarx-check"
PATHS = (("call", OPERATION), ("call", "call", OPERATION))


class _UnreachableApprovalVerifier(StatusFlowServices):
    bindings = {OPERATION: {"omniarx"}}
    write_gates = {OPERATION}

    def support_request(self, index, fault):
        raise AssertionError("Workload refusal failed to stop execution before OmniArx")


class OmniArxPrefixFlow(TypedServiceFlow):
    """Exercise the real workload hops without implementing the absent peer."""

    def __init__(self, workload_chain):
        super().__init__(workload_chain, _UnreachableApprovalVerifier)

    def supports(self, execution):
        hops = execution["hops"]
        if (tuple(hop["operation"] for hop in hops) not in PATHS
                or hops[-1].get("support") != "omniarx"):
            return False
        target, _, reason = execution["outcome_id"].partition(":")
        if (reason not in {"peer-identity-refused", "operation-scope-refused"}
                or not target.isascii() or not target.isdecimal()
                or not 0 < int(target) < len(hops)
                or execution["decision_hop"] != int(target)
                or execution["reached_hops"] != int(target)
                or execution["expected_effects"] != 0):
            return False
        return super().supports(execution)
