"""Wire the native AgentMaurice WIT+WPT receiver into the File Tool fixture."""

import http.client
import json
import re


PIN = (
    "agentmaurice",
    "c9ae5757e9d97ec8fa6b9fc9e6b835c63eba770b",
    "agentmaurice-v2.2.18-workflow-loopback-v1",
)
FILE_AUDIENCE = "http://rich.ietf127.example:5063"
TRANSACTION_AUDIENCE = "rich.ietf127.example"
TRANSACTION_ISSUER = "http://rich.ietf127.example:5061"
RESEARCH = "wimse://rich.ietf127.example/agent/research"
WORKFLOW_BODY = b'{"inputs":{"text":"Q3.pdf"}}'


class FileToolReceiver:
    """Verify the exact caller proof in AgentMaurice before the fixture reads."""

    def __init__(self, agent, wimse, transaction_jwks):
        if not re.fullmatch(r"[a-z0-9]+", agent):
            raise ValueError("Invalid disposable AgentMaurice deployment ID")
        self.path = f"/api/v2/agents/{agent}/workflows/text-stats/executions"
        self.parse_jwt = wimse.parse_jwt
        self.verify_jwt = wimse.verify_jwt
        self.transaction_jwks = transaction_jwks

    def verify_wimse_proof(self, method, path_and_query, headers, body, trust_jwks, *, expected_aud):
        if (method, path_and_query, expected_aud) != ("POST", "/files/read", FILE_AUDIENCE):
            raise ValueError("Unexpected File Tool fixture route or audience")
        headers = {name.lower(): value for name, value in headers.items()}
        wit = headers.get("workload-identity-token", "")
        authorization = headers.get("authorization", "")
        token = headers.get("txn-token", "")
        if not authorization.startswith("WPT ") or not wit:
            return False, 401, "proof-required", {}
        try:
            _, claims, _, _ = self.parse_jwt(wit)
            _, proof, _, _ = self.parse_jwt(authorization.removeprefix("WPT "))
        except (ValueError, TypeError, IndexError):
            return False, 401, "proof-invalid", {}
        # The shared lab has both ingress and File Tool audiences. Select the
        # exact File Tool audience before AgentMaurice authenticates the proof.
        if proof.get("aud") != FILE_AUDIENCE or claims.get("sub") != RESEARCH:
            return False, 401, "proof-invalid", {}
        try:
            transaction = self.verify_jwt(token, self.transaction_jwks, expected_typ="txntoken+jwt",
                                          expected_aud=TRANSACTION_AUDIENCE)
        except (ValueError, TypeError, IndexError):
            return False, 403, "txn-token-invalid", {}
        try:
            requested = json.loads(body)
        except ValueError:
            return False, 400, "invalid-request", {}
        if (transaction.get("iss") != TRANSACTION_ISSUER or transaction.get("req_wl") != RESEARCH
                or transaction.get("scope") != "files:read" or not transaction.get("txn")
                or not transaction.get("sub") or transaction.get("tctx") != {"file": "Q3.pdf"}
                or requested != {"file": "Q3.pdf"}):
            return False, 403, "not-authorized", {}

        connection = http.client.HTTPConnection("127.0.0.1", 5000, timeout=8)
        try:
            # WPT binds the WIT and transaction token. Forward those exact
            # credential bytes and translate the body to the workflow API.
            connection.request("POST", self.path, WORKFLOW_BODY, {
                "Content-Type": "application/json", "Authorization": authorization,
                "Workload-Identity-Token": wit, "Txn-Token": token,
            })
            response = connection.getresponse()
            payload = response.read()
        finally:
            connection.close()
        if response.status in (400, 401, 403):
            return False, response.status, "proof-invalid", {}
        result = json.loads(payload)
        execution = result.get("execution", result)
        if (response.status != 200 or execution.get("state") != "completed"
                or (execution.get("output") or execution.get("data")) != {"count": 6, "upper": "Q3.PDF"}):
            raise RuntimeError(f"AgentMaurice File Tool authentication workflow returned HTTP {response.status}")
        return True, 200, "accept", {"peer_id": RESEARCH, "wit_claims": claims, "mechanism": "wpt"}


def build_bindings(context):
    """Register when the shared runner opts into the Research-enabled lab."""
    from nine_hop_runtime import PeerBinding

    agent = context.get("agentmaurice_file_tool_agent")
    if agent is None:
        return {}
    import domain_b
    import wimse

    receiver = FileToolReceiver(agent, wimse, domain_b.tts_b_jwks)
    return {"file-tool": PeerBinding({"verify_wimse_proof": receiver.verify_wimse_proof}, PIN)}
