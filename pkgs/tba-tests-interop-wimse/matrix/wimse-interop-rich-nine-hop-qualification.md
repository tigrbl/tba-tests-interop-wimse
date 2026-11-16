# RICH and the IETF 127 nine-hop success case

`wimse-interop-rich-nine-hop-executions.json.gz` contains 161,370 unique candidate execution IDs. The existing 142,844 rows retain their IDs and contents. The expansion adds 1,136 RICH workload cases, 5,102 RICH typed flows, and 12,288 assignments for one named nine-hop success case. The 3,072 assignments that keep each domain's issuer and exchange on the same implementation are included in the 12,288.

From the package directory, generate a new copy at an unused output path.

```sh
python -m tba_tests_interop_wimse \
  --extend-frozen-manifest matrix/wimse-interop-all-tba-executions.json.gz \
  --output rich-nine-hop.json.gz
python -m tba_tests_interop_wimse --frozen-manifest rich-nine-hop.json.gz
```

The expansion uses the original manifest's endpoint pins and falls back to the peer catalog for declared capabilities absent from it. The RICH coordinator and research configurations share the pinned revision and use distinct workload identities. The named flow models the pinned B_CHAIN success case separately from the generic one-to-three-hop vocabulary. Its input, output, role candidates and qualification contracts are in `named_scenarios.ietf127-b-chain` in the generated inventory.

## Qualification required

The original AgentMaurice/RICH binding is documented in the [pinned hackathon wire review](https://github.com/apelov/IETF127-Hackathon-AI2II-WIMSE/blob/49d29ca31d248af4a169176969e712c673f11ef9/validation/opus-chain-review.md). The generated rows are planned candidates. The existing hosted matrix continues to use the original manifest for its qualified regression scope.

| Hop | Contract to qualify | Directional binding pairs |
| --- | --- | ---: |
| 1 | Driver obtains T_A. The issuer binds the driver's WIMSE identity, ingress audience, scope, and file context. | 8 |
| 2 | Ingress validates the signed request and T_A, authorizes the workload, and completes the text-stats workflow. | 16 |
| 3 | Domain A exchange verifies the signed request and T_A, then issues an audience-bound cross-domain assertion. | 8 |
| 4 | Domain B exchange validates the assertion and issues an access token for the Coordinator and Research. | 8 |
| 5 | Coordinator verifies the signed request with its Domain B access token and drives the downstream calls. | 16 |
| 6 | Domain B issuer accepts the access token and issues T_B1 for the Coordinator. | 8 |
| 7 | Research verifies the Coordinator's signed call and the T_B1 bound to it. | 12 |
| 8 | The same Domain B issuer replaces T_B1 with T_B2, preserving the transaction ID and narrowing scope for Research. | 6 |
| 9 | The File Tool verifies WPT binding to the WIT and T_B2, then authorizes exactly one protected read with the expected output. | 12 |
| **Total** | **27 role bindings across nine logical roles** | **94** |

1. **Bind the actual endpoints.** Give each role binding a launch command or callable, immutable version, trust configuration and verifier instrumentation. Parameterize the pinned demo's addresses, audiences and keys so the same driver can call a substituted workload. Keep the distinct identities of the Coordinator and Research even when both use one implementation. Exercise the two RICH endpoints with their exact HTTP-signature and WPT interfaces, then qualify the matching components and application adapters for substitute roles.
2. **Qualify issuance and exchange.** For TbA candidates, wire a transaction issuer, the JWT assertion exchange, its redemption, and Domain B's replacement flow to the exact token types and claims in the named case. Check signed-body binding, issuer trust, audience, `req_wl`, transaction-ID continuity, and scope. Validate the one-to-many handoffs where T_A feeds both ingress and source exchange and where the Domain B access token feeds the Coordinator and issuer. Verify that Domain A's raw token stays in Domain A.
3. **Qualify complete role behavior.** Exercise the actual ingress workflow, coordinator-to-research call, research-to-tool call and protected read. A proof component qualifies only the portion it performs. Establish the passing control for each applicable handoff and verify rejection of an incompatible trust anchor, wrong audience, mismatched proof key, wrong workload binding, scope widening, and replay. These are qualification controls for the success inventory.
4. **Wire and audit hosted execution.** Add a runner for the named flow that can provision the separate or co-located token endpoints, execute each assignment on Ubuntu, and record nine ordered hops, token fingerprints or correlation values, and the protected-effect count. Preserve the existing published IDs in the combined report and reconcile one terminal result per ID. Mark an unmet runtime or qualification dependency as blocked. Compare the full trace with the original wire oracle, including both WPT token hashes at the File Tool and the absence of T_A in Domain B.

The 94 pairs are a local qualification inventory. The end-to-end run still needs to verify cross-hop state for each of the 12,288 assignments. The pinned AgentMaurice caller's transaction-header refusal excludes it from roles that must send a workflow-supplied Txn-Token. Pinned Authgent emits a client identifier in `req_wl` and accepts ID or access tokens for issuance. The named flow requires the presenting WIMSE identity and, at hop 8, a prior transaction token. [AgentMaurice hosted evidence](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/43834708146/artifacts/14213917621) · [Authgent token service](https://github.com/authgent/authgent/blob/8341cf932c9816dc666f2a6577b6776bd6f3b978/server/authgent_server/services/token_service.py)
