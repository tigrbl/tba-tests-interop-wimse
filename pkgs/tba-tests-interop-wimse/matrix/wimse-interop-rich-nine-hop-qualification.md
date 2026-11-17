# RICH and the IETF 127 nine-hop success case

The [full manifest](wimse-interop-rich-nine-hop-executions.json.gz) preserves the original 142,844 IDs and adds 1,136 generic RICH workload cases, 5,102 generic RICH typed-hop cases, and 12,288 assignments for the named `ietf127-b-chain` success case. The [interop guide](../../../INTEROP.md) explains the full hosted results.

The [pinned IETF 127 B_CHAIN reference](https://github.com/apelov/IETF127-Hackathon-AI2II-WIMSE/blob/49d29ca31d248af4a169176969e712c673f11ef9/validation/opus-chain-review.md) models a request originating in Domain A that obtains authority to read a protected file in Domain B.

| Hop | Caller → receiver | Handoff and check | Qualified directions |
| --- | --- | --- | ---: |
| 1 | Driver → Issuer A | Issue `T_A` bound to the Driver identity, ingress audience, scope, and file context | 8 |
| 2 | Driver → Ingress | Verify the WIT, HTTP signature, and `T_A`, then run the text-stats operation | 16 |
| 3 | Driver → Exchange A | Verify the signed request and `T_A`, then issue an assertion for Exchange B | 8 |
| 4 | Driver → Exchange B | Redeem the assertion for an access token scoped to Domain B | 8 |
| 5 | Driver → Coordinator | Verify the signed request and Domain B access token, then start the downstream calls | 16 |
| 6 | Coordinator → Issuer B | Exchange the Domain B access token for `T_B1` bound to the Coordinator | 8 |
| 7 | Coordinator → Research | Verify the signed call and the bound `T_B1` | 12 |
| 8 | Research → Issuer B | Replace `T_B1` with `T_B2`, retaining the transaction ID and narrowing scope for Research | 6 |
| 9 | Research → File Tool | Verify WPT binding to the WIT and `T_B2`, then authorize exactly one read of `Q3.pdf` | 12 |
| **Total** | | | **94** |

The success oracle checks the ordered HTTP results, ingress and research outputs, token continuity, narrowed scope, and the single protected effect. The original Domain A transaction token stays in Domain A.

## Role substitutions

Each assignment selects one pinned implementation and configuration per role. That choice stays fixed wherever the role appears. Issuer B is the same instance on hops 6 and 8. RICH Coordinator and RICH Research share a source revision and use distinct workload identities and proof configurations.

| Role | Qualified choices | Count |
| --- | --- | ---: |
| Driver | Cofide, Cred, TbA, IETF 127 demo | 4 |
| Issuer A | TbA, IETF 127 demo | 2 |
| Ingress | AgentMaurice, Cofide, Cred, TbA | 4 |
| Exchange A | TbA, IETF 127 demo | 2 |
| Exchange B | TbA, IETF 127 demo | 2 |
| Coordinator | Cofide, Cred, TbA, RICH Coordinator | 4 |
| Issuer B | TbA, IETF 127 demo | 2 |
| Research | Cred, TbA, RICH Research | 3 |
| File Tool | AgentMaurice, Cred, TbA, IETF 127 demo | 4 |

The product of the choice counts is **12,288 assignments**, including **3,072** with Issuer A and Exchange A co-located and Exchange B and Issuer B co-located. See [nine_hop.toml](../src/tba_tests_interop_wimse/nine_hop.toml) for admissibility rules and the manifest's `named_scenarios.ietf127-b-chain.role_candidates` for exact version and configuration tuples.

The pinned AgentMaurice workflow caller reserves the supplied `Txn-Token` header. Its qualified substitutions are Ingress and File Tool receivers. Authgent's issuer constraints are below. Cofide's [signature bridge](../tests/support/nine_hop_cofide.md) uses an overlay to sign `wimse-aud`. The [TbA File Tool WPT fixture](../tests/support/nine_hop_tba.md) opts in to preserving the exact empty-path audience.

## Hosted execution and evidence

[Hosted run 44021013592, attempt 2](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/attempts/2) reported **12,288 passed, 0 failed, and 0 blocked** for the named success case. Its `nine-hop-results/qualification.json` links all **27 role bindings** and **94 directional handoffs** to passing execution IDs. The runner compares each assignment's HTTP capture with the nine-hop checks and uploads result metadata and per-ID outcomes. Refusal controls have separate qualification evidence.

Dispatch [WIMSE nine-hop interoperability](../../../.github/workflows/nine-hop.yml) to rerun these assignments on hosted Ubuntu. To regenerate the full inventory locally, run from the package directory at a fresh output path.

```sh
python -m tba_tests_interop_wimse \
  --extend-frozen-manifest matrix/wimse-interop-all-tba-executions.json.gz \
  --output rich-nine-hop.json.gz
python -m tba_tests_interop_wimse --frozen-manifest rich-nine-hop.json.gz
```

## Authgent issuer candidates

Run `tests/qualify_authgent_nine_hop.py` against the installed server from the
clean pinned Authgent checkout. The probe uses disposable local issuers and
reports signed claim checks and HTTP outcomes without recording credentials.
At revision `8341cf932c9816dc666f2a6577b6776bd6f3b978`, the source and
destination issuance controls returned verified transaction JWTs with a
registered OAuth client identifier in `req_wl`. The replacement control sent
the issued Domain B token back as a transaction-token subject and received
HTTP 400 `invalid_request`.

Qualify a future issuer revision at hop 1 using the authenticated WIT subject
as the requesting workload. For hops 6 and 8, qualify one issuer instance
with the real Domain B access token, then verify that replacement from
`T_B1` preserves the transaction ID, narrows scope and binds the Research
identity. Keep these candidate roles outside the published inventory until
the live issuer passes those controls.
