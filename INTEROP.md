# WIMSE interop guide

## Hops, trust domains, and execution IDs

A **hop** is a directed interaction from an initiating participant to the participant that handles it. The catalog models five types: workload call, delegation, token exchange, credential acquisition, and status or policy check. A gateway can receive one call and originate the next. A hop can stay in one trust domain or cross into another. The named nine-hop chain uses two trust domains. [Hop types and one-, two-, and three-hop diagrams](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#arrows-and-hops) · [Trust-domain layouts and supplemental cases](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#trust-domain-assignments-for-the-example-flows)

A **structural scenario** selects a topology, scenario variant, and applicable authentication and issuer choices. An **execution** assigns pinned implementations and configurations to its roles and records the expected outcome. The direction, credential issuer, and proof mode can change the assignment. The published ID identifies the planned case. The runtime ID identifies the corresponding case in the qualified lab and is used to find its JUnit observation. [From use case to published ID](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#from-a-use-case-to-an-execution-id) · [Published examples](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#published-execution-examples)

A **peer** is an implementation bound to a participant. Its capability is specific to a role and profile, such as receiving WIT/WPT or delivering an X.509-SVID. A directional control qualifies one pinned caller and receiver pairing. For the full lookup, see the [peer capability reference](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-peers.md), [authentication and peer assignments](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#authentication-and-peer-assignments), and [named nine-hop substitutions](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-qualification.md#role-substitutions).

## Select a run

| Scope | GitHub Actions workflow | Selection |
| --- | --- | --- |
| All 161,370 published IDs | [Full WIMSE interoperability matrix](.github/workflows/full-matrix.yml) | Baseline and generic RICH shards plus nine-hop shards |
| Original 142,844 IDs | [WIMSE interop matrix](.github/workflows/interop-matrix.yml) | Leave `execution_id` empty |
| One original ID | [WIMSE interop matrix](.github/workflows/interop-matrix.yml) | Set `execution_id` to the exact ID |
| All 12,288 named nine-hop IDs | [Nine-hop workflow](.github/workflows/nine-hop.yml) | Choose the shard count |

To inspect a generic RICH or nine-hop ID locally, look it up in the full manifest and follow the [package fixture instructions](pkgs/tba-tests-interop-wimse/README.md) or the [nine-hop guide](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-qualification.md). To regenerate the full inventory from the original frozen manifest, use the generation command in the nine-hop guide. The original manifest includes TbA-only and external-peer cases.

List the frozen inventory from the repository root after installing the harness.

```sh
tba-tests-interop-wimse --frozen-manifest pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-executions.json.gz
```

Changing peer pins can change generated IDs. Compare a runtime report with the frozen manifest used for that run.

## Read the results

The [README results table](README.md#hosted-results) records run 44021013592, attempt 2. The [combined report](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/artifacts/14305462171) contains `summary.md`, `summary.json`, and `per-id.csv.gz`. Look up an `execution_id` in the CSV for its lane, outcome, and reason. Match the report's manifest digest to the inventory used for the run. GitHub artifact retention applies. The workflow summary also records the totals and blocker breakdown.

- **Passed** includes expected refusals where the case checks a refusal and its effects.
- **Failed** means the observed runtime result differed from the expected outcome.
- **Blocked** means execution could not reach a verdict. Inspect the per-ID reason for missing endpoints, handoffs, issuers, or other support roles. Setup failures and cases without results also count as blocked and are flagged as infrastructure outcomes. Attempt 2 had zero infrastructure outcomes.

All 182 failures were in the original matrix. Its 8,402 blockers were AgentMaurice bindings or signing controls (7,838), Redthread (284), and OmniArx (280). The two generic RICH groups had 1,717 blockers, including 880 cases with AgentMaurice companion endpoints or directions and 792 cases requiring source/destination token, accounting/resource, or status/effect fixtures. The report records the remaining support and adapter reasons per ID.

The original-matrix workflow can also publish its audited aggregate to the
`interop-evidence` branch. Dispatch from `master` with `commit_evidence`
enabled. Shards upload their own evidence and the report job writes once
after aggregation under `runs/<run-id>/attempt-<attempt>/`. The full-matrix
workflow uploads its combined report as a workflow artifact.

## Peers and evidence

The [peer catalog](pkgs/tba-tests-interop-wimse/src/tba_tests_interop_wimse/peers.toml) lists candidate roles and profiles. The hosted qualification artifacts record the exact implementation, pin, configuration, direction, and evidence. Use the [nine-hop substitution table](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-qualification.md#role-substitutions) for the role choices and the manifest's `named_scenarios.ietf127-b-chain.role_candidates` for their exact pins.

| Peer or fixture | Runtime scope in the hosted suite |
| --- | --- |
| TbA | Native baseline cases, generic RICH companion endpoints, and all nine named role choices |
| RICH Coordinator | WIT with HTTP Message Signatures in both directions with TbA for generic cases. Coordinator in the named chain |
| RICH Research | Receives TbA HTTP Message Signatures with a WIT and calls TbA with WIT/WPT for generic cases. Research in the named chain |
| Cofide | Pinned Go signature bridge. Driver, Ingress, and Coordinator in the named chain using the signed-audience compatibility overlay |
| Cred | Pinned WIT/WPT and HTTP-signature adapters. Driver, Ingress, Coordinator, Research, and File Tool in the named chain |
| AgentMaurice | Named Ingress and File Tool receivers. Generic coverage is limited by the selected SPIRE WIT-SVID/proof-key and outbound transaction-signature bindings |
| IETF 127 demo | Reference Driver, Domain A and B token services, and File Tool |
| wimsey, Defakto, go-spiffe | Pinned proof or mutual-TLS components in the shared HTTPS lab as configured by profile |
| Teleport tbot | Hosted Workload API X.509-SVID delivery and mTLS handoff |
| MintID, EMILIA | Hosted status and before-effect controls within the configured fixtures |
| Authgent | Pinned transaction-token cases in the original matrix. Named nine-hop issuer requirements are tracked separately |
| Redthread, OmniArx | Blocked rows remain in the inventory pending runnable bindings for the reported verifier and support operations |

[Generic RICH qualification](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/artifacts/14304893080) records the four live directional controls. The named nine-hop report's `qualification.json` maps each role binding and each directional handoff to a passing execution ID. The named and generic scopes have different fixture contracts and pins.
