# WIMSE interoperability guide

This guide explains the core scenario model, peer bindings, and the original 142,844-ID inventory. The [repository interop guide](../../../INTEROP.md) covers the full 161,370-ID workflow and hosted results. The [named nine-hop guide](wimse-interop-rich-nine-hop-qualification.md) covers the two-domain B_CHAIN expansion.

## From a use case to an execution ID

The [scenario catalog](../src/tba_tests_interop_wimse/scenarios.toml) defines 20 families. A family groups scenarios that check the same behavior. In **Peer identity**, the success case checks that a valid peer is accepted. Refusal cases check that invalid inputs, such as a wrong trust anchor, are rejected. Each variant specifies the expected decision, events, and effects. If it introduces a fault, it also identifies the affected hop and layer. The [scenario matrix](wimse-interop-scenario-matrix.md#scenario-matrix) lists all 20 families and their conditions.

A **structural scenario** binds a variant to a topology and applicable authentication and issuer choices. The core catalog expands to 3,148 structural scenarios. The [factor catalog](../src/tba_tests_interop_wimse/factors.toml) declares the available choices. The [exclusions](../src/tba_tests_interop_wimse/exclusions.toml) remove combinations that cannot represent the intended case. Expected refusals remain in scope when the request can occur and the receiver should deny it.

A **typed flow execution** binds an ordered list of hops to participants, peer implementations, and an expected outcome. The original one- and two-call scenarios use `workload-call` hops with their original `ingress` and `enforcing` names where applicable. A gateway can receive one call and originate the next. Reversing two peers can produce a distinct execution.

| Arrows per execution | Typed flow executions |
| ---: | ---: |
| 1 | 2,043 |
| 2 | 11,544 |
| 3 | 129,257 |
| **Total** | **142,844** |

The [frozen manifest](wimse-interop-all-tba-executions.json.gz) stores **published IDs** in the `workload_executions` and `planned_executions` arrays. Scenario-derived flows retain the original ID encoding the family, variant, decision layer, authentication bindings, and peer pins. Operation-path flows retain their `hop-v1:` IDs. Each planned typed-flow row records its ordered `hops` and `outcome_id`. Scenario-derived workload rows use their scenario and per-hop bindings to describe the case.

A fresh qualification snapshot can change endpoint pins and therefore the **runtime ID**. The planner joins each runtime case to its published ID and writes the mapping to `mapping.json.gz`. Look up stable cases by published ID. Use the runtime ID to find the corresponding JUnit observation.

## Entities, peers, roles, and capabilities

A **participant** is a node in a flow, such as `workload-0`, a gateway, or an issuer. Its **entity type** tells you what it is. Its **role** tells you what it does on a particular hop. A **peer** is the concrete implementation bound to a participant. Two participants may use the same implementation, for example two independently configured TbA workloads.

| Entity type | Example roles | Example bindings |
|---|---|---|
| Workload | Caller, receiver, delegator, delegate, token client, credential requester, policy client | TbA, wimsey, Cred, Cofide, go-spiffe, Defakto, AgentMaurice |
| Delegation authority | Delegation authority | TbA delegation fixture |
| Token service | Token issuer, transaction-token issuer | TbA token fixture, authgent |
| Credential delivery service | Credential delivery | SPIRE Workload API, Teleport tbot, TbA Workload API |
| Status and policy service | Status authority, before-effect enforcer, receipt verifier, approval verifier | TbA policy fixtures, MintID, EMILIA, Redthread, OmniArx |

The matrix uses one [peer catalog](../src/tba_tests_interop_wimse/peers.toml) for TbA and external implementations. The tables below group capabilities by hop role. An implementation can appear in more than one group when it fills multiple roles. For example, go-spiffe acts as a workload caller, a workload receiver, and a credential requester.

A workload-call capability specifies the role, authentication profile, WIC identifier scheme, version, and configuration. A directional baseline records the exact caller and receiver tested together. Other hops have role-specific bindings and runtime evidence.

### Workload calls

Seven implementations fill workload-call roles. Two additional catalog slots for combined authentication resolve to wimsey in the lab. The WIC identifiers below apply to the TLS certificate. WIT supplies the application credential, and WPT or HTTP Message Signatures supply its proof. [Pinned sources and directional controls](wimse-interop-peers.md#workload-calls)

| Peer or slot | Workload roles | Authentication profiles | WIC identifiers | Runtime scope |
| --- | --- | --- | --- | --- |
| TbA (`tba`) | Caller and receiver | WIC/mTLS, WIT + WPT, WIT + HTTP Message Signatures, and WIC/mTLS combined with either proof | WIMSE and SPIFFE where WIC is used | Includes TbA-to-TbA and multi-hop cases, plus native X.509-SVID and WIT-SVID controls. |
| wimsey (`wimsey`) | Caller and receiver | WIC/mTLS | WIMSE and SPIFFE | The shared TLS lab exercises the wimsey WIC verifier in both directions against TbA. |
| Cred (`cred`) | Caller and receiver | WIT + WPT and WIT + HTTP Message Signatures | — | The WPT lab covers SPIRE-issued WIT-SVID. The signature lab covers direct requests and transaction binding with a lab-issued WIT. |
| Cofide WIMSE PoC (`cofide`) | Caller and receiver | WIT + HTTP Message Signatures | — | A bridge adapts the PoC signing profile for the tested TbA pairings. |
| Combined WPT slot (`combined-wpt-candidate`) | Caller and receiver | WIC/mTLS + WIT/WPT | WIMSE and SPIFFE | Composes the wimsey WIC verifier and WPT bridge in the shared HTTPS lab. |
| Combined signature slot (`combined-signature-candidate`) | Caller and receiver | WIC/mTLS + WIT/HTTP Message Signatures | WIMSE and SPIFFE | Composes the wimsey WIC and HTTP signature components in the shared HTTPS lab. |
| go-spiffe (`go-spiffe`) | Caller and receiver in the shared mTLS fixture | WIC/mTLS | SPIFFE | Exercises direct-CA and SPIRE credentials in both directions. |
| Defakto (`defakto`) | Caller and receiver in the shared mTLS fixture | WIC/mTLS | SPIFFE | Both directions exercise the SDK verifier with direct-CA and SPIRE-issued credentials. |
| AgentMaurice (`agentmaurice`) | Workflow caller and protected workflow receiver | WIT + WPT and WIT + HTTP Message Signatures | — | Both directions exercised ordinary WIT. The tested grant refused a SPIFFE holder, and SPIRE WIT-SVID needs separate inbound and outbound bindings. |

### Credential acquisition, delegation, token exchange, and policy checks

An execution can pass when it refuses a request at an expected earlier hop. Use the per-ID evidence to see whether the execution reached the peer assigned to a later role. [Credential acquisition and issuance](wimse-interop-peers.md#credential-acquisition-and-issuance) · [Delegation and token exchange](wimse-interop-peers.md#delegation-and-token-exchange) · [Status and policy checks](wimse-interop-peers.md#status-and-policy-checks) · [Runtime configuration](wimse-external-peer-access.md)

| Implementation | Hop or credential role | Capability exercised or targeted |
| --- | --- | --- |
| go-spiffe (`go-spiffe`) | Credential requester | Fetches an X.509-SVID and trust bundle from SPIRE Agent. |
| Teleport tbot (`teleport-tbot`) | Credential delivery | Delivers an X.509-SVID and bundle. The next mTLS receiver verifies the delivered certificate in acquisition cases that continue. |
| SPIRE Server and Agent | Credential issuer and delivery service | Server supplies lab X.509-SVID and WIT-SVID issuer bindings. Agent delivers X.509-SVIDs through the Workload API. |
| TbA (`tba`) | Credential issuer and delivery service | Native fixtures issue X.509-SVIDs and WIT-SVIDs. The Workload API delivers X.509-SVIDs and a trust bundle. |
| TbA (`tba`) | Delegation authority and token issuer | Lab fixtures bind delegated authority, issue transaction tokens, and handle source and destination token exchanges. TbA also provides a bearer-protected resource. |
| authgent (`authgent`) | Transaction-token issuer | Exercises issuance scope and request binding with TbA and Cred. Lab services handle the subsequent source and destination exchanges. |
| TbA (`tba`) | Status authority, before-effect enforcer, receipt verifier, and approval verifier | Lab fixtures exercise status and delegation enforcement, receipt verification, and approval checks. |
| MintID (`mintid`) | Status authority | Exercises active proofs, issuer revocation, holder self-revocation, and witness refresh before a protected effect. |
| EMILIA (`emilia`) | Before-effect enforcer | Exercises entry for an active issuer and blocks the protected callback after revocation. |
| OmniArx (`omniarx`) | Approval verifier | Targets signed approval bound to the observed request and action. Cases that reach the verifier need a runnable binding. |
| Redthread Security (`redthread`) | Delegation receipt verifier and before-effect enforcer | Targets delegation narrowing, receipt verification, and enforcement. Cases that reach the service need a runnable binding. |

## Arrows and hops

A **hop** is one directed arrow between participants. The source initiates the interaction and the destination handles it. The [hop catalog](../src/tba_tests_interop_wimse/hops.toml) defines five arrow types and the allowed operation transitions.

| Arrow type | Example |
|---|---|
| Workload call | An agent calls a protected workload. |
| Delegation | An authorized workload requests a narrower grant. |
| Token exchange | A token client exchanges a grant for a destination credential. |
| Credential acquisition | A workload obtains an X.509-SVID and trust bundle from a Workload API. |
| Status or policy check | A workload asks a verifier to confirm approval or revocation status before an effect. |

An expected refusal can end the observed trace before a later planned arrow. Use `reached_hops`, `decision_hop`, and the trace to see where execution stopped. An exchange or lookup performed internally by a fixture counts as a separate hop when the catalog models it as its own arrow.

Each workload hop records its TLS profile, application-layer credential, application proof, and issuer choices. For example, **WIT** is the credential, **WPT** is the proof, and `spire-wit-svid` identifies the issuer mode. A WIC/mTLS-only hop records `None` for application-layer credential and application proof.

Each numbered arrow counts as one hop. Trust domains count separately. In a connected flow where each participant has one trust-domain assignment, all participants can share one domain, or each hop can introduce at most one additional domain. A one-hop flow can therefore involve 1–2 domains, a two-hop flow 1–3, and a three-hop flow 1–4. A hop can also return to a domain already used in the flow.

### Trust-domain assignments for the example flows

Each numbered arrow represents a request and its response. An arrow within a column stays in that trust domain. An arrow through a divider crosses a trust boundary. Resource means the protected workload, API means the Workload API, and Status means the status authority.

**One hop — Direct workload call**

```text
1 domain
Trust domain A
[Caller] --1 call--> [Resource]

2 domains
Trust domain A                       | Trust domain B
[Caller] --1 call--------------------+---> [Resource]
```

**Two hops — Workload calls through a gateway**

```text
1 domain
Trust domain A
[Caller] --1 ingress--> [Gateway]
[Gateway] --2 enforce--> [Resource]

2 domains
Trust domain A                       | Trust domain B
[Caller] --1 ingress--> [Gateway]    |
[Gateway] --2 enforce----------------+---> [Resource]

3 domains
Trust domain A                       | Trust domain B                       | Trust domain C
[Caller] --1 ingress-----------------+---> [Gateway]                        |
                                     | [Gateway] --2 enforce----------------+---> [Resource]
```

**Three hops — Acquire a credential, call a workload, check status**

```text
1 domain
Trust domain A
[Workload A] --1 acquire--> [API]
[Workload A] --2 mTLS--> [Workload B]
[Workload B] --3 check--> [Status]

2 domains
Trust domain A                       | Trust domain B
[Workload A] --1 acquire--> [API]    |
[Workload A] --2 mTLS----------------+---> [Workload B]
                                     | [Workload B] --3 check--> [Status]

3 domains
Trust domain A                       | Trust domain B                       | Trust domain C
[Workload A] --1 acquire--> [API]    |                                      |
[Workload A] --2 mTLS----------------+---> [Workload B]                     |
                                     | [Workload B] --3 check---------------+---> [Status]

4 domains
Trust domain A                       | Trust domain B                       | Trust domain C                       | Trust domain D
[Workload A] --1 acquire-------------+---> [API]                            |                                      |
[Workload A] --2 mTLS----------------+--------------------------------------+---> [Workload B]                     |
                                     |                                      | [Workload B] --3 check---------------+---> [Status]
```

These layouts illustrate where participants can sit. Each cross-domain hop requires compatible peer and issuer bindings and the trust configuration appropriate to the expected outcome.

### Verified trust-domain coverage

Four live TbA loopback cases passed with SPIFFE X.509-SVIDs over mTLS. They cover a one-domain control, a direct call across two domains, a two-hop gateway path across three domains, and a three-hop gateway chain across four domains. Each trust domain has its own CA, and each side validates the expected SPIFFE identity against the peer's configured bundle. The three- and four-domain cases use workload calls through gateways. The credential acquisition and status-check diagrams above illustrate a different topology. [Trust-domain assignments and case IDs](wimse-interop-execution-matrix.md#trust-domain-executions)

The four supplemental cases are selected through pytest and counted separately from the 142,844-ID frozen manifest. These additional cases cover static bundle configuration. SPIRE bundle exchange and external peers have separate qualification paths.

The supplemental fixture lives in repository commit `23cd5cf`. To reproduce that historical run, use a checkout containing that fixture. From its package directory, install pytest, the `wic` and `spiffe-wic` extras, and the shared workload credential conformance fixture, then run the four cases.

```powershell
$env:PYTHONPATH = "src;tests"
python -m pytest -q tests/peer/test_trust_domain_executions.py
```

### Published execution examples

Each ID below is a complete identifier from the frozen manifest. Use it as the **Execution ID** input to select a single run. These examples specify an expected outcome. Consult the runtime report for the observed outcome. [Frozen execution manifest](wimse-interop-all-tba-executions.json.gz)

**One hop — Peer identity.** A TbA caller presents a WIC with a WIMSE ID to a TbA receiver. The receiver should allow the operation.

```text
01:valid-peer:operation:enforcing=wic-mtls/wimse/baseline/none:["tba","sha256:a4eeb55ad83b39b74e2ee5a9ecadb5cb42f03bb810e21622acca953f2e9b1d19","shared-python-tls-direct-ca-ledger-v1"];["tba","sha256:a4eeb55ad83b39b74e2ee5a9ecadb5cb42f03bb810e21622acca953f2e9b1d19","shared-python-tls-direct-ca-ledger-v1"]
```

**Two hops — TLS termination.** TbA acts as caller, gateway, and receiver. Both the ingress and enforcing hops use WIC/mTLS with WIMSE IDs. The protected operation should be allowed.

```text
04:validated-origin-proof:operation:ingress=wic-mtls/wimse/baseline/none,enforcing=wic-mtls/wimse/baseline/none:["tba","sha256:a4eeb55ad83b39b74e2ee5a9ecadb5cb42f03bb810e21622acca953f2e9b1d19","shared-python-tls-direct-ca-ledger-v1"];["tba","sha256:a4eeb55ad83b39b74e2ee5a9ecadb5cb42f03bb810e21622acca953f2e9b1d19","shared-python-tls-direct-ca-ledger-v1"];["tba","sha256:a4eeb55ad83b39b74e2ee5a9ecadb5cb42f03bb810e21622acca953f2e9b1d19","shared-python-tls-direct-ca-ledger-v1"];["tba","sha256:a4eeb55ad83b39b74e2ee5a9ecadb5cb42f03bb810e21622acca953f2e9b1d19","shared-python-tls-direct-ca-ledger-v1"]
```

**Three hops — Credential acquisition, workload call, and status check.** The caller obtains a TbA-issued X.509-SVID and presents it on a SPIFFE mTLS hop. The receiver should accept fresh status and perform one protected operation.

```text
hop-v1:a5ebf2745935d75eb969fe2ff2816de294f7ee065a08a6221c60827496d0e17a
```

## Authentication and peer assignments

The five enforcing-hop profiles produce eight rows when split by WIC identifier scheme. Where TLS client authentication is **None**, TLS still authenticates the server, and the caller sends its WIT and proof at the application layer.

| Enforcing profile | TLS client authentication | WIC ID | Application-layer credential | Application proof | Example caller → receiver | Workload count |
| --- | --- | --- | --- | --- | --- | ---: |
| WIC/mTLS | WIC (mTLS) | WIMSE (`wimse://`) | None | None | TbA → wimsey | 600 |
| WIC/mTLS | WIC (mTLS) | SPIFFE (`spiffe://`) | None | None | TbA → go-spiffe | 2,708 |
| WIT/WPT | None | — | WIT | WPT | TbA → Cred | 1,670 |
| WIT/HTTP signatures | None | — | WIT | HTTP Message Signatures | TbA → Cofide | 1,710 |
| WIC/mTLS + WIT/WPT | WIC (mTLS) | WIMSE (`wimse://`) | WIT | WPT | TbA → wimsey (combined WPT slot) | 830 |
| WIC/mTLS + WIT/WPT | WIC (mTLS) | SPIFFE (`spiffe://`) | WIT | WPT | TbA → wimsey (combined WPT slot) | 1,660 |
| WIC/mTLS + WIT/HTTP signatures | WIC (mTLS) | WIMSE (`wimse://`) | WIT | HTTP Message Signatures | TbA → wimsey (combined signature slot) | 854 |
| WIC/mTLS + WIT/HTTP signatures | WIC (mTLS) | SPIFFE (`spiffe://`) | WIT | HTTP Message Signatures | TbA → wimsey (combined signature slot) | 1,708 |
| **Total** | | | | | | **11,740** |

This table breaks down the 11,740 flows derived from the original workload scenarios by enforcing-hop profile and WIC ID. Each count includes all applicable peer assignments and both success and refusal variants. Two-hop flows in this subset count once under their enforcing hop. [Execution matrix and assignment fields](wimse-interop-execution-matrix.md#peer-and-role-assignments)

## Run the matrix

### GitHub Actions

In a checkout published with the [matrix workflow](../../../.github/workflows/interop-matrix.yml), open **Actions → WIMSE interop matrix → Run workflow**. Leave `execution_id` blank for the original 142,844-ID inventory or paste one exact published ID. Set the shard count to control parallelism. The workflow prepares and qualifies its configured lab fixtures, executes the selected IDs, and uploads the aggregate and shard artifacts. See the [repository README](../../../README.md) for runner settings, artifact retention, and optional evidence publication.

### Local execution

Use the packages and peer artifacts pinned by the workflow or the configured lab you want to reproduce. A live run requires a **qualification snapshot** and the corresponding peer executables, bridge files, and service containers for its selected IDs. See [peer setup and qualification](wimse-external-peer-access.md) and the [runtime closure plan](wimse-runtime-closure-plan.md). Refresh qualification when a fixture or peer pin changes.

From the package directory, with the test dependencies installed, prepare a plan. The commands below use PowerShell. Set `qualification.json` to the path to your lab snapshot. Add `--execution-id <published-id>` to prepare a single case.

```powershell
$env:PYTHONPATH = "src;tests"
$env:TBA_WIMSE_PEER_SNAPSHOT = (Resolve-Path qualification.json).Path
$manifest = "matrix/wimse-interop-all-tba-executions.json.gz"
python tests/ci_matrix.py prepare --manifest $manifest --snapshot $env:TBA_WIMSE_PEER_SNAPSHOT --shards 1 --output run/plan
```

Set the environment variables for the peer artifacts referenced by the snapshot. Then execute the plan and audit the report. For a multi-shard plan, repeat the pytest command for each `shard-N.json` and write each report under `run/reports/interop-shard-N/results.xml` before aggregating.

```powershell
$env:TBA_WIMSE_EXPANDED = "1"
$env:TBA_WIMSE_INCLUDE_NATIVE = "1"
$env:TBA_WIMSE_FROZEN_MANIFEST = (Resolve-Path run/plan/runtime.json.gz).Path
$env:TBA_WIMSE_EXECUTION_SELECTION = (Resolve-Path run/plan/shard-0.json).Path
python -m pytest -o junit_family=xunit1 tests/peer/test_candidate_executions.py --junitxml=run/reports/interop-shard-0/results.xml
python tests/ci_matrix.py aggregate --manifest $manifest --plan run/plan --reports run/reports --output run/report
```

For a single-ID selection, collect only `test_peer_execution` for a scenario-derived ID or `test_typed_hop_execution` for a `hop-v1:` ID. These pytest entry points dispatch to different adapters. The workflow also shows how to run Authgent's dedicated driver and place its JUnit under `plan/authgent/results.xml` for the audit. Run the available specialized peer batches against their own qualified lab dependencies.

To inspect the catalog without starting peer services, run `tba-tests-interop-wimse --frozen-manifest matrix/wimse-interop-all-tba-executions.json.gz` from the package directory. Add `--json` to inspect the individual frozen rows.

## Read the reports

| Artifact | What to look for |
|---|---|
| `summary.json` and `summary.md` | Selected scope, counts by outcome, common blocker reasons, and audit errors. |
| `results.csv.gz` | One row per selected published ID, with its runtime ID, shard, result, and reason. |
| `provenance.json` | Hashes for the manifest, qualification snapshot, mapping, runtime plan, report, and JUnit inputs. |
| Shard `results.xml` and pytest log | Exact runtime observations and setup diagnostics. Typed traces include the reached hops, decision hop, and protected effects. |
| [Per-ID blocker report](wimse-interop-per-id-blockers.csv.gz) | Endpoint, directional baseline, issuer, support role, or adapter gaps. Historical observations carry their original runtime IDs. |
| [Execution results workbook](wimse-interop-execution-results.xlsx) | A 4,448-row result snapshot with per-hop profiles, credentials, proofs, issuers, and expected and observed decisions. |

- **Passed** means the runtime matched the expected result and effects. An expected denial with zero protected effects can pass.
- **Failed** means the runtime observation or execution failed the case.
- **Blocked** means a required binding or qualification was unavailable for that case.
- **Setup failure** means the runner recorded a failed preflight or fixture setup.
- **Not run** means the audit found no validated result for a selected ID. Check shard completion, audit errors, and the plan's scope.

Use the aggregate for counts and the per-ID CSV for lookup. For an individual case, join its published ID to the runtime ID in the CSV, then find that runtime ID in the corresponding shard report. Compare observed and expected decisions and effects before interpreting a refusal. A complete aggregate accounts for the selected IDs, including cases reported as failed or blocked.
