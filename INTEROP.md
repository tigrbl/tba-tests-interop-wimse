# WIMSE interop guide

[![Interop guide hits](https://hits.sh/github.com/tigrbl/tba-tests-interop-wimse/blob/master/INTEROP.md.svg?label=Guide%20hits)](https://hits.sh/github.com/tigrbl/tba-tests-interop-wimse/blob/master/INTEROP.md/)

## Table of contents

- [Hops, trust domains, and execution IDs](#hops-trust-domains-and-execution-ids)
- [Entities, peers, roles, and capabilities](#entities-peers-roles-and-capabilities)
  - [Peers and evidence](#peers-and-evidence)
  - [Workload calls](#workload-calls)
  - [Credential acquisition, delegation, token exchange, and policy checks](#credential-acquisition-delegation-token-exchange-and-policy-checks)
  - [RICH Coordinator and Research](#rich-coordinator-and-research)
- [Arrows and hops](#arrows-and-hops)
  - [Trust-domain assignments for the example flows](#trust-domain-assignments-for-the-example-flows)
  - [Verified trust-domain coverage](#verified-trust-domain-coverage)
  - [Published execution examples](#published-execution-examples)
- [From a use case to an execution ID](#from-a-use-case-to-an-execution-id)
- [Authentication and peer assignments](#authentication-and-peer-assignments)
- [Nine-hop success case across two trust domains](#nine-hop-success-case-across-two-trust-domains)
  - [Nine-hop role substitutions](#nine-hop-role-substitutions)
- [Select a run](#select-a-run)
- [Read the results](#read-the-results)
  - [Review individual executions](#review-individual-executions)

## Hops, trust domains, and execution IDs

A **hop** is a directed interaction from an initiating participant to the participant that handles it. The catalog models five types: workload call, delegation, token exchange, credential acquisition, and status or policy check. A gateway can receive one call and originate the next. A hop can stay in one trust domain or cross into another. The named nine-hop chain uses two trust domains. [Hop types and one-, two-, and three-hop diagrams](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#arrows-and-hops) · [Trust-domain layouts and supplemental cases](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#trust-domain-assignments-for-the-example-flows)

A **structural scenario** selects a topology, scenario variant, and applicable authentication and issuer choices. An **execution** assigns pinned implementations and configurations to its roles and records the expected outcome. The direction, credential issuer, and proof mode can change the assignment. The published ID identifies the planned case. The runtime ID identifies the corresponding case in the qualified lab and is used to find its JUnit observation. [From use case to published ID](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#from-a-use-case-to-an-execution-id) · [Published examples](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#published-execution-examples)

A **peer** is an implementation bound to a participant. Its capability is specific to a role and profile, such as receiving WIT/WPT or delivering an X.509-SVID. A directional control qualifies one pinned caller and receiver pairing. For the full lookup, see the [peer capability reference](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-peers.md), [authentication and peer assignments](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-guide.md#authentication-and-peer-assignments), and [named nine-hop substitutions](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-qualification.md#role-substitutions).

## Entities, peers, roles, and capabilities

A **participant** is a node in a flow, such as `workload-0`, a gateway, or an issuer. Its **entity type** tells you what it is. Its **role** tells you what it does on a particular hop. A **peer** is the concrete implementation bound to a participant. Two participants may use the same implementation, for example two independently configured TbA workloads.

| Entity type | Example roles | Example bindings |
|---|---|---|
| Workload | Caller, receiver, delegator, delegate, token client, credential requester, policy client | TbA, wimsey, Cred, Cofide, go-spiffe, Defakto, AgentMaurice |
| Delegation authority | Delegation authority | TbA delegation fixture |
| Token service | Token issuer, transaction-token issuer | TbA token fixture, authgent |
| Credential delivery service | Credential delivery | SPIRE Workload API, Teleport tbot, TbA Workload API |
| Status and policy service | Status authority, before-effect enforcer, receipt verifier, approval verifier | TbA policy fixtures, MintID, EMILIA, Redthread, OmniArx |

The matrix uses one [peer catalog](pkgs/tba-tests-interop-wimse/src/tba_tests_interop_wimse/peers.toml) for TbA and external implementations. The tables below group capabilities by hop role. An implementation can appear in more than one group when it fills multiple roles. For example, go-spiffe acts as a workload caller, a workload receiver, and a credential requester.

A workload-call capability specifies the role, authentication profile, WIC identifier scheme, version, and configuration. A directional baseline records the exact caller and receiver tested together. Other hops have role-specific bindings and runtime evidence.

### Peers and evidence

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

### Workload calls

Seven implementations fill workload-call roles. Two additional catalog slots for combined authentication resolve to wimsey in the lab. The WIC identifiers below apply to the TLS certificate. WIT supplies the application credential, and WPT or HTTP Message Signatures supply its proof. [Pinned sources and directional controls](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-peers.md#workload-calls)

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

An execution can pass when it refuses a request at an expected earlier hop. Use the per-ID evidence to see whether the execution reached the peer assigned to a later role. [Credential acquisition and issuance](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-peers.md#credential-acquisition-and-issuance) · [Delegation and token exchange](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-peers.md#delegation-and-token-exchange) · [Status and policy checks](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-peers.md#status-and-policy-checks) · [Runtime configuration](pkgs/tba-tests-interop-wimse/matrix/wimse-external-peer-access.md)

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

### RICH Coordinator and Research

| Binding | Caller proof | Receiver proof | Qualified scope |
| --- | --- | --- | --- |
| RICH Coordinator | WIT + HTTP Message Signatures | WIT + HTTP Message Signatures | Generic control in both directions with TbA, plus the named Coordinator role |
| RICH Research | WIT + WPT | WIT + HTTP Message Signatures | Calls TbA with WPT and receives TbA HTTP signatures in generic controls, plus the named Research role |

The roles share one source revision and use distinct workload identities. The named nine-hop assignments and the generic RICH cases qualify separately.

## Arrows and hops

A **hop** is one directed arrow between participants. The source initiates the interaction and the destination handles it. The [hop catalog](pkgs/tba-tests-interop-wimse/src/tba_tests_interop_wimse/hops.toml) defines five arrow types and the allowed operation transitions.

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

Four live TbA loopback cases passed with SPIFFE X.509-SVIDs over mTLS. They cover a one-domain control, a direct call across two domains, a two-hop gateway path across three domains, and a three-hop gateway chain across four domains. Each trust domain has its own CA, and each side validates the expected SPIFFE identity against the peer's configured bundle. The three- and four-domain cases use workload calls through gateways. The credential acquisition and status-check diagrams above illustrate a different topology. [Trust-domain assignments and case IDs](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-execution-matrix.md#trust-domain-executions)

The four supplemental cases were run separately from the 142,844-ID frozen manifest and the 161,370-ID hosted run. These additional cases cover static bundle configuration. SPIRE bundle exchange and external peers have separate qualification paths.

| Execution ID | Domains | Ordered participant and trust-domain assignments | mTLS hops | Crossings |
| --- | ---: | --- | ---: | ---: |
| `trust-domain:1:same-domain-control` | 1 | Caller (`alpha.example`) → resource (`alpha.example`) | 1 | 0 |
| `trust-domain:2:direct` | 2 | Caller (`alpha.example`) → resource (`bravo.example`) | 1 | 1 |
| `trust-domain:3:gateway` | 3 | Caller (`alpha.example`) → gateway (`bravo.example`) → resource (`charlie.example`) | 2 | 2 |
| `trust-domain:4:gateway-chain` | 4 | Caller (`alpha.example`) → gateway (`bravo.example`) → relay (`charlie.example`) → resource (`delta.example`) | 3 | 3 |

The supplemental fixture lives in repository commit `23cd5cf`. To reproduce that historical run, use a checkout containing that fixture. From its package directory, install pytest, the `wic` and `spiffe-wic` extras, and the shared workload credential conformance fixture, then run the four cases.

```powershell
$env:PYTHONPATH = "src;tests"
python -m pytest -q tests/peer/test_trust_domain_executions.py
```

### Published execution examples

Each ID below is a complete identifier from the frozen manifest. Use it as the **Execution ID** input to select a single run. These examples specify an expected outcome. Consult the runtime report for the observed outcome. [Frozen execution manifest](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-all-tba-executions.json.gz)

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

## From a use case to an execution ID

The [scenario catalog](pkgs/tba-tests-interop-wimse/src/tba_tests_interop_wimse/scenarios.toml) defines 20 families. A family groups scenarios that check the same behavior. In **Peer identity**, the success case checks that a valid peer is accepted. Refusal cases check that invalid inputs, such as a wrong trust anchor, are rejected. Each variant specifies the expected decision, events, and effects. If it introduces a fault, it also identifies the affected hop and layer. The [scenario matrix](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-scenario-matrix.md#scenario-matrix) lists all 20 families and their conditions.

A **structural scenario** binds a variant to a topology and applicable authentication and issuer choices. The core catalog expands to 3,148 structural scenarios. The [factor catalog](pkgs/tba-tests-interop-wimse/src/tba_tests_interop_wimse/factors.toml) declares the available choices. The [exclusions](pkgs/tba-tests-interop-wimse/src/tba_tests_interop_wimse/exclusions.toml) remove combinations that cannot represent the intended case. Expected refusals remain in scope when the request can occur and the receiver should deny it.

A **typed flow execution** binds an ordered list of hops to participants, peer implementations, and an expected outcome. The original one- and two-call scenarios use `workload-call` hops with their original `ingress` and `enforcing` names where applicable. A gateway can receive one call and originate the next. Reversing two peers can produce a distinct execution.

| Arrows per execution | Typed flow executions |
| ---: | ---: |
| 1 | 2,043 |
| 2 | 11,544 |
| 3 | 129,257 |
| **Original matrix total** | **142,844** |

The [frozen manifest](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-all-tba-executions.json.gz) stores **published IDs** in the `workload_executions` and `planned_executions` arrays. Scenario-derived flows retain the original ID encoding the family, variant, decision layer, authentication bindings, and peer pins. Operation-path flows retain their `hop-v1:` IDs. Each planned typed-flow row records its ordered `hops` and `outcome_id`. Scenario-derived workload rows use their scenario and per-hop bindings to describe the case.

A fresh qualification snapshot can change endpoint pins and therefore the **runtime ID**. The planner joins each runtime case to its published ID and writes the mapping to `mapping.json.gz`. Look up stable cases by published ID. Use the runtime ID to find the corresponding JUnit observation.

The full manifest adds **1,136** generic RICH workload executions, **5,102** generic RICH typed-hop executions, and **12,288** assignments for the named nine-hop success case. That brings the published inventory to **161,370 IDs**. [Full execution manifest](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-executions.json.gz)

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

This table breaks down the 11,740 flows derived from the original workload scenarios by enforcing-hop profile and WIC ID. Each count includes all applicable peer assignments and both success and refusal variants. Two-hop flows in this subset count once under their enforcing hop. [Execution matrix and assignment fields](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-execution-matrix.md#peer-and-role-assignments)

To read a peer assignment, start with the ordered caller and receiver for each workload hop, then inspect their implementation, version, and configuration. The `wic_issuer` and `wit_issuer` choices are separate from the endpoint pair. For a gateway, check the ingress and enforcing assignments independently. Swapping caller and receiver changes which implementation presents the credential and which validates it, so the reverse direction needs its own control.

## Nine-hop success case across two trust domains

The named `ietf127-b-chain` flow models a two-domain request that ends in a protected file read. The Driver starts in Domain A. It gets the original transaction token in A and exchanges an audience-bound assertion at Exchange B. The original transaction token stays in A. The Coordinator and Research run in B with separate workload identities. [Pinned nine-hop reference and qualification](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-qualification.md)

```text
Domain A                         | Domain B
Driver --1--> Issuer A           |
Driver --2--> Ingress            |
Driver --3--> Exchange A         |
Driver --4-----------------------+--> Exchange B
Driver --5-----------------------+--> Coordinator
                                 | Coordinator --6--> Issuer B
                                 | Coordinator --7--> Research
                                 | Research ----8--> Issuer B
                                 | Research ----9--> File Tool
```

| Hop | Operation | What the flow checks |
| ---: | --- | --- |
| 1 | Driver → Issuer A | Issuer A binds the original transaction token to the Driver, ingress audience, scope, and file context. |
| 2 | Driver → Ingress | Ingress verifies the signed request and original transaction token before completing the text-stats workflow. |
| 3 | Driver → Exchange A | Exchange A verifies the signed request and original token, then issues an assertion for Exchange B. |
| 4 | Driver → Exchange B | Exchange B redeems the assertion for a Domain B access token. |
| 5 | Driver → Coordinator | Coordinator verifies the signed request and Domain B access token before starting the downstream calls. |
| 6 | Coordinator → Issuer B | Issuer B issues a transaction token bound to the Coordinator. |
| 7 | Coordinator → Research | Research verifies the signed request and the bound transaction token. |
| 8 | Research → Issuer B | The same Issuer B replaces the token, preserving the transaction ID and narrowing the scope for Research. |
| 9 | Research → File Tool | The File Tool verifies the WPT binding to both the WIT and the narrowed token, then authorizes exactly one protected file read. |

### Nine-hop role substitutions

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

The product of the choice counts is **12,288 assignments**, including **3,072** with Issuer A and Exchange A co-located and Exchange B and Issuer B co-located. See [nine_hop.toml](pkgs/tba-tests-interop-wimse/src/tba_tests_interop_wimse/nine_hop.toml) for admissibility rules and the manifest's `named_scenarios.ietf127-b-chain.role_candidates` for exact version and configuration tuples.

The pinned AgentMaurice workflow caller reserves the supplied `Txn-Token` header. Its qualified substitutions are Ingress and File Tool receivers. The pinned Authgent issuer uses a client identifier in `req_wl` and rejects the replacement grant required by this flow. See the [Authgent issuer controls](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-qualification.md#authgent-issuer-candidates). Cofide's [signature bridge](pkgs/tba-tests-interop-wimse/tests/support/nine_hop_cofide.md) uses an overlay to sign `wimse-aud`. The [TbA File Tool WPT fixture](pkgs/tba-tests-interop-wimse/tests/support/nine_hop_tba.md) opts in to preserving the exact empty-path audience.

The hosted run recorded **12,288 passed, 0 failed, and 0 blocked** for these success assignments. The `nine-hop-results` artifact maps the **27 qualified role bindings** and **94 qualified directional handoffs** to passing execution IDs. Qualification controls for refusals have separate evidence. [Hosted run](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/attempts/2)

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

<a name="hosted-outcomes-by-hop-count"></a>

See the [README results by planned hop count](README.md#hosted-outcomes-by-hop-count) for the one-, two-, three-, and nine-hop totals.

The [README results table](README.md#hosted-results) records run 44021013592, attempt 2. The [combined report](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/artifacts/14305462171) contains `summary.md`, `summary.json`, and `per-id.csv.gz`. Look up an `execution_id` in the CSV for its lane, outcome, and reason. Match the report's manifest digest to the inventory used for the run. GitHub artifact retention applies. The workflow summary also records the totals and blocker breakdown.

- **Passed** includes expected refusals where the case checks a refusal and its effects.
- **Failed** means the observed runtime result differed from the expected outcome.
- **Blocked** means execution could not reach a verdict. Inspect the per-ID reason for missing endpoints, handoffs, issuers, or other support roles. Setup failures and cases without results also count as blocked and are flagged as infrastructure outcomes. Attempt 2 had zero infrastructure outcomes.

All 182 failures were in the original matrix. Its 8,402 blockers were AgentMaurice bindings or signing controls (7,838), Redthread (284), and OmniArx (280). The two generic RICH groups had 1,717 blockers, including 880 cases with AgentMaurice companion endpoints or directions and 792 cases requiring source/destination token, accounting/resource, or status/effect fixtures. The report records the remaining support and adapter reasons per ID.

### Review individual executions

Download and extract `full-wimse-matrix-results`, then open `results.html` in a current browser. The viewer includes every audited ID. Filter by status, suite, planned hop count, distinct planned peer count, or one or more planned peers. Match any selected peer or require all selected peers. Search by published or runtime ID, scenario, hop sequence, or reason. Select a row's ID to see the exact result metadata, planned roles and pins, and evidence path when supplied. The peer and hop filters describe the planned assignment. A refusal or blocker can stop execution before a later planned peer is reached.

Open **Hop features** to filter by transport authentication, application credential, application proof, WIC identifier scheme, WIC issuer, or WIT issuer. Multiple checked values in a group are alternatives. One planned hop must satisfy all active groups. Use **Hop position** or **Hop receiver** to narrow the match, for example to the File Tool. These filters describe the plan. The results and evidence fields describe what ran.

**Direct test CA** is the baseline lab issuer for a WIC. **Lab WIT issuer** is the baseline issuer for a WIT. **SPIFFE URI** describes the certificate identifier scheme and can be paired with different WIC issuers. **Not applicable** marks an explicit `none` field. **Unavailable in report** marks a missing field. Select an execution ID for labeled hop details, and expand **Pins and evidence** for the exact fixture IDs, revisions, and report references.

The original CSV and summary remain available in the artifact. For an earlier artifact that has `per-id.csv.gz` and `summary.json` but lacks the viewer, regenerate it from the repository root using the matching frozen manifest.

```sh
python pkgs/tba-tests-interop-wimse/tests/render_execution_report.py \
  --manifest pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-executions.json.gz \
  --report path/to/full-wimse-matrix-results
```

The original-matrix workflow can also publish its audited aggregate to the
`interop-evidence` branch. Dispatch from `master` with `commit_evidence`
enabled. Shards upload their own evidence and the report job writes once
after aggregation under `runs/<run-id>/attempt-<attempt>/`. The full-matrix
workflow uploads its combined report as a workflow artifact.
