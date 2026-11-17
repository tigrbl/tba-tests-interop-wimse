# TBA WIMSE interop tests

This interoperability project contains the WIMSE scenario definitions, peer execution plans, and rules for counting combinations.

See the [interop guide](../../INTEROP.md) for the full 161,370-ID inventory, hosted results, and current peer qualification.

| File | Purpose |
| --- | --- |
| [Coverage workbook](matrix/wimse-interop-coverage.xlsx) | Factor levels, raw Cartesian matrix, and planned runs |
| [Scenario matrix](matrix/wimse-interop-scenario-matrix.md) | Scenario variants, expected decisions, and observable effects |
| [Execution matrix](matrix/wimse-interop-execution-matrix.md) | Candidate peers, versions, roles, and directions |
| [Factor catalog](src/tba_tests_interop_wimse/factors.toml) | Factor levels and required pairings, bundled in the wheel |
| [Exclusions](src/tba_tests_interop_wimse/exclusions.toml) | Incompatible combinations, bundled in the wheel |
| [Scenario catalog](src/tba_tests_interop_wimse/scenarios.toml) | Named hops, variants, expected event order, decisions, and effects |
| [Peer catalog](src/tba_tests_interop_wimse/peers.toml) | Endpoint capabilities by implementation, role, profile, and identifier scheme |
| [All-TbA baseline plan](matrix/tba-native-baseline.md) | Native role readiness, package work, and matrix changes for TbA-only flows |
| [Full runtime closure plan](matrix/wimse-runtime-closure-plan.md) | Counted delivery tranches and evidence required for the 142,844-ID inventory |
| [Per-ID blocker report](matrix/wimse-interop-per-id-blockers.csv.gz) | Runtime and published IDs, historical evidence, and binding gaps |
| [External peer access](matrix/wimse-external-peer-access.md) | Public artifacts and sandbox dependencies for proposed peers |
| [RICH and nine-hop candidate inventory](matrix/wimse-interop-rich-nine-hop-executions.json.gz) | The 161,370-ID additive matrix |
| [Nine-hop qualification](matrix/wimse-interop-rich-nine-hop-qualification.md) | Generation command and contracts for running the named success case |

From this package directory, run `uv run tba-tests-interop-wimse`. After installing the wheel, run `tba-tests-interop-wimse` or `python -m tba_tests_interop_wimse`. The command loads the TOML files from the installed package.

The bundled catalogs declare their schema with the SemVer string `schema_version = "1.0.0"`. The loader accepts that exact version. Advance the schema version when the catalog format changes, and update the loader to support it.

Give each factor a stable key under `[factors.<key>]`, a display name, and a list of levels. Each rule has an `id`, a `basis`, and a `when` predicate. When it matches, the `requires` predicate must hold or the `excludes` predicate must be false. Predicates can test a factor's level with `{ factor = "tls", in = ["WIC mutual TLS"] }` or combine predicates using `all`, `any`, and `not`. Keep expected denials in the scenario matrix when a request can occur and the verifier is expected to reject it.

The default command reports scenario families, endpoint capabilities, structural scenarios, and pending and qualified execution rows. Use `--json` to export the generated data and `--legacy-count` to reproduce the flat workbook count. The workbook's Generated Scenarios, Generated Executions, and Peer Capabilities sheets reflect the scoped model. Its Cartesian Matrix and Planned Runs sheets preserve the earlier flat model.

The generator expands authentication settings and issuer modes on each named hop. A terminating or chained call joins the receiving implementation on one hop to the calling implementation on the next. Its scenario variants define the fault target and ordered events. In the bearer fixture, a denied provider call stays in scope when the expected trace has no release. If a structurally valid scenario lacks a matching peer chain, it remains in Generated Scenarios without an execution row.

Qualify a peer capability by entering an exact version and evidence. A capability covers one profile, one role, and one identifier scheme. To qualify issuer or other support roles, add an entry under `qualified_support` in `peers.toml` keyed by the role reported in the execution output. Each entry must include its implementation, version, and evidence. Both endpoint capabilities and all support roles must qualify before an execution row qualifies.

Qualification also requires a configuration pin on each capability and support role, and a passing `[[baselines]]` record for each ordered caller/receiver pair. Each baseline has `outcome = "pass"`, an `evidence` reference, and `caller` and `receiver` tables with implementation, version, configuration, profile, and identifier scheme.

Each hop profile declares `application_proof` in `factors.toml` with one of three levels: `None`, `WPT`, or `HTTP Message Signatures`. Generated scenario hops expose the same field and the execution workbook displays it as **Application proof** per hop. The generated `proof` field retains the earlier combined credential and proof labels for existing consumers.

The [hop catalog](src/tba_tests_interop_wimse/hops.toml) defines five interaction types and the rules for composing them. Run `tba-tests-interop-wimse --hop-matrix` to reproduce the [155-row hop sequence matrix](matrix/wimse-interop-hop-matrix.csv). Add `--json` for the type definitions and composition rules.

The matrix enumerates all ordered type sequences of length one through three. **Mapped** rows already link to structural scenarios. **Proposed** rows have a concrete example awaiting a modeled scenario and execution support. **Unreviewed** rows still need an applicability decision. The binding gaps on unmapped rows describe the roles and inputs that must be declared. A zero candidate count on an unmapped row measures the current catalog and leaves its applicability undecided.

Supply `--peer-snapshot PATH` to count qualified runs in a lab snapshot. To verify which runs actually passed, audit the matching JUnit report with `--audit-peer-junit`.

The [peer catalog](src/tba_tests_interop_wimse/peers.toml) records external integration candidates under `[implementations]`. Add `--include-candidates` to the hop plan to expand proposed endpoint profiles and explicitly modeled support operations. The [expanded hop and peer matrix](matrix/wimse-interop-hop-peer-expansion.csv) counts them by sequence. The proposal overlay preserves existing qualified bindings. Proposed endpoints and support roles require their own runtime evidence.

Run `tba-tests-interop-wimse --expand-hops --peer-snapshot PATH` for the [constrained execution plan](matrix/wimse-interop-hop-expansion-plan.csv). The planner evaluates every sequence against the lab operations in `hops.toml`. A flow needs a declared initial input, allowed operation transitions, and a complete final operation. Compatible workload pairs use the snapshot's profile and issuer options. A workload role keeps the same endpoint pin throughout its flow. Support operations use the declared lab roles and can require the TbA implementation or a specific profile on the next call.

Each admitted assignment gets a success control and one case per applicable refusal. A refusal stops the flow at its decision hop with zero effects. For this lab plan, operations that can commit an effect wait for the final authorization before doing so. The planner reuses the existing scenario catalog for bare one- and two-call flows. Add `--json` to export every new planned execution ID, its ordered hop bindings, and its oracle. Planned IDs need runtime adapters and outcome evidence. A sequence excluded by these lab contracts can become eligible when new contracts are added.

From this package directory, export every workload and typed-hop ID against the same qualification snapshot you will use for pytest.

```powershell
$env:TBA_WIMSE_PEER_SNAPSHOT = (Resolve-Path path/to/qualification.json).Path
$env:TBA_WIMSE_EXPANDED = "1"
tba-tests-interop-wimse --expand-hops --include-candidates --peer-snapshot $env:TBA_WIMSE_PEER_SNAPSHOT --json > matrix/expanded-executions.json
python -m pytest -o junit_family=xunit1 tests/peer/test_candidate_executions.py --junitxml=matrix/expanded-results.xml
tba-tests-interop-wimse --expand-hops --include-candidates --peer-snapshot $env:TBA_WIMSE_PEER_SNAPSHOT --audit-peer-junit matrix/expanded-results.xml
```

Set `TBA_WIMSE_EXECUTION_ID` to a full ID from `workload_executions` or `planned_executions` to run one case. The full suite uses the peer lab prerequisites below for qualified workload runs. Typed adapters register under their ordered operation path and must match the assigned bindings before returning observed reached hops, decision hop, result, and effects. The included local adapters cover stand-alone status and delegation. Missing bindings produce a per-ID blocked result. The JUnit audit requires individual pass evidence for the entire plan and returns a nonzero exit code when any ID is blocked, failed, or missing.

Set `TBA_WIMSE_HOP_PATH=call,call,call` with expanded collection enabled to select the three-workload-call flow. The chain uses the pinned peer lab and requires a qualified directional baseline and issuer for every call. A single request starts the chain, and authenticated intermediate receivers forward it. The final workload owns the only write. The report includes the HTTP decision at each reached hop and the observed ledger count.

Add `--include-native` to the expanded export or audit and set `TBA_WIMSE_INCLUDE_NATIVE=1` for pytest to include the all-TbA runs. With the Cred qualification snapshot and `--include-candidates`, the [combined manifest](matrix/wimse-interop-all-tba-executions.json.gz) contains 142,844 distinct IDs. The [sequence counts](matrix/wimse-interop-all-tba-expansion.csv) include native workload and typed runs. Set `TBA_WIMSE_FROZEN_MANIFEST` to the combined manifest to require the runner to reproduce every frozen ID from the selected snapshot before collection. The plan counts a shared local-only scenario once. Native X.509-SVID and WIT-SVID issuer names and the TbA replacements for external support services denote planned bindings.

The native three-workload-call adapter uses separately configured TbA endpoints with baseline issuers. Its runtime snapshot must carry the digest of the current TbA fixture source. Generate a fresh snapshot after changes to those sources and use the same snapshot to generate IDs, run pytest, and audit JUnit. New issuer and support-role adapters need independent runtime evidence before their IDs can pass.

With the peer lab dependencies loaded, `python tests/run_three_call_batch.py --help` shows how to run the remaining existing-peer three-call cases from the frozen snapshot and prior pilot report. The driver records its selected IDs, writes each observed result to `attempts.jsonl` as it runs, and writes JUnit on completion. Use `python tests/expanded_blockers.py --help` to refresh the per-ID blocker export from the published manifest, pinned snapshots and runtime reports, and the live attempt log.

The [native WIT-SVID controls](matrix/wimse-native-wit-svid-controls.xml) exercise TbA issuance and presentation across six proof and transport profiles. They are component evidence for the issuer integration and are kept separate from candidate execution results.

After refreshing the pinned peer snapshot, collect JUnit evidence from the native WIT-SVID issuer controls for that runtime, using `-o junit_family=xunit1`. Pass the resulting XML and snapshot to `python tests/run_native_wit_svid_batch.py --help` for the arguments to run the 16,710 native WIT-SVID-only cases. The driver checks the six issuer controls, records the runtime snapshot and selected IDs, and audits the one-, two-, and three-hop results against that snapshot. Set `TBA_WIMSE_NATIVE_WIT_ONLY=1` with expanded native collection enabled to select the same scope from pytest.

For the 6,261 X.509-SVID-only cases, collect the native X.509-SVID issuer control JUnit report and pass it with the pinned snapshot to the same driver with `--issuer tba-x509-svid`. The runtime uses freshly minted TbA X.509-SVIDs on the selected SPIFFE mTLS hops, with the baseline application-proof issuer where applicable. `TBA_WIMSE_NATIVE_ISSUER=tba-x509-svid` selects this scope from pytest.

For the 23,878 cases using both native issuers, collect the combined issuer controls and both component control reports against the same fixture version. Pass the combined JUnit report as `--controls`, the two component reports as `--wit-controls` and `--x509-controls`, and select `--issuer combined`. The scope includes both credentials on the same request and credentials used on separate hops in the same flow. `TBA_WIMSE_NATIVE_ISSUER=combined` selects this scope from pytest.

Use `python tests/run_typed_service_batch.py --help` for the 21,140 typed service cases. Run with `--qualify` first to check each operation path and outcome with its assigned native or existing peer bindings. Pass the resulting JUnit file as `--qualification-results` to run the entire slice against the same pinned snapshot. The suite uses the local status, delegation, exchange, and bearer services and the pinned SPIRE Agent Workload API. The agent returns the workload certificate, key, and bundle used by the next call. The results record reached hops, stop reasons, and resource effects per ID.

Use the same runner with `--native-acquisition` for the 627 native credential-acquisition executions. Install `grpcio==1.85.1` and `protobuf==7.36.2` in the test environment alongside the TbA workspace packages. The TbA fixture implements `FetchX509SVID` over a loopback gRPC stream. It derives workload selectors from mutually authenticated fixture certificates. This setup qualifies the X.509 acquisition flow on Windows without depending on platform-specific process attestation. The workload uses the returned certificate, key, and bundle for the next mTLS call. The evidence records both the SHA-256 fingerprint returned by the Workload API and the fingerprint observed by the receiver.

Use `--specialized-acquisition` for the 105 native executions where that mTLS call depends on a terminal policy decision. The local services cover issuer and holder revocation, revocation before commit, delegation status, and approval display verification. The workload receiver writes to its ledger only after an allow decision. The same `--qualify` and `--qualification-results` steps apply to this tranche.

To run the 728 short native workload cases with baseline credentials, capture JUnit evidence from the native baseline workload controls using `-o junit_family=xunit1`. Pass that evidence as `--controls` to `tests/run_native_baseline_workload_batch.py` with `--snapshot` pointing to the current pinned peer snapshot and `--output` to a new result directory. These cases exercise the existing scenario oracles for the enforcing hop, event order, writes, and releases.

Use `tests/run_native_baseline_policy_batch.py` for the 2,396 specialized flows with baseline credentials. Supply the baseline profile JUnit file as `--profile-controls` and the current peer snapshot as `--snapshot`. Run `--qualify` first, then supply its JUnit report as `--qualification-results` for the full tranche. The loopback services run transaction-token issuance, delegation receipt verification, and terminal policy checks with the existing workload fixtures.

Add `--svids`, `--wit-controls`, `--x509-controls`, and `--combined-controls` to the same runner for the 8,775 specialized flows that use native SVIDs. Supply the WIT-SVID, X.509-SVID, and combined issuer JUnit reports for the pinned runtime. The per-ID runtime trace includes the fingerprint and verification outcome for each native SVID seen by a receiver.

Use `tests/run_go_spiffe_batch.py` for the external SPIFFE workload cases. Build the pinned module in `tests/support/go_spiffe_bridge/` for the host and for Linux. The Linux binary checks credential acquisition directly against the local SPIRE Agent. The host binary independently verifies the presented X.509-SVID and SPIFFE ID in the shared mTLS fixture. Install the locked dependencies for `tests/support/defakto_bridge/` with `npm ci --ignore-scripts`, then pass its `verify.mjs` as `--defakto-bridge` to qualify Defakto's SDK verification and select Defakto-only and mixed go-spiffe cases. The optional external support services remain separate qualification dependencies.

Install the locked dependencies in `tests/support/emilia_bridge/` with `npm ci --ignore-scripts` and pass `check.mjs` as `--emilia-bridge` to select the 64 go-spiffe and Defakto workloads that require the EMILIA service. The runner qualifies Gate's provider-entry allow and refusal behavior before it runs the workload cases.

Generated scenarios and peer runs expose `hop_count` and `hop_sequence_id` for the workload calls explicitly modeled by that row. A status lookup or provider call handled inside a current fixture does not become an extra hop in this report until modeled as an explicit arrow. The existing peer join expands mapped scenarios into executions. The flat catalog's `second_hop` factor still describes an authentication profile and has no role in multiplying hop type sequences into peer runs.

## Verification

Dispatch `full-matrix.yml` for the 161,370-ID inventory on GitHub-hosted
Ubuntu. It runs the 142,844 baseline and 12,288 named nine-hop executions in
parallel. The aggregate artifact `full-wimse-matrix-results` reconciles every
published ID. The 6,238 generic RICH cases run in the baseline shards after
four live directional controls qualify the pinned Research and Coordinator
proof adapters. The report records unavailable companion endpoints and
support operations with their assigned roles and hop sequences.

Use the [frozen manifest](matrix/wimse-interop-all-tba-executions.json.gz) to check the 142,844-ID inventory, including native TbA-to-TbA and external peer cases. Run peer components and matrix executions against pinned endpoints. Keep qualification controls separate from per-ID execution results.

The following paragraph records the original spreadsheet snapshot and its qualification status. Current results and blockers are in the [hosted run summary](../../README.md#hosted-results).

The 3,148 structural keys are exhaustive for the options declared by the current templates. The 20 flat axes are retained for comparison and are not all active independent axes in the templates. Runtime adapters and qualifying evidence for the remaining profiles and families are pending. No external peer pair is qualified. The spreadsheet is a snapshot of the current candidate inventory.

## Candidate peer runs

### Run either side of the WIC/mTLS fixture

Install the package with the `wic` extra using the selected TbA wheels. For
example, with a fixture wheelhouse use
`pip install --no-index --find-links ./wheelhouse "tba-tests-interop-wimse[wic]==0.4.0.dev2"`.
The Python API exposes `WicCaller`, `WicReceiver`, and `WorkloadVerifier` from
`tba_tests_interop_wimse.wic`. `WorkloadVerifier` accepts a certificate status
provider. `WicReceiver` accepts a resource implementing `commit(identity)`
and `snapshot()` and defaults to an in-memory ledger.

Give each role a JSON configuration with its own leaf and key, the TLS trust
anchor, its expected peer URI, and explicitly approved peer leaf certificates.
The fixture currently accepts direct issuance by the configured domain anchor.
Example caller configuration:

```json
{
  "tls": {
    "certificate": "caller.pem",
    "private_key": "caller.key",
    "trust_anchor": "test-ca.pem"
  },
  "expected_peer": "wimse://example.org/receiver",
  "domain_anchors": {"example.org": "test-ca.pem"},
  "good_certificates": ["receiver.pem"],
  "host": "127.0.0.1",
  "port": 8443,
  "dns_name": "receiver.example.org"
}
```

For the receiver configuration, supply its leaf and key, the expected caller
URI, and the caller certificate under `good_certificates`. Match the server
leaf's DNS SAN to the caller's `dns_name`. Run:

```sh
tba-wimse-wic-fixture receive receiver.json
tba-wimse-wic-fixture call caller.json
tba-wimse-wic-fixture readback caller.json
```

The receiver listens on loopback and prints its port as JSON. Use `"port": 0`
to allocate one automatically. A partner caller can use its own mTLS client to
send `POST /writes` and `GET /effects`. A partner receiver can implement those
same endpoints for the TbA caller. An allowed write returns HTTP 201 and the
authenticated workload URI. Readback returns HTTP 200 and the committed
identities. A workload identity refusal after a TLS handshake returns HTTP 403
from the receiver, or a `server-identity` denial from the TbA caller. If a
partner receiver provides a different contract, use its own resource readback.

### Run either side of the WIT/WPT fixture

Install `tba-tests-interop-wimse[wpt]` from the selected wheelhouse. Import
`WptCaller` or `WptReceiver` from `tba_tests_interop_wimse.wpt`, or use
`tba-wimse-wpt-fixture receive receiver.json`, `call caller.json`, and
`readback caller.json`. The receiver binds loopback. Both roles share the
WIC fixture's protected write and readback routes. HTTPS authenticates the
server by its DNS name. TbA authenticates the caller using WIT/WPT.

Receiver JSON takes `certificate`, `private_key`, `dns_name`, optional
`port` (zero selects a port), and `trust_by_domain` (a map from trust domain
to trusted issuer JWKs). Caller JSON takes `host` (defaults to loopback),
`port`, `dns_name`, `trust_anchor`, `wit_file`, and `private_key` (the PEM
proof key bound to the WIT). TLS file paths and key files are supplied by the
operator. The receiver checks the audience against its configured DNS name,
listening port, and the requested fixture route.

The native interoperability baseline uses TbA for both endpoints with separate TLS, issuer,
and proof keys. It exercises all five profiles and all eight profile/scheme
configurations in the baseline inventory. The 52 structural rows include
positive writes and readback, applicable identity and proof refusals, replay,
and the combined-profile identity equality policy. The replay case verifies
one committed write and no additional effect from the duplicate.

For WIT/HTTP signatures, use `SignatureCaller` and `SignatureReceiver` from
`tba_tests_interop_wimse.httpsig`. This is the Ed25519, single-signature,
bodyless GET/POST subset of [the WIMSE HTTP signature draft -08](https://www.ietf.org/archive/id/draft-ietf-wimse-http-signature-08.html).
It does not implement signed responses, CONNECT, or the general signature
grammar. For a composition, use `CombinedCaller` with a WIC verifier and
the selected application caller. Supply both transport credentials and a
client verifier to the receiver. It requires the identities to be equal or
to match an exact configured pair. Use the `spiffe-wic` extra alongside
`wic` for `SpiffeWicVerifier`. The mixed SPIFFE setup keeps the WIT in the
native WIMSE namespace and configures the corresponding pair explicitly.
The SPIFFE client authenticates the expected workload URI after TLS chain
validation. The native WIMSE fixture also validates the TLS DNS name.

### Run the candidate inventory

Run `tba-tests-interop-wimse --coverage` for a JSON inventory of every
structural scenario and peer execution ID. Add `--attempts attempts.json`
to reconcile peer results. The file is a JSON array with an `execution_id`,
positive integer `attempt`, and `status` per entry. Component tests are
evidence for the behavior they exercise and do not populate this file as
complete execution attempts.

The first component slices are opt-in:

- Set `TBA_WIMSEY_CHECKOUT` to a checkout of
  `56b070582f3e380c5006630698fb4ca808c08b04` built with
  `cargo build --locked -p wimsey-cli`. Run
  `tests/peer/test_wimsey_wic_component.py` with the
  WIC dependencies and workload certificate fixture available. This pairs
  the wimsey WIC verifier with TbA's verifier over the shared TLS fixture,
  recording which engine made the decision at the checked endpoint.
  `tests/peer/test_wimsey_http_signature.py` verifies request signatures
  in both directions against the same pinned CLI with synthetic inputs.
- Set `CRED_SDK_CHECKOUT` to the built revision described in the Cred
  testkit README and make that testkit and its WIT/WPT dependencies
  available. Run `tests/peer/test_baselines.py`. This exercises the pinned
  Cred verifier over loopback HTTP and checks the protected read response
  for the control, proof refusals, and duplicate presentation.

These checks belong to the external interop evidence track. The fixture
manifest identifies them as component bindings. Complete
candidate runs still require the pinned endpoint configuration and
directional baseline defined in the peer catalog.

From the repository root, run:

```sh
python -m pytest pkgs/tba-tests-interop-wimse/tests/peer --collect-only -q
python -m pytest pkgs/tba-tests-interop-wimse/tests/peer -o junit_family=xunit1 --junitxml=peer-runs.xml
```

For full-inventory validation, report only the candidate execution tests and
audit their results against the current catalog:

```sh
python -m pytest pkgs/tba-tests-interop-wimse/tests/peer/test_candidate_executions.py -o junit_family=xunit1 --junitxml=candidates.xml
tba-tests-interop-wimse --audit-peer-junit candidates.xml
```

The audit exits 1 for an incomplete inventory. Use `--json` with the audit
to include each execution's status and observations.

For a local peer lab run, put the package's `src` and `tests` directories
on the Python path and configure `TBA_WIMSEY_CHECKOUT` and
`TBA_WIMSE_PEER_SNAPSHOT` (an output JSON path). Run
`python -m support.qualification_overlay` before pytest. This runs four
positive controls for the native WIMSE and SPIFFE WIC configurations,
in both directions, and captures the exact fixture source and wimsey
binary digests. It also records qualification of the ephemeral direct
test CA for that WIC configuration. The peer suite consumes the snapshot
through the same environment variable. Pass its path to the auditor
with `--peer-snapshot` so evidence is matched to the pinned execution IDs.
These results describe the pinned local lab configuration.

The direct WIC lab adapter also runs scenarios 09, 10, 11, 13, and 16
with baseline CA trust in both TbA/wimsey directions and both identifier
schemes. Peer verifiers run over mutual TLS. The shared test resource
owns the application policies, including synthetic delegation status,
protected operations, child grants, and tool and build claim checks.
The harness checks the rejection reason and reads back the resource
ledger over HTTPS after each policy request.

The same lab snapshot qualifies the shared support fixtures for gateway
origin handling, token exchange, revocation before effect, shared
accounting, approval display, and bearer release. Qualification executes
issuer controls in both directions and exercises every supported policy
variant before recording a role. The approval fixture verifies the
published V5 and R2 vectors from OASNT draft -02 Appendix A against its
enrolled test key and fixed clock.

Set `TBA_WIMSE_SPIRE=1` when building the snapshot to include the
SPIRE issuer. The lab uses the pinned local SPIRE 1.16.0 server image in a
disposable container with no external network. It exercises server-minted
X.509-SVIDs and their trust bundle. For malformed SAN and foreign domain
cases, it injects a separate fixture leaf into the peer input while keeping
the receiver's SPIRE workload trust pin. The issuer role covers the
server-mint path. Agent attestation and Workload API delivery are outside
that qualification. Cross-domain application issuers, budget and status
authorities, and the bearer provider are local test fixtures.

Set `TBA_WIMSE_COMBINED_SIGNATURE=1` to fill the combined-signature
candidate slot for the SPIFFE profile in the lab snapshot. In each direction
the control sends a signed write and independently reads the ledger over
mutual TLS. The wimsey side uses its pinned WIC verifier and HTTP signature
CLI. The shared fixture supplies the HTTPS resource, replay state, and
the mapping between the authenticated SPIFFE identity and the WIMSE WIT.
The controls cover the lab CA and, when enabled, SPIRE server-minted
X.509-SVIDs. Set `TBA_WIMSE_SPIRE_WIT=1` alongside
`TBA_WIMSE_SPIRE=1` to qualify the separate SPIRE WIT-SVID issuer. The
SPIRE server mints ES256 WIT-SVIDs with SPIFFE subjects, and the fixture
loads the matching WIT authority from the SPIFFE bundle. Separate
ephemeral SPIRE servers provide wrong-anchor and foreign-domain
credentials for denial cases. These controls exercise the SPIRE server
mint interface. Workload API delivery requires its own qualification.

Set `TBA_WIMSE_COMBINED_SIGNATURE_WIMSE=1` to qualify the WIMSE URI
variant in both directions. A lab CA issues the WIMSE transport
certificates. The application identity is either a lab-issued WIMSE
WIT or a server-minted SPIFFE WIT-SVID. The latter uses an explicit
mapping from the WIMSE transport identity to the SPIFFE subject.
When the other combined profiles are enabled, the support controls
exercise both orders of the eligible mixed-profile and mixed-identifier
chains.

The combined adapter also covers gateway origin handling, transaction
binding, delegated authority, proxy rewrites, cross-domain exchange,
revocation before effect, and gateway identity mapping. Its two-hop
controls exercise the supported arrangements of WIC-only and
combined-signature endpoints. The cross-domain token issuers, status
authority, effect store, and proxy handoff use local test fixtures.

Set `TBA_WIMSE_COMBINED_WPT=1` to also qualify the SPIFFE combined WPT
candidate slot with wimsey. This builds a small offline command-line
bridge against the pinned wimsey WIT and WPT crates. The bridge receives
the request's Txn-Token and destination access token and uses wimsey's
WPT binding APIs. The suite pins the bridge binary digest in the
qualification snapshot. Both directions exercise the four baseline
and SPIRE issuer combinations. The support controls also cover
chains with WPT, WIC-only, and HTTP-signature hops. The lab harness
provides HTTPS, replay state, the local support services, and ES256
proof signing on the TbA side for SPIRE-minted WIT-SVIDs.

Set `TBA_WIMSE_COMBINED_WPT_WIMSE=1` to qualify the WIMSE transport URI
variant in both directions using the same bridge. The lab CA issues
the transport certificates. The application proof uses a lab-issued WIMSE
WIT or a SPIRE server-minted WIT-SVID with a mapped SPIFFE subject.
With the other combined profiles enabled, qualification also exercises
WIMSE and SPIFFE hops together and both orders of the eligible mixed
WPT and HTTP-signature chains.

Set `TBA_WIMSE_COFIDE_BRIDGE` to the path of the compiled
`tests/support/cofide_bridge.go` executable to qualify Cofide in the
shared HTTPS lab. Build it in a temporary Go module using the pinned
Cofide checkout at `7984a60105002dc65b31e9cd08572cd5d10ed9d6` as the
replacement for `github.com/cofide/wimse-s2s-httpsig-poc`. Seed the
temporary module with the checkout's `go.mod` and `go.sum`, change its
module name, add a requirement on the replaced module, and build the
bridge with Go 1.25.3. The qualification snapshot pins the resulting
binary digest.

The bridge uses the prototype's Go signing function and its pinned
P-256 verification library. The lab profile signs the method,
request target, destination authority, WIT, and any applicable
authorization or transaction token headers. TbA checks the WIT issuer,
freshness, and replay state. The lab uses its own HTTPS endpoints and
support services. This qualification covers request signatures with
a lab-issued WIT or SPIRE server-minted WIT-SVID.

Set `TBA_WIMSE_CRED_CHECKOUT` to a clean Cred SDK checkout at
`586e1a76f487c2376e0ba0a4687bb2de8d3eb588` with its pinned dependencies
installed. Qualification builds Cred's identity modules and exposes its
demo client's signing function in a temporary adapter beside the snapshot.
The snapshot pins the generated modules and bridge. The adapter uses
Cred's WIT and WPT verification, with the lab supplying HTTPS, replay
state, token issuance and resource effects. Its caller signs the WPT for
the lab request URI and binds any transaction or destination access token.

The same checkout qualifies Cred independently as a second WIT + HTTP
Message Signatures peer alongside Cofide. For draft-08 requests, both
TbA → Cred and Cred → TbA exercise a baseline request, a request with a
valid signed transaction JWT, and a request with a second valid
transaction JWT substituted after signing. Each valid request records
one write. Each substitution fails signature verification and records
zero writes. These controls use direct HTTPS with a lab-issued WIT and
bodyless requests. To run them without building the other peers, run
`python -m pytest tests/peer/test_cred_http_signature.py` from the
package directory with `TBA_WIMSE_CRED_CHECKOUT` set.

After the candidate run, use
`python -m support.blocker_report snapshot.json candidates.xml` to count
remaining blockers. It reports the overlap between missing runtime
adapters, directional baselines, and issuer or support roles, so one row
can appear in several categories. Trust isolation is exercised by
holding the TLS CA fixed and varying the workload identity or its
configured workload anchor.

The native adapter registry is separate from the peer lab registry. The expanded inventory includes native cases with `TBA_WIMSE_INCLUDE_NATIVE=1`. Rows without a runtime binding appear as skipped.

Pytest collects one item per generated execution ID. A single test function joins
each row to its scenario and calls the same runner used by the pilot. The report
retains the full execution ID, scenario ID, and runner result. Blocked items are
reported as skipped with their reason. A skipped item provides no runtime evidence.

Register real peer bindings in the `peer_adapters` fixture. An adapter can cover
multiple variants and families. The runner checks qualification, checks adapter
support, reuses setup controls within each worker, and opens an isolated context
for each row. Its setup key must include every setting that affects the control,
including ordered peer and issuer pins, configuration, and topology. Local
reference adapters are separate from the peer lab bindings.

The 31 flat rules remain available for comparison through `--legacy-count`. In the scoped model, hop layout handles the topology rules. Profile expansion handles WIC URI and issuer applicability. Variant definitions handle transaction, authority, accounting, and event ordering. The peer join handles role and profile matching. The broker trace exclusion stays explicit in `exclusions.toml`.

| Flat rule IDs | Scoped owner |
| --- | --- |
| `chain-hops`, `direct-hops`, `gateway-hops`, `missing-origin-identity` | Named hop lists and gateway variants |
| `wic-uri-required`, `wic-uri-inapplicable`, `issuer-wit`, `issuer-wic` | Per-hop profile and issuer expansion |
| `wic-faults`, `application-faults`, `identity-comparison`, `signature-rewrite`, `token-binding` | Target hop, verification layer, and family profile list |
| `token-domain`, `child-grant`, `human-display`, `human-effect`, `protected-read-attempt`, `read-only-write` | Typed scenario topology and named variants |
| `shared-accounting`, `shared-counter` | Shared budget variants and explicit accounting and schedule levels |
| `bearer-release`, `post-release`, `denied-broker-no-release`, `fail-closed-broker-visible-revocation` | Ordered provider events and the broker trace exclusion |
| `peer-profile-1` through `peer-profile-6` | Capability matching by profile, scheme, version, and role |
