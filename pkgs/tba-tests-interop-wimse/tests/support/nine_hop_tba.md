# TbA B_CHAIN runtime binding

`support.nine_hop_tba.build_bindings(context)` supplies the nine role bindings to
`nine_hop_runtime.load_bindings`. The context supplies the already loaded
`wimse`, `domain_a`, and `domain_b` modules from fixture revision
`49d29ca31d248af4a169176969e712c673f11ef9`. Load the bindings before starting the
loopback listeners. The module uses the published candidate tuple for row
selection. The nine-hop HTTP fixture and cryptographic operations are what the
test executes. The candidate digest and configuration label originated in
the earlier TLS matrix.

| Role | Operation executed by TbA |
| --- | --- |
| Driver | Signs ingress, source exchange and Coordinator POSTs using one WIT and key |
| Issuer A | Signs the fixture's ingress-bound transaction token |
| Ingress | Verifies the WIT, signature and transaction JWT before the runner computes text stats |
| Exchange A | Verifies the signed body and Domain A transaction JWT, then signs the Domain B assertion |
| Exchange B | Verifies the source assertion under configured issuer keys and signs the destination access JWT |
| Coordinator | Authenticates the signed request and access JWT, then signs the request carrying T_B1 |
| Issuer B | Verifies the access JWT and prior transaction JWT, then signs T_B1 and narrower T_B2 using one issuer |
| Research | Authenticates the Coordinator's signature and T_B1, then creates a native WIT and WPT binding T_B2 |
| File Tool | Authenticates the research WIT and WPT, including both token hashes, then verifies T_B2 before the fixture reads |

The fixture retains the workflow, HTTP routing, scope derivation and file
effect. The adapter computes and checks the exact SHA-256 content digest and
selects the trusted keys, expected token types, claims and audiences. TbA's
WIMSE signature routines construct and verify covered components, authenticate
the WIT and reserve the proof nonce. The public signature wrapper is bodyless,
so this fixture calls the pinned internal routines with explicit body coverage.
The TbA receiving adapter also verifies Cofide's authority-bound signature form
using the configured audience's exact Host and signed derived components.
The TbA JOSE provider signs and verifies the compact JWTs. The pinned signer
supports EdDSA. The adapter adds one disposable Ed25519 key per issuer to the
fixture's in-memory trust bundles alongside its existing ES256 keys.

The hosted environment needs `tba-provider-replay-memory` from TbA revision
`c12980ae00260c356ced82f57fa92238a2b9f02a`, as used by the existing interop
workflow. Its `MemoryReplayCheckProvider.check_and_store` returns true for a
fresh proof. The locally installed PyPI wheel with the same package version
returned true for a duplicate and rejected fresh proofs. The HTTP signature,
WIT, WPT, JWT and JOSE package Python files used in the local test matched the
same revision.

The hosted wheel applies `nine_hop_tba_wpt_audience.patch` to the pinned WPT
profile. The patch exposes an opt-in to preserve an empty URI path. The
File Tool fixture opts in for both presentation and authentication, and
expects the exact signed audience `http://rich.ietf127.example:5063`. The
profile's default canonicalization is retained for other consumers.
The signature, replay checks and both token hashes are verified as before.

The runner provisions a disposable TbA Research issuer before starting
AgentMaurice. Its public key joins the existing Research trust bundle.
TbA signs its Research WIT with that key and includes the configured issuer
claim, so the receivers can verify the unchanged token bytes.

For local verification after running the upstream fixture's
`setup/gen_keys.py`, execute `tests/nine_hop_tba_local.py <upstream> <manifest>`
with the pinned dependencies. It exercises four published assignments using
the shared runner and real loopback HTTP. It checks the application-level
requests and responses. The hosted runner still owns independent packet
capture and final per-ID qualification.
