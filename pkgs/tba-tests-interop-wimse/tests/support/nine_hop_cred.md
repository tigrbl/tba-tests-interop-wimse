# Cred in the nine-hop success fixture

`support.nine_hop_cred.build_bindings(context)` registers the five Cred roles
with the shared runner. The runner supplies `wimse`, `workdir` and its
`ExitStack` as `stack`. Set `TBA_WIMSE_CRED_CHECKOUT` to a clean checkout of
`cred-ninja/sdk` at `586e1a76f487c2376e0ba0a4687bb2de8d3eb588` and provide
Node 24 on `PATH`. One Node subprocess per runner serves the proof operations
over stdin and stdout. The fixture transports all nine requests on loopback.

| Role | Cred operation |
| --- | --- |
| Driver | `signWimseRequest` covers body bytes and the applicable authorization headers. The adapter retains one WIT and confirmation key across its three signed requests. |
| Ingress | `verifyWimseRequestSignature` verifies the WIT, signature, coverage, body digest, and audience. `verifyTxnToken` verifies the Domain A token. |
| Coordinator | Cred verifies the incoming WIT and HTTP signature and the Access Token's JOSE signature. Cred signs the Research call with T_B1. |
| Research | Cred verifies the incoming WIT, HTTP signature and T_B1. The pinned hackathon client creates and signs the File Tool WPT, including both token hashes. |
| File Tool | `verifyWit`, `verifyWpt` and `verifyTxnToken` verify the Research identity, resource audience, both hashes and T_B2. |

The adapter applies the fixture's replay, workload, issuer, scope and file
checks, and supplies the `at+jwt` JOSE envelope and claim checks around Cred's
`verifySignature` primitive. The pinned fixture supplies enrollment, the two
token services, workflow logic and the synthetic file response. The build
exposes the Cred hackathon client's existing WPT constructor on its returned
object so the runner can supply the File Tool audience. The constructor's
hashing and signing code runs as published.

Local validation used the clean pinned checkout and Node 24.18.0. The all-Cred
workload substitution returned nine HTTP 200 responses. It observed all five
roles, one driver WIT across its three signed requests, a single transaction
ID, scope narrowing to `files:read`, both final WPT hashes, the expected
text-stats and research outputs, and one authorized `Q3.pdf` read. The
shared runner also observed all 12 sampled assignments covering each Cred
role individually and all five together, with reference and TbA token
services. These checks used localhost HTTP, with the hosted packet-capture
audit remaining part of matrix execution.
