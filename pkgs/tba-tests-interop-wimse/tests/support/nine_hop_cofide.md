# Cofide in the B_CHAIN fixture

`support.nine_hop_cofide.build_bindings(context)` registers the matrix pin
`cofide / 7984a60105002dc65b31e9cd08572cd5d10ed9d6 /
shared-python-tls-direct-ca-ledger-v1`. The shared runner supplies `context["wimse"]`.
Set `TBA_WIMSE_NINE_HOP_COFIDE_BRIDGE` to the absolute path of the separate
nine-hop binary; the existing two-peer Cofide bridge has a different protocol.

| Role | Cofide proof operation | Shared fixture operation |
| --- | --- | --- |
| Driver | `http_sig`; one WIT and confirmation key for all three signatures | Enroll the workload, issue its WIT, send requests and check the result |
| Ingress | `verify_wimse_proof`; verify signature, coverage, digest, and audience | Validate WIT against the configured trust bundle, check the transaction token, and run text-stats |
| Coordinator | `verify_wimse_proof` on the driver request; `http_sig` on Research with T_B1 | Validate WIT and AT_B, obtain T_B1, and relay the Research result |

The bridge calls the pinned Cofide
[`shared.GetWITHTTPSigner`](https://github.com/cofide/wimse-s2s-httpsig-poc/blob/7984a60105002dc65b31e9cd08572cd5d10ed9d6/wimse/shared/httpsig.go).
Signature verification calls the same pinned
[`NewP256Verifier` / `VerifyRequest` dependency used by the Cofide server](https://github.com/cofide/wimse-s2s-httpsig-poc/blob/7984a60105002dc65b31e9cd08572cd5d10ed9d6/wimse/server/server.go).
It also uses that dependency to generate and verify SHA-256 Content-Digest. The
Go process receives the exact request bytes, headers, logical audience and P-256
confirmation key. A process failure is surfaced; there is no fallback signer.

## Build and run

With Go 1.25.3, from the harness checkout root, with an adjacent pinned Cofide
source checkout in `.interop/cofide`:

```sh
test "$(git -C .interop/cofide rev-parse HEAD)" = 7984a60105002dc65b31e9cd08572cd5d10ed9d6
mkdir -p .interop/nine-hop-cofide-build
cp .interop/cofide/go.mod .interop/cofide/go.sum \
  pkgs/tba-tests-interop-wimse/tests/support/nine_hop_cofide_bridge.go \
  .interop/nine-hop-cofide-build/
(
  cd .interop/nine-hop-cofide-build
  go mod edit -module=interop-ci.invalid/nine-hop-cofide \
    -require=github.com/cofide/wimse-s2s-httpsig-poc@v0.0.0 \
    -replace=github.com/cofide/wimse-s2s-httpsig-poc=../cofide
  go build -mod=mod -o ../nine-hop-cofide-bridge .
)
export TBA_WIMSE_NINE_HOP_COFIDE_BRIDGE="$PWD/.interop/nine-hop-cofide-bridge"
python pkgs/tba-tests-interop-wimse/tests/support/nine_hop_cofide_smoke.py \
  .interop/ietf127 "$TBA_WIMSE_NINE_HOP_COFIDE_BRIDGE"
```

The runner dispatches `http_sig(method, url, body, wit, wkey, *, aud, headers)`
and `verify_wimse_proof(method, path_and_query, headers, body, trust_jwks, *,
expected_aud)` with the same interfaces as the pinned Python fixture.
The bridge is stateless and accepts one JSON object on stdin, with the body
encoded in Base64.

## Wire compatibility

Cofide sends `@method`, `@request-target`, `@authority`, WIT, content type,
body digest, and any transaction or authorization headers as signed components.
The signed authority is the expected logical audience authority, also sent as
the HTTP Host. The TCP connection stays on loopback. A receiver must compare that
Host against its configured audience before using it as verification context.

The pinned `httpsign` v0.3.1
[`SignConfig`](https://github.com/yaronf/httpsign/blob/v0.3.1/config.go) has no
extension for setting the draft-08 `wimse-aud` signature parameter. The
[unchanged IETF receiver](https://github.com/apelov/IETF127-Hackathon-AI2II-WIMSE/blob/49d29ca31d248af4a169176969e712c673f11ef9/peers/wimse.py)
requires that parameter, rejects `keyid`, and requires `@path` and `@query`.
Therefore its source exchange or Research cannot accept a Cofide-produced
signature. Cofide's verifier *can* accept the reference format: the adapter
checks `wimse-aud` and configures the Go verifier for the incoming derived
component list. These are separate directional results.

TbA's native verifier can independently verify the Cofide format when the
receiver configuration opts into it. A local check with TbA v0.4.0.dev2
accepted Cofide's actual wire bytes by checking Host against
`urlsplit(expected_aud).netloc` and selecting
`derived=("@method", "@request-target", "@authority")`,
`authority=urlsplit(expected_aud).netloc`, `binding="keyid"`,
`expected_binding="wimse"`, and `required_algorithm="ES256"` in
`_authenticate_signature`. Any receiving peer should own its verification;
routing a reference receiver through Cofide would not qualify that handoff.
