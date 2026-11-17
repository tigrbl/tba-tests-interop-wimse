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
  httpsign=$(go mod download -json github.com/yaronf/httpsign@v0.3.1 | python -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')
  cp -R "$httpsign" ../httpsign
  chmod -R u+w ../httpsign
  patch --batch -d ../httpsign -p1 < ../../pkgs/tba-tests-interop-wimse/tests/support/nine_hop_httpsign_wimse_audience.patch
  go mod edit -replace=github.com/yaronf/httpsign=../httpsign
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

The nine-hop bridge still calls Cofide's pinned signer. An overlay on
`httpsign` v0.3.1 adds `wimse-aud` to the signed parameters. The bridge sends
`@method`, `@path`, `@query`, WIT, content type, body digest and applicable
transaction or authorization headers. Receivers verify their own signatures,
digests and exact configured audiences. The Cofide verifier also supports the
original authority-bound format with its existing Host and signature checks.

The local smoke test checks both the Cofide verifier and the unchanged IETF
reference verifier. The hosted report qualifies each peer direction from
the actual captured nine-hop executions.
