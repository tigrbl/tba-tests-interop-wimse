# TbA WIMSE interoperability

The installable harness lives in [pkgs/tba-test-interop-wimse](pkgs/tba-test-interop-wimse).
It owns the frozen 142,844-ID inventory, external adapters, and execution evidence.
Native TbA-to-TbA scenarios remain in the inventory. TbA T0–T3 tests live in
[tigrbl_auth](https://github.com/tigrbl/tigrbl_auth).

The [frozen manifest](pkgs/tba-test-interop-wimse/matrix/wimse-interop-all-tba-executions.json.gz)
and [closure plan](pkgs/tba-test-interop-wimse/matrix/wimse-runtime-closure-plan.md)
record the inventory and outstanding qualification. Historical artifacts retain their original
runtime pins. The [Cred acceptance test](pkgs/tba-test-interop-wimse/tests/peer/test_cred_wit_wpt_acceptance.py)
covers the seven protected-endpoint controls alongside the matrix, with no new canonical IDs.


Read the published inventory from the repository root with:

```sh
tba-test-interop-wimse --frozen-manifest pkgs/tba-test-interop-wimse/matrix/wimse-interop-all-tba-executions.json.gz
```

An expansion with a different peer snapshot can produce different runtime IDs. Keep
the frozen manifest and runtime evidence together and use the supplied blocker
and batch reports to reconcile logical cases across pin changes.

The core wheel installs independently. For the native fixtures, download the interop wheel and the TbA runtime wheels from the same GitHub release into one directory, then install with `uv pip install --find-links . 'tba_test_interop_wimse-0.4.0.dev2-py3-none-any.whl[wic,wpt,spiffe-wic]'`. The runtime wheels supply the source revisions required by the fixtures.
