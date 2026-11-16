# TbA WIMSE interoperability

The installable harness lives in [pkgs/tba-tests-interop-wimse](pkgs/tba-tests-interop-wimse).
It owns the frozen 142,844-ID inventory, external adapters, and execution evidence.
The inventory includes native TbA-to-TbA scenarios and external peer scenarios.

The [frozen manifest](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-all-tba-executions.json.gz)
and [closure plan](pkgs/tba-tests-interop-wimse/matrix/wimse-runtime-closure-plan.md)
record the inventory and outstanding qualification. Historical reports retain their original
runtime pins and observations. Archived control reports use descriptive test labels. The [Cred acceptance test](pkgs/tba-tests-interop-wimse/tests/peer/test_cred_wit_wpt_acceptance.py)
covers the seven protected-endpoint controls alongside the matrix, with no new canonical IDs.


Read the published inventory from the repository root with:

```sh
tba-tests-interop-wimse --frozen-manifest pkgs/tba-tests-interop-wimse/matrix/wimse-interop-all-tba-executions.json.gz
```

An expansion with a different peer snapshot can produce different runtime IDs. Keep
the frozen manifest and runtime evidence together and use the supplied blocker
and batch reports to reconcile logical cases across pin changes.

To run the inventory on GitHub, open **Actions → WIMSE interop matrix → Run workflow**.
Leave `execution_id` empty to select all 142,844 published IDs, or enter one
exact published ID to run it alone. A full run uses 32 shards by default. Choose
4 to 64 shards, with up to 16 standard `ubuntu-latest` jobs in parallel and two
pytest workers per job. The prepare job qualifies the native TbA paths and the
pinned wimsey, Cofide, Cred, go-spiffe, Defakto, EMILIA, and Teleport fixtures.
Authgent's dedicated run is joined in the audit. AgentMaurice and MintID still
need their separate labs, and cases reaching unavailable vendor verifiers
remain in the inventory as blocked.

Each shard uploads its JUnit and pytest log as `interop-shard-*`. After the
shards finish, the report job audits the published-to-runtime ID mapping and
writes `interop-report` with a per-ID CSV, outcome counts, blocker reasons,
and checksums for the inputs and JUnit files. The aggregate and qualification
artifacts are retained for 30 days and raw shard artifacts for seven days.
Failures, setup failures, and missing results fail the workflow. Set
`require_all_pass` to also fail on blocked cases.

Select `commit_evidence` when dispatching from `master` to record the audited
aggregate under `runs/<run-id>/attempt-<attempt>/` on the `interop-evidence`
branch. The writer records complete reports even when they contain failures
or blockers. The GitHub token must be allowed to push to that branch. Each
run writes once after aggregation and retries a rejected fast-forward push
against the current branch tip. Shard jobs have read-only repository access.

The core wheel installs independently. Download it from a successful
[Build interop distribution run](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/build.yml).
To install the native fixtures before all their pinned TbA dependencies are
available on PyPI, build the missing wheels from the matching TbA source
revision and place them beside the interop wheel. Then install with
`uv pip install --find-links . 'tba_tests_interop_wimse-0.4.0.dev2-py3-none-any.whl[wic,wpt,spiffe-wic]'`.
