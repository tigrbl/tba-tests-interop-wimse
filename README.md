# TbA WIMSE interoperability

## Hosted results

[Run 44021013592, attempt 2](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/attempts/2) reconciled every ID on GitHub-hosted Ubuntu. **151,251 cases executed to a verdict**.

| Scope | Execution IDs | Passed | Failed | Blocked |
| --- | ---: | ---: | ---: | ---: |
| Original matrix | 142,844 | 134,260 | 182 | 8,402 |
| Generic RICH workload | 1,136 | 123 | 0 | 1,013 |
| Generic RICH typed hops | 5,102 | 4,398 | 0 | 704 |
| IETF 127 nine-hop success | 12,288 | 12,288 | 0 | 0 |
| **Full matrix** | **161,370** | **151,069** | **182** | **10,119** |

A pass means the observed result matched the expected outcome, which can include a refusal. A failure means execution produced a different result. A blocked case could not reach a verdict.

The nine-hop case exercises a protected file read across two trust domains. All published substitutions passed, covering **27 role bindings** and **94 directional handoffs**. The [interop guide](INTEROP.md) explains how to run the matrix and inspect the evidence. The [nine-hop guide](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-qualification.md) lists the substitutions and the checks at every hop.

Open [Full WIMSE interoperability matrix](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/full-matrix.yml) and select **Run workflow**. The defaults use 32 shards for the baseline and generic RICH cases and 16 for the nine-hop cases. The combined report is uploaded as `full-wimse-matrix-results`.

## Original 142,844-ID inventory

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

### Original matrix workflow

The workflow can still run the frozen original inventory. The setup description below records the earlier lab configuration. For current peer qualification and blockers, see the [interop guide](INTEROP.md#peers-and-evidence).

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

## Build, install, and publish

The core wheel installs independently. Download it from a successful
[Build interop distribution run](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/build.yml).
To install the native fixtures before all their pinned TbA dependencies are
available on PyPI, build the missing wheels from the matching TbA source
revision and place them beside the interop wheel. Then install with
`uv pip install --find-links . 'tba_tests_interop_wimse-0.4.0.dev2-py3-none-any.whl[wic,wpt,spiffe-wic]'`.
