# TbA WIMSE interoperability

<p align="center">
  <a href="https://github.com/tigrbl/tigrbl_auth#readme"><img src="https://raw.githubusercontent.com/tigrbl/tigrbl_auth/master/docs/assets/tba-brand.png" alt="TbA · Tigrbl Auth" width="360"></a>
</p>
<p align="center">
  <a href="https://pypi.org/project/tba-tests-interop-wimse/"><img src="https://img.shields.io/pypi/v/tba-tests-interop-wimse" alt="PyPI version"></a>
  <a href="pkgs/tba-tests-interop-wimse/pyproject.toml"><img src="https://img.shields.io/badge/Python-%3E%3D3.10%2C%3C3.16-3776ab" alt="Python requirement: &gt;=3.10,&lt;3.16"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-525252" alt="Apache-2.0 license"></a>
</p>
<p align="center">
  <a href="https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/build.yml"><img src="https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/build.yml/badge.svg?branch=master" alt="Build interop distribution"></a>
  <a href="https://pepy.tech/project/tba-tests-interop-wimse"><img src="https://static.pepy.tech/badge/tba-tests-interop-wimse/month" alt="Monthly PyPI downloads"></a>
  <a href="https://hits.sh/github.com/tigrbl/tba-tests-interop-wimse/"><img src="https://hits.sh/github.com/tigrbl/tba-tests-interop-wimse.svg" alt="Repository hits"></a>
</p>

This harness tests how TbA and other WIMSE implementations authenticate workloads, obtain and exchange credentials, and authorize protected operations across trust domains. It covers direct calls, one- to three-hop typed flows, and the IETF 127 nine-hop success case. The [interop guide](INTEROP.md) shows the hops, trust domains, peer capabilities, and exact execution examples.

## How coverage is built

The core catalog defines **20 scenario families**. Factoring their variants by topology, workload credentials, proofs, and issuer choices yields **3,148 structural scenarios**. Requirements and exclusions determine which factor levels can be combined. Expected refusals, such as a receiver rejecting a foreign credential, remain test cases when the interaction can occur.

Each execution binds the ordered hops to compatible peers and support services. A capability applies to a particular role, such as a caller presenting WIT with WPT, a receiver validating it, or an issuer supplying credentials. A binding also records the implementation version and configuration. Substituting a peer or reversing a call changes the binding and can produce a separate execution ID. The inventory enumerates every assignment admitted by the published scenario rules and peer pins. The runtime report shows which assignments actually ran. [Scenario model and peer assignments](INTEROP.md#from-a-use-case-to-an-execution-id)

## Peers covered by the matrix

| Role in the matrix | Peers and fixtures |
| --- | --- |
| Workload callers and receivers | TbA, wimsey, Cred, Cofide, go-spiffe, Defakto, AgentMaurice, RICH Coordinator, and RICH Research |
| Credential issuance and delivery | TbA, SPIRE, and Teleport tbot. The go-spiffe client also exercises credential acquisition. |
| Transaction tokens, status, and policy | TbA support fixtures, Authgent, MintID, and EMILIA |
| Named nine-hop reference roles | IETF 127 demo fixtures for the Driver, token services, and File Tool |
| Blocked external bindings | Redthread and OmniArx cases that require a runnable verifier or support operation |

Runtime evidence applies to the role, direction, and proof mode exercised with the pinned configuration. A passing result can be an expected refusal before a downstream role runs. See [peer roles, capabilities, and evidence](INTEROP.md#entities-peers-roles-and-capabilities) for the scope of each binding.

## Hosted results

[Run 44021013592, attempt 2](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/attempts/2) reconciled every ID on GitHub-hosted Ubuntu. **151,251 cases executed to a verdict**.

### By execution suite

| Scope | Execution IDs | Passed | Failed | Blocked |
| --- | ---: | ---: | ---: | ---: |
| Original matrix | 142,844 | 134,260 | 182 | 8,402 |
| Generic RICH workload | 1,136 | 123 | 0 | 1,013 |
| Generic RICH typed hops | 5,102 | 4,398 | 0 | 704 |
| IETF 127 nine-hop success | 12,288 | 12,288 | 0 | 0 |
| **Full matrix** | **161,370** | **151,069** | **182** | **10,119** |

### Hosted outcomes by hop count

Counts are execution IDs. Each ID represents a scenario and an applicable peer assignment. The table joins the 161,370-ID frozen manifest to the per-ID outcomes from run 44021013592, attempt 2. A case is grouped by its planned hop count, even if an expected refusal ends the observed trace earlier.

| Planned hops | Execution IDs | Passed | Failed | Blocked |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2,195 | 2,012 | 4 | 179 |
| 2 | 12,602 | 10,258 | 178 | 2,166 |
| 3 | 134,285 | 126,511 | 0 | 7,774 |
| 9 | 12,288 | 12,288 | 0 | 0 |
| **Total** | **161,370** | **151,069** | **182** | **10,119** |

The one-, two-, and three-hop rows include both the original and applicable generic RICH executions. The nine-hop row covers the named two-domain success case. The four supplemental trust-domain controls ran separately. [Nine-hop diagram and substitutions](INTEROP.md#nine-hop-success-case-across-two-trust-domains) · [Supplemental trust-domain controls](INTEROP.md#verified-trust-domain-coverage)

A pass means the observed result matched the expected outcome, which can include a refusal. A failure means execution produced a different result. A blocked case could not reach a verdict.

## IETF 127 nine-hop success case

The nine-hop case exercises a protected file read across two trust domains. All published substitutions passed, covering **27 role bindings** and **94 directional handoffs**. The [interop guide](INTEROP.md) explains how to run the matrix and inspect the evidence. The [nine-hop guide](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-qualification.md) lists the substitutions and the checks at every hop.

The Coordinator can be Cofide, Cred, TbA, or RICH Coordinator. Research can be Cred, TbA, or RICH Research. Each assignment keeps the same Domain B issuer for issuance and narrowing. The original Domain A transaction token stays in Domain A, and the File Tool checks that the WPT binds the workload identity and narrowed transaction token before allowing one read. [Nine-hop substitutions](INTEROP.md#nine-hop-role-substitutions)

Run the [standalone nine-hop workflow](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/nine-hop.yml) to execute just these **12,288** assignments. Choose 4, 8, 16, or 32 shards. The default is 16. The `nine-hop-results` artifact records per-ID outcomes and maps the qualified role bindings and directional handoffs to passing IDs.

## Quick start

Inspect the full frozen inventory from the repository root. The PyPI package supplies the CLI, and the manifest comes from the checkout. The package declares Python `>=3.10,<3.16`. The hosted workflows use Python 3.12 on Ubuntu.

```sh
python -m pip install --pre tba-tests-interop-wimse
tba-tests-interop-wimse --frozen-manifest pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-executions.json.gz
```

[Download the wheel or source distribution from PyPI](https://pypi.org/project/tba-tests-interop-wimse/#files). To use the CLI from the current checkout, install it with `python -m pip install ./pkgs/tba-tests-interop-wimse`.

| Run | Workflow | Selection |
| --- | --- | --- |
| Full inventory | [Full WIMSE interoperability matrix](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/full-matrix.yml) | All 161,370 IDs, including generic RICH and nine-hop |
| Nine-hop only | [WIMSE nine-hop interoperability](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/nine-hop.yml) | All 12,288 success assignments |
| Original matrix | [WIMSE interop matrix](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/interop-matrix.yml) | All 142,844 IDs, or one exact ID in `execution_id` |

Open [Full WIMSE interoperability matrix](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/full-matrix.yml) and select **Run workflow**. The defaults use 32 shards for the baseline and generic RICH cases and 16 for the nine-hop cases. The combined report is uploaded as `full-wimse-matrix-results`.

## Results and evidence

Download the `full-wimse-matrix-results` artifact, extract it, and open `results.html` in a browser. Search by execution ID, scenario, or reason. Filter by outcome, suite, planned hop count, or planned peer. Select an ID to inspect its evidence fields and planned hop bindings. The report works offline. For an older artifact, [generate the browser report locally](INTEROP.md#review-individual-executions).

For the full run, open `full-wimse-matrix-results` and find the published `execution_id` in `per-id.csv.gz`. Use the corresponding manifest row for the planned peer assignment and expected outcome. The report records the result and reason. Use `summary.json` to check the inventory digest and the aggregate counts. [Hosted results artifact](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/artifacts/14305462171) · [Report fields](INTEROP.md#read-the-results)

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

The workflow runs the frozen original inventory. For current peer qualification and blockers, see the [interop guide](INTEROP.md#peers-and-evidence).

To run the inventory on GitHub, open **Actions → WIMSE interop matrix → Run workflow**.
Leave `execution_id` empty to select all 142,844 published IDs, or enter one
exact published ID to run it alone. A full run uses 32 shards by default. Choose
4 to 64 shards, with up to 16 standard `ubuntu-latest` jobs in parallel and two
pytest workers per job. The prepare job qualifies the native TbA paths and the
pinned wimsey, Cofide, Cred, go-spiffe, Defakto, EMILIA, and Teleport fixtures.
The hosted workflow also prepares AgentMaurice and MintID and runs their cases
in its execution shards. Authgent runs in the shards that select its cases.
Cases reaching unavailable vendor verifiers remain in the inventory as blocked.

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

## Build and install fixture extras

The core wheel installs independently. Download it from a successful
[Build interop distribution run](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/build.yml)
or from [PyPI](https://pypi.org/project/tba-tests-interop-wimse/#files).
To install the native fixtures before all their pinned TbA dependencies are
available on PyPI, build the missing wheels from the matching TbA source
revision and place them beside the interop wheel. Use the wheel filename from your selected build. For example, install the `0.4.0.dev2` wheel with
`uv pip install --find-links . 'tba_tests_interop_wimse-0.4.0.dev2-py3-none-any.whl[wic,wpt,spiffe-wic]'`.

## Documentation

- [Interop guide](INTEROP.md) for hops, trust domains, peer assignments, and execution examples.
- [Matrix file index](pkgs/tba-tests-interop-wimse/matrix/README.md) for manifests, planning exports, and runtime evidence.
- [Package README](pkgs/tba-tests-interop-wimse/README.md) for CLI usage and fixture setup.
