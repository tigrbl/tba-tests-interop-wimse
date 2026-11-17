# WIMSE interop matrix files

This directory holds the published execution inventories, planning exports, and evidence from particular runs. An **execution inventory** tells the runner which cases exist and what each case expects. A **result** tells you what happened when a case ran. Use the execution ID to join the two.

- **Run the matrix or look up a case.** Start with the 161,370-ID manifest below and the [interop guide](../../../INTEROP.md).
- **Check whether a case passed, failed, or was blocked.** Open the [full-matrix hosted run](https://github.com/tigrbl/tba-tests-interop-wimse/actions/runs/44021013592/attempts/2). Its `full-wimse-matrix-results` artifact contains a summary and `per-id.csv.gz`. GitHub Actions artifact retention applies.
- **Change the test model.** Edit the appropriate [TOML catalog](../src/tba_tests_interop_wimse/) and follow the [package README](../README.md) to regenerate the relevant inventory or export.

For hop diagrams, trust-domain layouts, execution ID examples, and authentication assignments, see the [detailed interop guide](wimse-interop-guide.md). For capabilities and qualification by role, see the [peer reference](wimse-interop-peers.md).

## Execution manifests

The `.json.gz` files are gzip-compressed JSON. They contain large lists of execution rows, including IDs, peer assignments, and expected results. The CLI reads them directly with `--frozen-manifest`. The frozen copies give runners and reports a common set of IDs.

| Manifest | Purpose |
| --- | --- |
| [`wimse-interop-rich-nine-hop-executions.json.gz`](wimse-interop-rich-nine-hop-executions.json.gz) | **161,370 IDs.** Input to the full-matrix and nine-hop workflows. Includes the original 142,844 IDs plus 6,238 generic RICH cases and 12,288 assignments for the named nine-hop success case. |
| [`wimse-interop-all-tba-executions.json.gz`](wimse-interop-all-tba-executions.json.gz) | **142,844 IDs.** Frozen original matrix. Includes both TbA-only and external-peer cases. Used by the original-matrix workflow and by the full workflow to reconcile its original IDs. |
| [`wimse-interop-expanded-executions.json.gz`](wimse-interop-expanded-executions.json.gz) | **64,881 IDs.** Earlier peer and typed-hop expansion snapshot, retained for comparison with later inventories. |

See the [nine-hop qualification guide](wimse-interop-rich-nine-hop-qualification.md) for the substitution table, the named flow's acceptance checks, and the command for regenerating the 161,370-ID manifest.

## Planning and spreadsheet exports

These CSVs summarize a model or plan by hop sequence. Counts in fields such as `candidate_runs` and `new_planned_runs` describe the inventory for that export's peer snapshot.

| File | Purpose |
| --- | --- |
| [`wimse-interop-hop-matrix.csv`](wimse-interop-hop-matrix.csv) | The 155 ordered one-, two-, and three-hop type sequences, with scenario mappings and binding gaps. |
| [`wimse-interop-hop-expansion-audit.csv`](wimse-interop-hop-expansion-audit.csv) | A saved coverage audit of those sequences and their mappings. |
| [`wimse-interop-hop-expansion-plan.csv`](wimse-interop-hop-expansion-plan.csv) | Constrained expansion showing admitted flows, compatible assignments, and planned runs by sequence. |
| [`wimse-interop-hop-peer-expansion.csv`](wimse-interop-hop-peer-expansion.csv) | Expansion with additional peer candidates and support operations. |
| [`wimse-interop-all-tba-expansion.csv`](wimse-interop-all-tba-expansion.csv) | Expansion summary with separate counts for native TbA workload and typed-hop runs. |
| [`wimse-interop-coverage.xlsx`](wimse-interop-coverage.xlsx) | Coverage workbook with factors, profiles, scenarios, peer capabilities, and planning views, including the earlier Cartesian model. |
| [`wimse-interop-execution-results.xlsx`](wimse-interop-execution-results.xlsx) | Spreadsheet snapshot with execution rows and a factor catalog. Use the hosted per-ID report above for the full 161,370-ID result. |

The [scenario matrix](wimse-interop-scenario-matrix.md) describes scenario variants and their expected effects. The [execution matrix](wimse-interop-execution-matrix.md) describes peer assignments and directions.

## Checked-in run evidence

These files preserve results from scoped runs, pilots, retries, and fixture qualification. The same ID can appear in more than one run. Use the audited aggregate for the run you want to report.

| Format | What it records |
| --- | --- |
| `*-results.csv`, `*-per-id.csv` | Spreadsheet-friendly per-execution results. Depending on the run, rows include the published ID, runtime ID, decision, effects, and blocker reason. |
| [`wimse-interop-per-id-blockers.csv.gz`](wimse-interop-per-id-blockers.csv.gz) | Compressed closure snapshot for the original 142,844 IDs, with historical results and endpoint, baseline, issuer, or support gaps. |
| `*-summary.json`, `*-runtime-summary.json` | Machine-readable summaries for particular runs or tranches, often with counts by hop, peer, or outcome. |
| [`wimse-agentmaurice-controls.json`](wimse-agentmaurice-controls.json) | AgentMaurice release pin, deployment details, and directional and issuer control observations. |
| `*.xml`, `*.xml.gz` | JUnit evidence, with gzip compression on larger reports. `*-runtime` files capture execution results. `*-controls` files capture fixture qualification, such as issuer, profile, or Workload API checks. Pilots and retries keep their own reports. |

Use these filename prefixes to locate the evidence for a particular tranche.

| Prefix | Scope |
| --- | --- |
| `wimse-agentmaurice-`, `wimse-external-workload-`, `wimse-external-support-` | AgentMaurice, external workload peers, and external support roles. |
| `wimse-go-spiffe-`, `wimse-defakto-and-mixed-`, `wimse-emilia-workload-`, `wimse-mintid-support-`, `wimse-teleport-tbot-support-` | Runtime evidence for specific peer integrations. |
| `wimse-native-x509-svid-`, `wimse-native-wit-svid-`, `wimse-native-combined-svid-` | Native credential issuer and presentation runs. |
| `wimse-native-acquisition-`, `wimse-native-specialized-acquisition-` | Workload API and credential handoff runs and qualification controls. |
| `wimse-native-short-workload-`, `wimse-native-baseline-policy-`, `wimse-native-svid-policy-`, `wimse-typed-service-` | Native workload, policy, and typed service flow tranches. |
| `wimse-triple-call-pilot.xml`, `wimse-existing-peer-three-call-retry.xml.gz`, `wimse-interop-all-tba-runtime.xml` | Three-call pilot, targeted retry, and native TbA three-call batch. |

The [runtime closure plan](wimse-runtime-closure-plan.md), [native baseline notes](tba-native-baseline.md), and [external peer access notes](wimse-external-peer-access.md) explain the conditions for those runs.
