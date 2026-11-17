# TbA WIMSE interoperability

The [installable harness](pkgs/tba-tests-interop-wimse) covers native TbA-to-TbA and external-peer interoperability. The [full manifest](pkgs/tba-tests-interop-wimse/matrix/wimse-interop-rich-nine-hop-executions.json.gz) contains **161,370 execution IDs**, including all **142,844** original IDs.

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

## Run the matrix

Open [Full WIMSE interoperability matrix](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/full-matrix.yml) and select **Run workflow**. The defaults use 32 shards for the baseline and generic RICH cases and 16 for the nine-hop cases. The combined report is uploaded as `full-wimse-matrix-results`.

The [package README](pkgs/tba-tests-interop-wimse/README.md) covers local installation, catalog generation, and fixture setup. The focused Cred acceptance suite covers seven protected-endpoint controls alongside the matrix. Those controls have their own results. [Cred acceptance test](pkgs/tba-tests-interop-wimse/tests/peer/test_cred_wit_wpt_acceptance.py)

Download the wheel and source distribution from [Build interop distribution](https://github.com/tigrbl/tba-tests-interop-wimse/actions/workflows/build.yml). For local fixture extras, install any missing pinned TbA wheels from the source revision used by the workflow.
