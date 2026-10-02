### Fixed

- **The reviewed CodeQL gate no longer aborts when a SARIF result omits `region.startColumn` (#1674).** SARIF 2.1.0 defaults an absent `startColumn` to 1, and CodeQL omitted it for alert 447 in trusted run 36920507526, so `scripts/codeql_reviewed_dispositions.py` stopped with "HIGH+ SARIF start column is invalid" before matching any finding. The parser now applies the default only when the key is absent; a present `startColumn` that is null, a bool, a non-integer, zero or negative still fails closed, and the defaulted column must still equal the reviewed case and the live alert.
