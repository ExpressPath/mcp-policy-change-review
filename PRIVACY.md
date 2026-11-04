# Privacy Notice

**Effective date:** 2026-11-04

The MCP Policy Change Review Action has no telemetry or hosted service. It does not send policy files, MCP snapshots, fixtures, or reports to the publisher. It runs on the GitHub Actions runner in the workflow owner's repository and writes its report to the job log and step summary.

The report contains scenario IDs, policy decisions, MCP tool/change details, and SHA-256 fingerprints. These may reveal internal information. GitHub stores workflow logs and summaries under the repository's access and retention settings; repository owners control access to them. Do not put personal data or confidential values in scenario IDs or reportable policy explanations.

The workflow owner installs and pins OPA/Cedar binaries separately. This Action does not download or manage those binaries. The Action's OPA evaluation disables `http.send`, `net.lookup_ip_addr`, and `opa.runtime`; the workflow owner remains responsible for reviewing the installed binaries, workflow permissions, and any other Actions in the workflow.

Privacy questions or reports can be submitted through the [repository issue tracker](https://github.com/ExpressPath/mcp-policy-change-review/issues).
