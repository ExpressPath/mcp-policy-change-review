# Privacy Notice

**Effective date:** 2026-11-05

The MCP Policy Change Review Action has no telemetry or hosted service. It does not send policy files, MCP snapshots, fixtures, or reports to the publisher. It runs on the GitHub Actions runner in the workflow owner's repository and writes its report to the job log and step summary.

The report contains scenario IDs, policy decisions, MCP tool/change details, and SHA-256 fingerprints. If configured and all policy-plane executions complete, a machine-readable JSON copy is written to a new path inside the checked-out workspace; the Action does not upload that file. These outputs may reveal internal information. GitHub stores workflow logs and summaries under the repository's access and retention settings, and any uploaded artifact follows the workflow owner's separate upload and retention settings. Repository owners control access to them. Do not put personal data or confidential values in scenario IDs or reportable policy explanations.

The workflow owner installs and pins OPA/Cedar binaries separately. This Action does not download or manage those binaries. The Action's OPA evaluation disables `http.send`, `net.lookup_ip_addr`, and `opa.runtime`; the workflow owner remains responsible for reviewing the installed binaries, workflow permissions, and any other Actions in the workflow.

Privacy questions or reports can be submitted through the [repository issue tracker](https://github.com/ExpressPath/mcp-policy-change-review/issues).
