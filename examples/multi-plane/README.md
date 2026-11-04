# Multi-control-plane MCP change review

This example runs one MCP inventory change and shared authorization scenarios through two separately configured OPA policy planes. It produces one report that shows each plane's result, missing shared scenarios, cross-plane decision differences, and an unsigned SHA-256 evidence fingerprint.

## Passing example

Install OPA 1.x, verify its checksum, and expose it on `PATH` or set `OPA_BIN`. From the repository root, run:

~~~powershell
node bin/agent-policy-check.js mcp-multi-review `
  --manifest .\examples\multi-plane\mcp-multi-review.json `
  --require-policy-coverage `
  --fail-on-unexpected-new-allow `
  --format github
~~~

Both control planes use the same synthetic fixture IDs and policy version, so the two inventory changes should have passing mapped cases and no cross-plane divergence. The command exits with status 0.

## Cedar example

The [`mcp-multi-review-cedar.json`](./mcp-multi-review-cedar.json) manifest applies the same synthetic MCP change and five Cedar authorization cases to two separately named Cedar planes. Install and checksum-verify the Cedar CLI first, then run:

~~~powershell
node bin/agent-policy-check.js mcp-multi-review `
  --manifest .\examples\multi-plane\mcp-multi-review-cedar.json `
  --require-policy-coverage `
  --fail-on-unexpected-new-allow `
  --fail-on-candidate-divergence `
  --format github
~~~

The sample policy is identical in both planes. It demonstrates Cedar execution and scenario matching, not cross-plane divergence.

## Deliberate regional regression

The drift manifest gives the regional plane a candidate policy that incorrectly allows the newly exposed delete tool:

~~~powershell
node bin/agent-policy-check.js mcp-multi-review `
  --manifest .\examples\multi-plane\mcp-multi-review-drift.json `
  --require-policy-coverage `
  --fail-on-unexpected-new-allow `
  --fail-on-candidate-divergence `
  --format github
~~~

This command is expected to exit with status 1. The report should identify the regional `MCP-REV-002` decision as `allow` instead of `deny`, and show the candidate and transition divergence against the core plane. The intentionally failing policy is a synthetic regression fixture, not an example of a customer rule.

## Manifest and comparison rules

- A version 1 manifest must contain between 2 and 32 control planes. Each plane selects `opa` or `cedar`, its own baseline/candidate snapshots, baseline/candidate policy files, a fixture file, and optional engine-specific settings.
- Relative paths resolve from the manifest's directory. OPA and Cedar execute locally. No gateway, MCP server, or cloud API is contacted.
- Each fixture must have a unique `id` within its plane. Exact matching IDs are compared as shared scenarios; the runner does not infer equivalence from fixture names or policy inputs.
- Shared scenario coverage is required by default. `--allow-missing-cases` can disable that gate, while the report still lists missing plane IDs.
- Expected decisions are evaluated independently within each plane. Candidate decision and baseline-to-candidate transition divergence are reported but are not automatically failures; use `--fail-on-candidate-divergence` or `--fail-on-transition-divergence` when the organization requires uniform outcomes.
- The JSON report includes hashes of source inputs and a hash over the normalized result. It is unsigned and does not authenticate source control, reviewers, engine binaries, or deployment state.
- The report omits raw fixture inputs and policy files, but case IDs, tool IDs, outcomes, and change-field names may still be sensitive. Keep it inside the repository's access boundary.

The multi-plane GitHub Action is declared in [`../../action.yml`](../../action.yml). It defaults to requiring common scenarios, passing coverage, and no unexpected new allows.
