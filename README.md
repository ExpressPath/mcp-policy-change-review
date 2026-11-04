# MCP Policy Change Review

An early GitHub Action prototype for reviewing MCP tool-inventory changes and replaying the same authorization scenarios against separately managed OPA or Cedar policy planes.

It is designed for organizations that cannot consolidate every agent runtime, MCP gateway, and policy engine. It does not connect to MCP servers or gateways, enforce live tool calls, sign evidence, or prove production security. The bundled cross-plane example uses synthetic data. Multi-plane Cedar and customer-repository installs have not been validated.

## What the action checks

- Added, removed, or modified MCP tool definitions, keyed by stable organization-defined server ID and tool name.
- Expected authorization outcomes for each local policy plane.
- Baseline-to-candidate decision changes and unexpected new allows.
- Shared scenario-ID coverage, policy coverage for changed tools, and optional cross-plane decision/transition divergence.
- SHA-256 fingerprints of the reviewed inputs and normalized results. These fingerprints are unsigned and are not a provenance or identity attestation.

## Use in an existing workflow

The action uses the OPA or Cedar executable already available on the runner. Install the required engine from its official release source, verify its checksum, and ensure it is on `PATH` before this step. A Cedar control plane requires Cedar; an OPA control plane requires OPA.

```yaml
name: MCP policy review
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      # Install and checksum-verify the OPA/Cedar binaries required by your manifest.
      - name: Review MCP changes across policy planes
        uses: ExpressPath/mcp-policy-change-review@<full-commit-sha>
        with:
          manifest: examples/mcp-multi-review.json
          require-common-cases: 'true'
          require-policy-coverage: 'true'
          fail-on-unexpected-new-allow: 'true'
          fail-on-candidate-divergence: 'true'
```

Replace the owner/repository and placeholder SHA after a public release. Pin third-party actions to a reviewed full commit SHA under your organization's secure-use policy. The example assumes the sample manifest and all referenced policy, fixture, and snapshot paths are checked into the workflow repository.

## Manifest

The [sample manifest](examples/mcp-multi-review.json) runs the same synthetic scenarios against two separately configured OPA planes. Its companion [`mcp-multi-review-drift.json`](examples/mcp-multi-review-drift.json) contains an intentional regional over-permission regression. Run the CLI with `--format github` to see the report locally.

Each manifest supports 2–32 control planes. Relative paths resolve from the manifest file; absolute paths are also accepted when they remain inside `GITHUB_WORKSPACE`. The action canonicalizes paths and rejects a manifest, policy, fixture, snapshot, or data path that resolves outside the checked-out workspace, including a symlink that points outside it. Each plane provides baseline and candidate MCP snapshots, baseline and candidate policies, a fixture file, and optional OPA/Cedar-specific settings. Fixture `id` values must mean the same authorization scenario in each plane; the action does not infer scenario equivalence.

By default, the action requires common scenarios, policy coverage for changed tools, and no unexpected new allows. Cross-plane candidate-decision and transition divergence are reported; opt into failing on either when the organization requires it.

## Data and trust boundary

The action runs OPA or Cedar locally and does not contact an MCP server, cloud gateway, identity provider, or external service. It does not upload inputs. Its report includes case identifiers, decisions, change summaries, and hashes; those values may still reveal internal information, so retain the report under repository access controls. Workspace path confinement limits accidental reads from outside the checkout; it does not make attacker-controlled policies or manifests safe to execute. Protect the workflow branch and do not run untrusted pull-request content with sensitive runner credentials.

The hash is unsigned and does not prove who approved or produced the inputs. The action has no customer validation, formal security certification, or independent security review. Do not use it as a production authorization gateway or as the sole security control.

## License, end-user terms, and privacy

The source is available under [Apache-2.0](LICENSE). The separate [End User License Agreement](EULA.md) explains the Product's scope and limits. See the [Privacy Notice](PRIVACY.md) for report handling and data practices. Support and bug reports use the [repository issue tracker](https://github.com/ExpressPath/mcp-policy-change-review/issues).

## Current release state

This is a public pre-release candidate, not a versioned release or published Marketplace listing. Do not use `@main` as a production dependency. Clean-install evidence, multi-plane Cedar validation, security review beyond static self-review, a versioned release, and GitHub Marketplace Developer Agreement acceptance remain outstanding. No customer has validated the workflow or willingness to pay.
