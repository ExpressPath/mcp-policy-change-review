#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const command = process.argv[2];
const runners = {
  demo: 'src/check-policy.js',
  opa: 'src/check-opa.js',
  cedar: 'src/check-cedar.js',
  'mcp-diff': 'src/check-mcp-snapshot.js',
  'mcp-review': 'src/check-mcp-review.js',
  'mcp-multi-review': 'src/check-multi-plane-review.js',
};

if (command === '--help' || command === '-h' || !command) {
  console.log('Usage: agent-policy-check <demo|opa|cedar|mcp-diff|mcp-review|mcp-multi-review> [runner options]');
  console.log('Examples:');
  console.log('  agent-policy-check opa --policy ./policy/agent_policy.rego --fixtures ./policy-packs/mcp-agent-baseline.json');
  console.log('  agent-policy-check opa --policy ./examples/custom/access.rego --data ./examples/custom/access-data.json --query data.sample.allow --fixtures ./examples/custom/fixtures.json');
  console.log('  agent-policy-check cedar --policy ./examples/cedar/access.cedar --entities ./examples/cedar/entities.json --fixtures ./examples/cedar/fixtures.json');
  console.log('  agent-policy-check opa --baseline-policy ./base.rego --fail-on-unexpected-new-allow');
  console.log('  agent-policy-check mcp-diff --baseline ./mcp/before.json --candidate ./mcp/after.json --fail-on-any-change --format github');
  console.log('  agent-policy-check mcp-review --baseline-snapshot ./mcp/before.json --candidate-snapshot ./mcp/after.json --baseline-policy ./base.rego --policy ./policy.rego --fixtures ./fixtures.json --require-policy-coverage --format github');
  console.log('  agent-policy-check mcp-review --engine cedar --baseline-snapshot ./mcp/before.json --candidate-snapshot ./mcp/after.json --baseline-policy ./base.cedar --policy ./policy.cedar --entities ./entities.json --fixtures ./cedar-fixtures.json --require-policy-coverage --format github');
  console.log('  agent-policy-check mcp-multi-review --manifest ./mcp-review.json --require-policy-coverage --fail-on-unexpected-new-allow --format github');
  console.log('  agent-policy-check opa --format json');
  console.log('  agent-policy-check opa --format github >> "$GITHUB_STEP_SUMMARY"');
  process.exit(command ? 0 : 2);
}

const runner = Object.hasOwn(runners, command) ? runners[command] : undefined;
if (!runner) {
  console.error('Unknown runner "' + command + '". Choose "demo", "opa", "cedar", "mcp-diff", "mcp-review", or "mcp-multi-review".');
  process.exit(2);
}

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const entrypoint = resolve(packageRoot, runner);
const result = spawnSync(process.execPath, [entrypoint, ...process.argv.slice(3)], {
  cwd: process.cwd(),
  env: process.env,
  stdio: 'inherit',
  windowsHide: true,
});

if (result.error) {
  console.error(result.error.message);
  process.exit(2);
}
process.exit(result.status ?? 1);
