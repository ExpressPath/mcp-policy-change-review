#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFixtureSet } from './fixtures.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const cli = join(root, 'bin', 'agent-policy-check.js');
const valueOptions = new Set([
  '--baseline-snapshot', '--candidate-snapshot', '--engine', '--baseline-policy', '--policy', '--fixtures',
  '--data', '--baseline-data', '--query', '--entities', '--baseline-entities', '--schema', '--baseline-schema',
  '--schema-format', '--template-linked', '--baseline-template-linked', '--timeout-ms', '--format',
]);
const flagOptions = new Set(['--require-policy-coverage', '--fail-on-unexpected-new-allow', '--fail-on-any-policy-change']);

function parseOptions(args) {
  const options = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (flagOptions.has(option)) {
      options.set(option, true);
      continue;
    }
    if (!valueOptions.has(option)) throw new Error('Unknown option: ' + option);
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new Error('Missing value for ' + option + '.');
    options.set(option, value);
    index += 1;
  }
  for (const required of ['--baseline-snapshot', '--candidate-snapshot', '--baseline-policy']) {
    if (!options.has(required)) throw new Error('MCP change review requires ' + required + ' <path>.');
  }
  return options;
}

function absolutePath(path) {
  return isAbsolute(path) ? path : resolve(process.cwd(), path);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function readJsonPointer(value, pointer, label) {
  if (typeof pointer !== 'string' || !pointer.startsWith('/') || pointer.length < 2) {
    throw new Error(label + ' must be a non-root JSON Pointer.');
  }
  let current = value;
  for (const rawSegment of pointer.slice(1).split('/')) {
    if (/~(?![01])/.test(rawSegment)) throw new Error(label + ' contains an invalid JSON Pointer escape.');
    const segment = rawSegment.replaceAll('~1', '/').replaceAll('~0', '~');
    if (Array.isArray(current)) {
      if (!/^(0|[1-9][0-9]*)$/.test(segment)) return undefined;
      current = current[Number(segment)];
    } else if (isRecord(current) && Object.hasOwn(current, segment)) {
      current = current[segment];
    } else {
      return undefined;
    }
  }
  return current;
}

function validateFixtureBindings(fixtureSet, engine) {
  for (const [index, fixture] of fixtureSet.fixtures.entries()) {
    if (!fixture.mcp) continue;
    const label = fixture.id ?? fixture.name ?? 'fixtures[' + index + ']';
    const { server_id: serverId, tool_name: toolName } = fixture.mcp;

    if (engine === 'cedar') {
      const context = fixture.cedar_input?.request?.context;
      if (context?.server_id !== serverId || context?.tool_name !== toolName) {
        throw new Error('Cedar fixture ' + label + ' must place matching server_id and tool_name values in cedar_input.request.context.');
      }
      if (fixture.mcp_binding) throw new Error('Cedar fixture ' + label + ' cannot use the OPA-specific mcp_binding field.');
      continue;
    }

    if (Object.hasOwn(fixture, 'opa_input')) {
      if (!fixture.mcp_binding) {
        throw new Error('OPA fixture ' + label + ' uses opa_input with MCP coverage metadata but has no mcp_binding JSON Pointers.');
      }
      const actualServerId = readJsonPointer(fixture.opa_input, fixture.mcp_binding.opa_server_id_path, label + '.mcp_binding.opa_server_id_path');
      const actualToolName = readJsonPointer(fixture.opa_input, fixture.mcp_binding.opa_tool_name_path, label + '.mcp_binding.opa_tool_name_path');
      if (actualServerId !== serverId || actualToolName !== toolName) {
        throw new Error('OPA fixture ' + label + ' mcp_binding does not match its evaluated opa_input identity.');
      }
    }
  }
}

function runRunner(args, label) {
  const child = spawnSync(process.execPath, [cli, ...args], {
    cwd: process.cwd(),
    env: process.env,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
  if (child.error) throw new Error(label + ' could not start: ' + child.error.message);
  if (child.status === null) throw new Error(label + ' ended without an exit status: ' + (child.stderr || child.stdout || 'unknown process error'));
  let report;
  try {
    report = JSON.parse(child.stdout);
  } catch {
    const detail = (child.stderr || child.stdout || 'no diagnostic output').trim();
    throw new Error(label + ' did not return JSON (exit ' + child.status + '): ' + detail);
  }
  return { report, status: child.status };
}

function markdownCell(value) {
  return String(value ?? '—')
    .replaceAll('&', '&amp;')
    .replaceAll('|', '\\|')
    .replace(/[\r\n]+/g, ' ')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function policyCaseLabel(entry) {
  return entry.fixture.id ?? entry.fixture.name;
}

function renderGitHubSummary(report) {
  const failed = !report.summary.passed;
  const emoji = failed ? '❌' : '✅';
  const lines = [
    '## ' + emoji + ' MCP and authorization change review',
    '**Inventory:** ' + report.inventory.summary.baseline_tools + ' → ' + report.inventory.summary.candidate_tools
      + ' tools · ' + report.summary.tool_changes + ' changed (' + report.inventory.summary.added + ' added, '
      + report.inventory.summary.removed + ' removed, ' + report.inventory.summary.modified + ' modified)',
    '**' + report.policy.engine.toUpperCase() + ' replay:** ' + report.policy.summary.passed + '/' + report.policy.summary.total + ' passed · '
      + report.policy.summary.changed + ' decision changes · ' + report.policy.summary.new_allows + ' new allows',
    '**Coverage:** ' + report.summary.covered_tools + '/' + report.summary.tool_changes + ' changed tools have passing mapped cases'
      + (report.require_policy_coverage ? ' (required)' : ' (report only)'),
    '',
    '| Server ID | Tool | Inventory change | Changed fields | Mapped policy cases | Coverage |',
    '| --- | --- | --- | --- | --- | --- |',
  ];
  for (const item of report.tool_reviews) {
    const cases = item.policy_cases.map((entry) => {
      const baseline = entry.result?.baseline_actual ?? 'no baseline result';
      const candidate = entry.result?.actual ?? 'no result';
      return policyCaseLabel(entry) + ' (' + baseline + ' → ' + candidate + '; expected ' + entry.fixture.expected + ')';
    });
    lines.push('| ' + markdownCell(item.server_id)
      + ' | ' + markdownCell(item.tool_name)
      + ' | ' + markdownCell(item.change_type)
      + ' | ' + markdownCell(item.changed_fields.join(', '))
      + ' | ' + markdownCell(cases.join(', ') || 'none')
      + ' | ' + markdownCell(item.coverage) + ' |');
  }
  if (report.tool_reviews.length === 0) lines.push('| — | — | No inventory changes | — | — | — |');

  const failedCases = report.policy.results.filter((result) => !result.passed);
  if (failedCases.length > 0) {
    lines.push('', '### Policy cases needing review');
    for (const result of failedCases) {
      lines.push('- **' + markdownCell(result.id ?? result.name) + '** — expected '
        + markdownCell(result.expected) + ', received ' + markdownCell(result.actual)
        + (result.baseline_actual ? ' (baseline ' + markdownCell(result.baseline_actual) + ')' : '')
        + '. ' + markdownCell(result.rationale ?? 'Policy replay failed.'));
    }
  }
  lines.push('');
  return lines.join('\n');
}

function renderText(report) {
  const lines = ['MCP and authorization change review'];
  for (const item of report.tool_reviews) {
    const cases = item.policy_cases.map((entry) => policyCaseLabel(entry) + ': '
      + entry.result?.baseline_actual + ' -> ' + entry.result?.actual + ' (expected ' + entry.fixture.expected + ')');
    lines.push(item.change_type.toUpperCase() + '  ' + item.server_id + '/' + item.tool_name
      + ' · fields: ' + item.changed_fields.join(', ')
      + ' · coverage: ' + item.coverage
      + ' · cases: ' + (cases.join('; ') || 'none'));
  }
  lines.push('', report.policy.summary.passed + '/' + report.policy.summary.total + ' ' + report.policy.engine.toUpperCase() + ' cases passed; '
    + report.policy.summary.changed + ' decisions changed; ' + report.policy.summary.new_allows + ' new allows.');
  if (report.inventory.summary.changes === 0) lines.splice(1, 0, 'No MCP tool inventory changes.');
  return lines.join('\n');
}

function main() {
  try {
    const options = parseOptions(process.argv.slice(2));
    const format = options.get('--format') ?? 'text';
    if (!['text', 'json', 'github'].includes(format)) throw new Error('--format must be "text", "json", or "github".');
    const engine = options.get('--engine') ?? 'opa';
    if (!['opa', 'cedar'].includes(engine)) throw new Error('--engine must be "opa" or "cedar".');
    const opaOnlyOptions = ['--data', '--baseline-data', '--query'];
    const cedarOnlyOptions = [
      '--entities', '--baseline-entities', '--schema', '--baseline-schema', '--schema-format',
      '--template-linked', '--baseline-template-linked',
    ];
    const unsupportedOptions = engine === 'opa' ? cedarOnlyOptions : opaOnlyOptions;
    const unsupported = unsupportedOptions.find((option) => options.has(option));
    if (unsupported) throw new Error(unsupported + ' cannot be used with --engine ' + engine + '.');

    const baselineSnapshot = absolutePath(options.get('--baseline-snapshot'));
    const candidateSnapshot = absolutePath(options.get('--candidate-snapshot'));
    const fixturesPath = options.has('--fixtures')
      ? absolutePath(options.get('--fixtures'))
      : join(root, 'policy-packs', 'mcp-agent-baseline.json');
    const fixtureSet = readFixtureSet(root, fixturesPath);
    validateFixtureBindings(fixtureSet, engine);
    const diff = runRunner([
      'mcp-diff', '--baseline', baselineSnapshot, '--candidate', candidateSnapshot, '--format', 'json',
    ], 'MCP snapshot comparison');
    if (diff.status !== 0) throw new Error('MCP snapshot comparison failed with exit code ' + diff.status + '.');

    const policyArg = options.get('--policy')
      ?? (engine === 'opa' ? join(root, 'policy', 'agent_policy.rego') : undefined);
    if (!policyArg) throw new Error('--policy <path> is required when --engine cedar is selected.');
    const policyArgs = [
      engine, '--baseline-policy', absolutePath(options.get('--baseline-policy')),
      '--policy', absolutePath(policyArg), '--fixtures', fixturesPath, '--format', 'json',
    ];
    const engineOptions = engine === 'opa'
      ? ['--data', '--baseline-data', '--query', '--timeout-ms']
      : [
        '--entities', '--baseline-entities', '--schema', '--baseline-schema', '--schema-format',
        '--template-linked', '--baseline-template-linked', '--timeout-ms',
      ];
    for (const option of engineOptions) {
      if (options.has(option)) policyArgs.push(option, options.get(option));
    }
    if (options.has('--fail-on-unexpected-new-allow')) policyArgs.push('--fail-on-unexpected-new-allow');
    if (options.has('--fail-on-any-policy-change')) policyArgs.push('--fail-on-any-change');
    const policyRun = runRunner(policyArgs, engine.toUpperCase() + ' policy replay');
    if (policyRun.status !== 0 && policyRun.status !== 1) {
      throw new Error(engine.toUpperCase() + ' policy replay failed with exit code ' + policyRun.status + '.');
    }
    if (!Array.isArray(policyRun.report.results) || policyRun.report.results.length !== fixtureSet.fixtures.length) {
      throw new Error(policyRun.report.engine + ' report did not contain one result for each authorization fixture.');
    }

    const fixtureResults = new Map();
    for (const [index, fixture] of fixtureSet.fixtures.entries()) {
      if (fixture.mcp) {
        const key = JSON.stringify([fixture.mcp.server_id, fixture.mcp.tool_name]);
        if (!fixtureResults.has(key)) fixtureResults.set(key, []);
        fixtureResults.get(key).push({ fixture, result: policyRun.report.results[index] });
      }
    }
    const toolReviews = diff.report.results.map((change) => {
      const key = JSON.stringify([change.server_id, change.tool_name]);
      const policyCases = fixtureResults.get(key) ?? [];
      const allCasesPass = policyCases.length > 0 && policyCases.every((entry) => entry.result.passed);
      const hasCandidateDeny = policyCases.some((entry) => entry.fixture.expected === 'deny' && entry.result.actual === 'deny');
      const covered = allCasesPass && (change.change_type !== 'removed' || hasCandidateDeny);
      const coverage = covered ? 'covered'
        : policyCases.length === 0 ? 'uncovered'
          : !allCasesPass ? 'policy case failing'
            : 'missing candidate deny case';
      return { ...change, coverage, policy_cases: policyCases };
    });
    const coveredTools = toolReviews.filter((item) => item.coverage === 'covered').length;
    const coverageFailed = options.has('--require-policy-coverage') && coveredTools !== toolReviews.length;
    const passed = policyRun.status === 0 && !coverageFailed;
    const report = {
      version: 1,
      engine: 'mcp-review-' + engine,
      baseline_snapshot: diff.report.baseline,
      candidate_snapshot: diff.report.candidate,
      require_policy_coverage: options.has('--require-policy-coverage'),
      inventory: diff.report,
      policy: policyRun.report,
      tool_reviews: toolReviews,
      summary: {
        passed,
        tool_changes: toolReviews.length,
        covered_tools: coveredTools,
        incomplete_tools: toolReviews.length - coveredTools,
        policy_passed: policyRun.report.summary.passed,
        policy_failed: policyRun.report.summary.failed,
      },
    };

    if (format === 'json') console.log(JSON.stringify(report, null, 2));
    else if (format === 'github') process.stdout.write(renderGitHubSummary(report));
    if (format === 'text') console.log(renderText(report));
    if (!passed) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  }
}

main();
