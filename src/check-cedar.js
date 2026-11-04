import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFixtureSet } from './fixtures.js';
import { renderGitHubSummary } from './report.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const cedarBinary = process.env.CEDAR_BIN || 'cedar';
const options = new Map();
const valueOptions = new Set([
  '--policy', '--baseline-policy', '--entities', '--baseline-entities', '--schema', '--baseline-schema',
  '--schema-format', '--template-linked', '--baseline-template-linked', '--fixtures', '--format', '--timeout-ms',
]);
const flagOptions = new Set(['--fail-on-unexpected-new-allow', '--fail-on-any-change']);
for (let index = 2; index < process.argv.length; index += 1) {
  const option = process.argv[index];
  if (flagOptions.has(option)) {
    options.set(option, 'true');
    continue;
  }
  if (!valueOptions.has(option)) throw new Error(`Unknown option: ${option}`);
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`Missing value for ${option}.`);
  options.set(option, value);
  index += 1;
}

const fixturePath = options.get('--fixtures');
if (!fixturePath) throw new Error('The Cedar runner requires --fixtures; Cedar returns only allow/deny, so use fixtures mapped to the Cedar policy contract.');
const fixtureSet = readFixtureSet(root, fixturePath);
const pathOption = (name) => {
  const value = options.get(name);
  return value ? (isAbsolute(value) ? value : resolve(process.cwd(), value)) : undefined;
};
const policyPath = pathOption('--policy');
if (!policyPath) throw new Error('The Cedar runner requires --policy <path>.');
const baselinePolicyPath = pathOption('--baseline-policy');
const entitiesPath = pathOption('--entities');
const baselineEntitiesPath = pathOption('--baseline-entities');
const schemaPath = pathOption('--schema');
const baselineSchemaPath = pathOption('--baseline-schema');
const templateLinkedPath = pathOption('--template-linked');
const baselineTemplateLinkedPath = pathOption('--baseline-template-linked');
const schemaFormat = options.get('--schema-format') ?? 'cedar';
if (!['cedar', 'json'].includes(schemaFormat)) throw new Error('--schema-format must be "cedar" or "json".');
const format = options.get('--format') ?? 'text';
if (!['text', 'json', 'github'].includes(format)) throw new Error('--format must be "text", "json", or "github".');
const failOnUnexpectedNewAllow = options.has('--fail-on-unexpected-new-allow');
const failOnAnyChange = options.has('--fail-on-any-change');
if ((failOnUnexpectedNewAllow || failOnAnyChange) && !baselinePolicyPath) {
  throw new Error('Change-failure flags require --baseline-policy.');
}
if (baselineEntitiesPath && !baselinePolicyPath) throw new Error('--baseline-entities requires --baseline-policy.');
if (baselineSchemaPath && !baselinePolicyPath) throw new Error('--baseline-schema requires --baseline-policy.');
if (baselineTemplateLinkedPath && !baselinePolicyPath) throw new Error('--baseline-template-linked requires --baseline-policy.');
if (schemaFormat !== 'cedar' && !schemaPath && !baselineSchemaPath) throw new Error('--schema-format requires --schema or --baseline-schema.');
const timeoutMs = Number(options.get('--timeout-ms') ?? 10000);
if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) {
  throw new Error('--timeout-ms must be an integer from 100 to 120000.');
}

for (const fixture of fixtureSet.fixtures) {
  if (!fixture.cedar_input || typeof fixture.cedar_input !== 'object' || Array.isArray(fixture.cedar_input)) {
    throw new Error(`Fixture "${fixture.name}" has no cedar_input object. Cedar requires Cedar-specific request and entity data.`);
  }
  if (fixture.expected === 'approval_required') {
    throw new Error(`Fixture "${fixture.name}" expects approval_required, which Cedar's authorization decision does not represent. Use an engine-specific allow/deny expectation or test approval in the surrounding application adapter.`);
  }
  if (!['allow', 'deny'].includes(fixture.expected)) {
    throw new Error(`Fixture "${fixture.name}" must expect allow or deny for Cedar.`);
  }
  if (fixture.cedar_input.entities === undefined && !entitiesPath) {
    throw new Error(`Fixture "${fixture.name}" needs cedar_input.entities or a shared --entities file for candidate evaluation.`);
  }
  if (baselinePolicyPath && fixture.cedar_input.entities === undefined && !(baselineEntitiesPath ?? entitiesPath)) {
    throw new Error(`Fixture "${fixture.name}" needs cedar_input.entities, --baseline-entities, or shared --entities for baseline evaluation.`);
  }
}

const cedarEnvironment = {};
for (const key of ['PATH', 'PATHEXT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL']) {
  if (process.env[key] !== undefined) cedarEnvironment[key] = process.env[key];
}
const temporaryDirectory = mkdtempSync(join(tmpdir(), 'agent-policy-cedar-ci-'));
process.on('exit', () => {
  const resolvedTempRoot = resolve(tmpdir());
  const resolvedTemporaryDirectory = resolve(temporaryDirectory);
  if (dirname(resolvedTemporaryDirectory) === resolvedTempRoot && basename(resolvedTemporaryDirectory).startsWith('agent-policy-cedar-ci-')) {
    rmSync(resolvedTemporaryDirectory, { recursive: true, force: true });
  }
});

function processErrorDetail(error) {
  const e = error && typeof error === 'object' ? error : {};
  if (e.code === 'ETIMEDOUT' || e.killed) return `Cedar process exceeded its ${e.timeout ?? 'configured'} ms timeout.`;
  const stderr = e.stderr ? String(e.stderr).trim() : '';
  const stdout = e.stdout ? String(e.stdout).trim() : '';
  return [stderr, stdout].filter(Boolean).join('\n') || (error instanceof Error ? error.message : String(error));
}

function writeJson(name, value) {
  const path = join(temporaryDirectory, name);
  writeFileSync(path, JSON.stringify(value), { encoding: 'utf8', flag: 'wx' });
  return path;
}

function cedarRequestFiles(fixture, index) {
  const input = fixture.cedar_input;
  const request = input.request;
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new Error(`Fixture "${fixture.name}" cedar_input.request must be an object.`);
  }
  for (const field of ['principal', 'action', 'resource']) {
    if (typeof request[field] !== 'string' || request[field].trim() === '') {
      throw new Error(`Fixture "${fixture.name}" cedar_input.request.${field} must be a non-empty Cedar entity UID.`);
    }
  }
  if (request.context !== undefined && (!request.context || typeof request.context !== 'object' || Array.isArray(request.context))) {
    throw new Error(`Fixture "${fixture.name}" cedar_input.request.context must be an object.`);
  }
  const requestPath = writeJson(`${index}.request.json`, {
    principal: request.principal,
    action: request.action,
    resource: request.resource,
    context: request.context ?? {},
  });
  const fixtureEntities = input.entities;
  const fixtureEntitiesPath = Array.isArray(fixtureEntities)
    ? writeJson(`${index}.entities.json`, fixtureEntities)
    : undefined;
  return { requestPath, fixtureEntitiesPath };
}

function parseCedarOutput(output) {
  const lines = String(output).split(/\r?\n/);
  const decisionLine = lines.map((line) => line.trim()).find((line) => line === 'ALLOW' || line === 'DENY');
  if (!decisionLine) throw new Error(`Cedar returned no ALLOW/DENY decision. Output: ${String(output).trim().slice(0, 1000)}`);
  const noteIndex = lines.findIndex((line) => line.trim().toLowerCase().startsWith('note:'));
  const policyIds = [];
  if (noteIndex >= 0) {
    for (const line of lines.slice(noteIndex + 1)) {
      if (!line.trim()) break;
      if (!/^\s/.test(line)) break;
      policyIds.push(line.trim());
    }
  }
  const decision = decisionLine.toLowerCase();
  const reason = policyIds.length
    ? `Cedar returned ${decisionLine}; determining policy ID(s): ${policyIds.join(', ')}.`
    : decision === 'deny'
      ? 'Cedar returned DENY; no determining policy ID was reported.'
      : 'Cedar returned ALLOW.';
  return { decision, reason, rule_id: policyIds.length ? policyIds.join(', ') : undefined, policy_ids: policyIds };
}

function evaluate(policyFile, fixture, files, label, enginePaths) {
  const args = [
    'authorize', '--policies', policyFile, '--entities', enginePaths.entitiesPath, '--request-json', files.requestPath,
    '--error-format', 'plain', '--verbose',
  ];
  if (enginePaths.schemaPath) args.push('--schema', enginePaths.schemaPath, '--schema-format', schemaFormat);
  if (enginePaths.templateLinkedPath) args.push('--template-linked', enginePaths.templateLinkedPath);
  const result = spawnSync(cedarBinary, args, {
    encoding: 'utf8', env: cedarEnvironment, maxBuffer: 2_000_000, timeout: timeoutMs, windowsHide: true,
  });
  if (result.error) throw result.error;
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '').trim();
  if (result.signal || result.status === null) {
    throw new Error(stderr || stdout.trim() || `Cedar process ended without an exit status${result.signal ? ` (signal ${result.signal})` : ''}.`);
  }
  try {
    const parsed = parseCedarOutput(stdout);
    const expectedExitStatus = parsed.decision === 'allow' ? 0 : 2;
    if (result.status !== expectedExitStatus) {
      const detail = stderr || `Cedar returned ${parsed.decision.toUpperCase()} with unexpected exit code ${result.status} (expected ${expectedExitStatus}).`;
      throw new Error(detail);
    }
    return parsed;
  } catch (error) {
    throw new Error(`${label} policy returned an unsupported result for "${fixture.name}": ${error instanceof Error ? error.message : String(error)}`);
  }
}

const results = [];
for (const [index, fixture] of fixtureSet.fixtures.entries()) {
  try {
    const files = cedarRequestFiles(fixture, index);
    const baseline = baselinePolicyPath ? evaluate(
      baselinePolicyPath,
      fixture,
      files,
      'Baseline',
      { entitiesPath: files.fixtureEntitiesPath ?? baselineEntitiesPath ?? entitiesPath, schemaPath: baselineSchemaPath ?? schemaPath, templateLinkedPath: baselineTemplateLinkedPath ?? templateLinkedPath },
    ) : undefined;
    const candidate = evaluate(
      policyPath,
      fixture,
      files,
      'Candidate',
      { entitiesPath: files.fixtureEntitiesPath ?? entitiesPath, schemaPath, templateLinkedPath },
    );
    const changed = Boolean(baseline && baseline.decision !== candidate.decision);
    const newAllow = Boolean(baseline && baseline.decision !== 'allow' && candidate.decision === 'allow');
    const expectedMatches = candidate.decision === fixture.expected;
    const rejectedNewAllow = failOnUnexpectedNewAllow && newAllow && fixture.expected !== 'allow';
    const rejectedChange = failOnAnyChange && changed;
    const changeType = !changed ? undefined : newAllow ? 'new_allow' : baseline.decision === 'allow' ? 'allow_reduced' : 'changed';
    results.push({
      id: fixture.id,
      name: fixture.name,
      category: fixture.category,
      severity: fixture.severity,
      expected: fixture.expected,
      actual: candidate.decision,
      baseline_actual: baseline?.decision,
      baseline_reason: baseline?.reason,
      baseline_rule_id: baseline?.rule_id,
      baseline_policy_ids: baseline?.policy_ids,
      changed,
      new_allow: newAllow,
      change_type: changeType,
      passed: expectedMatches && !rejectedNewAllow && !rejectedChange,
      rationale: fixture.rationale,
      reason: candidate.reason,
      rule_id: candidate.rule_id,
      policy_ids: candidate.policy_ids,
    });
  } catch (error) {
    const e = error && typeof error === 'object' ? error : {};
    if (e.code === 'ENOENT') {
      console.error(`Cedar executable not found (${cedarBinary}). Install the Cedar CLI or set CEDAR_BIN to its path.`);
    } else {
      console.error(`Cedar evaluation failed for "${fixture.name}" (${baselinePolicyPath ? 'baseline/candidate' : 'candidate'}): ${processErrorDetail(error)}`);
    }
    process.exit(2);
  }
}

const passedCount = results.filter((result) => result.passed).length;
const changedCount = results.filter((result) => result.changed).length;
const newAllowCount = results.filter((result) => result.new_allow).length;
if (format === 'json') {
  console.log(JSON.stringify({
    version: 1,
    engine: 'cedar',
    pack: fixtureSet.pack,
    policy: policyPath,
    baseline_policy: baselinePolicyPath,
    entities: entitiesPath,
    baseline_entities: baselinePolicyPath ? baselineEntitiesPath ?? entitiesPath : undefined,
    schema: schemaPath,
    baseline_schema: baselinePolicyPath ? baselineSchemaPath ?? schemaPath : undefined,
    summary: { passed: passedCount, failed: results.length - passedCount, total: results.length, changed: changedCount, new_allows: newAllowCount },
    results,
  }, null, 2));
} else if (format === 'github') {
  process.stdout.write(renderGitHubSummary({ engine: 'cedar', pack: fixtureSet.pack, results }));
} else {
  for (const result of results) {
    const baseline = baselinePolicyPath ? `; baseline ${result.baseline_actual} (${result.baseline_rule_id ?? 'no policy id'}) -> candidate ${result.actual} (${result.rule_id ?? 'no policy id'})${result.change_type ? ` (${result.change_type})` : ''}` : '';
    console.log(`${result.passed ? 'PASS' : 'FAIL'}  ${result.id ? `[${result.id}] ` : ''}${result.name}: expected ${result.expected}, received ${result.actual}${baseline}`);
    if (!result.passed && result.rationale) console.error(`      Pack rationale: ${result.rationale}`);
  }
  console.log(`\n${passedCount}/${results.length} Cedar fixtures passed.`);
}
if (passedCount !== results.length) process.exitCode = 1;
