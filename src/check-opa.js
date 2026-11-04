import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { opaFixtureInput, readFixtureSet } from './fixtures.js';
import { renderGitHubSummary } from './report.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const opaBinary = process.env.OPA_BIN || 'opa';
function processErrorDetail(error) {
  const e = error && typeof error === 'object' ? error : {};
  if (e.code === 'ETIMEDOUT' || e.killed) return `OPA process exceeded its ${e.timeout ?? 'configured'} ms timeout.`;
  const stderr = e.stderr ? String(e.stderr).trim() : '';
  if (stderr) return stderr;
  const stdout = e.stdout ? String(e.stdout).trim() : '';
  if (stdout) {
    try {
      const parsed = JSON.parse(stdout);
      if (Array.isArray(parsed.errors) && parsed.errors.length > 0) {
        return parsed.errors.map((item) => {
          const location = item.location
            ? ` at ${item.location.file ?? 'policy'}:${item.location.row ?? '?'}:${item.location.col ?? '?'}`
            : '';
          return `${item.code ?? 'OPA error'}${location}: ${item.message ?? 'unknown error'}`;
        }).join('; ');
      }
    } catch {
      // Preserve OPA's output when it is not a JSON error document.
    }
    return stdout;
  }
  return error instanceof Error ? error.message : String(error);
}
const options = new Map();
const valueOptions = new Set(['--policy', '--baseline-policy', '--data', '--baseline-data', '--query', '--fixtures', '--format', '--timeout-ms']);
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
const fixtureSet = readFixtureSet(root, options.get('--fixtures'));
const policyArg = options.get('--policy');
const policyPath = policyArg ? (isAbsolute(policyArg) ? policyArg : resolve(process.cwd(), policyArg)) : join(root, 'policy', 'agent_policy.rego');
const baselineArg = options.get('--baseline-policy');
const baselinePolicyPath = baselineArg ? (isAbsolute(baselineArg) ? baselineArg : resolve(process.cwd(), baselineArg)) : undefined;
const dataArg = options.get('--data');
const dataPath = dataArg ? (isAbsolute(dataArg) ? dataArg : resolve(process.cwd(), dataArg)) : undefined;
const baselineDataArg = options.get('--baseline-data');
const baselineDataPath = baselineDataArg ? (isAbsolute(baselineDataArg) ? baselineDataArg : resolve(process.cwd(), baselineDataArg)) : undefined;
const query = options.get('--query') ?? 'data.agent_policy.decision';
const format = options.get('--format') ?? 'text';
if (!['text', 'json', 'github'].includes(format)) throw new Error('--format must be "text", "json", or "github".');
if (!query.startsWith('data.')) throw new Error('The OPA query must address a data document, for example data.agent_policy.decision.');
const failOnUnexpectedNewAllow = options.has('--fail-on-unexpected-new-allow');
const failOnAnyChange = options.has('--fail-on-any-change');
if ((failOnUnexpectedNewAllow || failOnAnyChange) && !baselinePolicyPath) {
  throw new Error('Change-failure flags require --baseline-policy.');
}
if (baselineDataPath && !baselinePolicyPath) throw new Error('--baseline-data requires --baseline-policy.');
const timeoutMs = Number(options.get('--timeout-ms') ?? 10000);
if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) {
  throw new Error('--timeout-ms must be an integer from 100 to 120000.');
}

const opaEnvironment = {};
for (const key of ['PATH', 'PATHEXT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL']) {
  if (process.env[key] !== undefined) opaEnvironment[key] = process.env[key];
}
const temporaryPolicyDirectory = mkdtempSync(join(tmpdir(), 'agent-policy-opa-ci-'));
process.on('exit', () => {
  const resolvedTempRoot = resolve(tmpdir());
  const resolvedPolicyDirectory = resolve(temporaryPolicyDirectory);
  if (dirname(resolvedPolicyDirectory) === resolvedTempRoot && basename(resolvedPolicyDirectory).startsWith('agent-policy-opa-ci-')) {
    rmSync(resolvedPolicyDirectory, { recursive: true, force: true });
  }
});
const capabilitiesPath = join(temporaryPolicyDirectory, 'capabilities.json');
const disabledBuiltins = ['http.send', 'net.lookup_ip_addr', 'opa.runtime'];
try {
  const rawCapabilities = execFileSync(opaBinary, ['capabilities', '--current'], {
    encoding: 'utf8',
    env: opaEnvironment,
    maxBuffer: 2_000_000,
    timeout: 10000,
    windowsHide: true,
  });
  const capabilities = JSON.parse(rawCapabilities);
  if (!Array.isArray(capabilities.builtins)) throw new Error('OPA returned an invalid capabilities document.');
  capabilities.builtins = capabilities.builtins.filter((builtin) => !disabledBuiltins.includes(builtin.name));
  writeFileSync(capabilitiesPath, JSON.stringify(capabilities), { encoding: 'utf8', flag: 'wx' });
} catch (error) {
  const e = error && typeof error === 'object' ? error : {};
  const detail = processErrorDetail(error);
  if (e.code === 'ENOENT') console.error(`OPA executable not found (${opaBinary}). Install OPA or set OPA_BIN to its path.`);
  else console.error(`Could not prepare restricted OPA capabilities: ${detail}`);
  process.exit(2);
}

const results = [];
function normalizeResult(value) {
  const validDecisions = new Set(['allow', 'deny', 'approval_required']);
  if (typeof value === 'boolean') {
    return { decision: value ? 'allow' : 'deny', reason: `OPA boolean query returned ${value}.` };
  }
  if (typeof value === 'string' && validDecisions.has(value)) {
    return { decision: value, reason: `OPA query returned the decision "${value}".` };
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && validDecisions.has(value.decision)) {
    const reason = typeof value.reason === 'string' && value.reason.trim()
      ? value.reason
      : `OPA query returned the decision "${value.decision}" without a policy explanation.`;
    return { decision: value.decision, reason, rule_id: typeof value.rule_id === 'string' ? value.rule_id : undefined };
  }
  throw new Error('OPA query must return a boolean, a canonical decision string, or an object with a canonical decision field.');
}

function evaluate(policyFile, input, fixture, label, policyDataPath) {
  const args = ['eval', '--format=json', '--stdin-input', '--strict-builtin-errors', '--capabilities', capabilitiesPath, '--data', policyFile];
  if (policyDataPath) args.push('--data', policyDataPath);
  args.push(query);
  const raw = execFileSync(opaBinary, args, { input: JSON.stringify(input), encoding: 'utf8', env: opaEnvironment, maxBuffer: 2_000_000, timeout: timeoutMs, windowsHide: true });
  const result = JSON.parse(raw);
  const value = result.result?.[0]?.expressions?.[0]?.value;
  try {
    return normalizeResult(value);
  } catch (error) {
    throw new Error(`${label} policy returned an unsupported result for "${fixture.name}": ${error instanceof Error ? error.message : String(error)}`);
  }
}

for (const [index, fixture] of fixtureSet.fixtures.entries()) {
  const input = opaFixtureInput(fixtureSet, fixture, index);
  try {
    const baseline = baselinePolicyPath ? evaluate(baselinePolicyPath, input, fixture, 'Baseline', baselineDataPath ?? dataPath) : undefined;
    const candidate = evaluate(policyPath, input, fixture, 'Candidate', dataPath);
    const changed = Boolean(baseline && baseline.decision !== candidate.decision);
    const newAllow = Boolean(baseline && baseline.decision !== 'allow' && candidate.decision === 'allow');
    const expectedMatches = candidate.decision === fixture.expected;
    const explanationProvided = Boolean(candidate.reason);
    const rejectedNewAllow = failOnUnexpectedNewAllow && newAllow && fixture.expected !== 'allow';
    const rejectedChange = failOnAnyChange && changed;
    const changeType = !changed ? undefined
      : newAllow ? 'new_allow'
        : baseline.decision === 'allow' ? 'allow_reduced'
          : candidate.decision === 'approval_required' ? 'deny_to_approval_required'
            : 'changed';
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
      changed,
      new_allow: newAllow,
      change_type: changeType,
      passed: expectedMatches && explanationProvided && !rejectedNewAllow && !rejectedChange,
      rationale: fixture.rationale,
      reason: candidate.reason,
      rule_id: candidate.rule_id,
    });
  } catch (error) {
    const e = error && typeof error === 'object' ? error : {};
    if (e.code === 'ENOENT') {
      console.error(`OPA executable not found (${opaBinary}). Install OPA or set OPA_BIN to its path.`);
    } else {
      console.error(`OPA evaluation failed for "${fixture.name}" (${baselinePolicyPath ? 'baseline/candidate' : 'candidate'}): ${processErrorDetail(error)}`);
    }
    process.exit(2);
  }
}

const passedCount = results.filter((result) => result.passed).length;
const changedCount = results.filter((result) => result.changed).length;
const newAllowCount = results.filter((result) => result.new_allow).length;
if (format === 'json') {
  console.log(JSON.stringify({ version: 1, engine: 'opa', pack: fixtureSet.pack, query, baseline_policy: baselinePolicyPath, baseline_data: baselinePolicyPath ? baselineDataPath ?? dataPath : undefined, policy_data: dataPath, security: { disabled_builtins: disabledBuiltins, timeout_ms: timeoutMs, inherited_environment: false }, summary: { passed: passedCount, failed: results.length - passedCount, total: results.length, changed: changedCount, new_allows: newAllowCount }, results }, null, 2));
} else if (format === 'github') {
  process.stdout.write(renderGitHubSummary({ engine: 'opa', pack: fixtureSet.pack, results }));
} else {
  for (const result of results) {
    const baseline = baselinePolicyPath ? `; baseline ${result.baseline_actual} (${result.baseline_rule_id ?? 'no rule id'}) -> candidate ${result.actual} (${result.rule_id ?? 'no rule id'})${result.change_type ? ` (${result.change_type})` : ''}` : '';
    console.log(`${result.passed ? 'PASS' : 'FAIL'}  ${result.id ? `[${result.id}] ` : ''}${result.name}: expected ${result.expected}, received ${result.actual}${baseline} (${result.rule_id ?? 'no rule id'})`);
    if (!result.reason) console.error(`      Missing explanation for ${result.name}.`);
    if (!result.passed && result.rationale) console.error(`      Pack rationale: ${result.rationale}`);
  }
  console.log(`\n${passedCount}/${results.length} OPA fixtures passed.`);
}
if (passedCount !== results.length) process.exitCode = 1;
