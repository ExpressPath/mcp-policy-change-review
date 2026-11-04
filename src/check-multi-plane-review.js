#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { closeSync, existsSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFixtureSet } from './fixtures.js';
import { spawnSync } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const cli = join(root, 'bin', 'agent-policy-check.js');
const maxManifestBytes = 1024 * 1024;
const maxSourceBytes = 256 * 1024 * 1024;
const valueOptions = new Set(['--manifest', '--format', '--report-file']);
const flagOptions = new Set([
  '--require-policy-coverage', '--fail-on-unexpected-new-allow', '--fail-on-any-policy-change',
  '--fail-on-candidate-divergence', '--fail-on-transition-divergence', '--allow-missing-cases',
]);
const engineOptions = {
  opa: new Set(['data', 'baseline_data', 'query', 'timeout_ms']),
  cedar: new Set([
    'entities', 'baseline_entities', 'schema', 'baseline_schema', 'schema_format',
    'template_linked', 'baseline_template_linked', 'timeout_ms',
  ]),
};
const pathOptions = new Set([
  'data', 'baseline_data', 'entities', 'baseline_entities', 'schema', 'baseline_schema',
  'template_linked', 'baseline_template_linked',
]);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(label + ' must be a non-empty string.');
}

function resolveWorkspacePath(value, label, baseDirectory, workspaceRoot) {
  requireString(value, label);
  const candidate = isAbsolute(value) ? value : resolve(baseDirectory, value);
  const canonicalPath = realpathSync(candidate);
  const relativePath = relative(workspaceRoot, canonicalPath);
  if (!relativePath || relativePath === '..' || relativePath.startsWith('..' + sep) || isAbsolute(relativePath)) {
    throw new Error(label + ' must resolve to a path inside the GitHub workspace.');
  }
  return canonicalPath;
}

function resolveReportPath(value, baseDirectory, workspaceRoot) {
  requireString(value, 'report file');
  if (/[\r\n]/.test(value)) throw new Error('The report file path cannot contain line breaks.');
  const candidate = isAbsolute(value) ? resolve(value) : resolve(baseDirectory, value);
  const relativeCandidate = relative(workspaceRoot, candidate);
  if (!relativeCandidate || relativeCandidate === '..' || relativeCandidate.startsWith('..' + sep) || isAbsolute(relativeCandidate)) {
    throw new Error('The report file must resolve to a new file inside the GitHub workspace.');
  }
  const parentPath = realpathSync(dirname(candidate));
  const relativeParent = relative(workspaceRoot, parentPath);
  if (relativeParent === '..' || relativeParent.startsWith('..' + sep) || isAbsolute(relativeParent)) {
    throw new Error('The report file must resolve to a new file inside the GitHub workspace.');
  }
  const reportPath = resolve(parentPath, basename(candidate));
  try {
    const existing = lstatSync(reportPath);
    if (existing.isSymbolicLink()) throw new Error('The report file cannot overwrite a symbolic link.');
    if (!existing.isFile()) throw new Error('The report file must be a new regular file.');
    throw new Error('The report file already exists; choose a fresh path so the Action never overwrites workspace content.');
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return reportPath;
    throw error;
  }
}

function writeReportFile(reportPath, report) {
  const descriptor = openSync(reportPath, 'wx', 0o600);
  try {
    writeFileSync(descriptor, JSON.stringify(report, null, 2) + '\n', { encoding: 'utf8' });
  } finally {
    closeSync(descriptor);
  }
}

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
    if (options.has(option)) throw new Error('Option supplied more than once: ' + option);
    options.set(option, value);
    index += 1;
  }
  if (!options.has('--manifest')) throw new Error('MCP multi-plane review requires --manifest <path>.');
  return options;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function hashInputPath(path) {
  if (!existsSync(path)) throw new Error('Evidence input does not exist: ' + path);
  const rootStat = lstatSync(path);
  if (rootStat.isSymbolicLink()) throw new Error('Evidence inputs cannot be symbolic links: ' + path);
  if (rootStat.isFile()) {
    if (rootStat.size > maxSourceBytes) throw new Error('Evidence input exceeds the 256 MiB fingerprint limit: ' + path);
    return { kind: 'file', sha256: sha256(readFileSync(path)), files: 1, bytes: rootStat.size };
  }
  if (!rootStat.isDirectory()) throw new Error('Evidence input must be a regular file or directory: ' + path);

  const files = [];
  let totalBytes = 0;
  function collect(directory, relativeDirectory) {
    const entries = readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      const absolute = join(directory, entry.name);
      const relativePath = relativeDirectory ? relativeDirectory + '/' + entry.name : entry.name;
      if (entry.isSymbolicLink()) throw new Error('Evidence directories cannot contain symbolic links: ' + absolute);
      if (entry.isDirectory()) {
        collect(absolute, relativePath);
      } else if (entry.isFile()) {
        const stat = lstatSync(absolute);
        totalBytes += stat.size;
        if (totalBytes > maxSourceBytes) throw new Error('Evidence directory exceeds the 256 MiB fingerprint limit: ' + path);
        files.push({ absolute, relative: relativePath.replaceAll('\\', '/'), size: stat.size });
        if (files.length > 100000) throw new Error('Evidence directory exceeds the 100,000-file fingerprint limit: ' + path);
      } else {
        throw new Error('Evidence directories cannot contain special files: ' + absolute);
      }
    }
  }
  collect(path, '');
  files.sort((a, b) => a.relative < b.relative ? -1 : a.relative > b.relative ? 1 : 0);
  const digest = createHash('sha256');
  for (const file of files) {
    digest.update(file.relative);
    digest.update('\0');
    digest.update(readFileSync(file.absolute));
    digest.update('\0');
  }
  return { kind: 'directory', sha256: digest.digest('hex'), files: files.length, bytes: totalBytes };
}

function resolveInput(value, label, manifestDirectory, workspaceRoot) {
  return resolveWorkspacePath(value, label, manifestDirectory, workspaceRoot);
}

function loadManifest(manifestPath) {
  const stat = lstatSync(manifestPath);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error('The manifest must be a regular file.');
  if (stat.size > maxManifestBytes) throw new Error('The manifest exceeds the 1 MiB size limit.');
  const bytes = readFileSync(manifestPath);
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error('Could not parse the multi-plane manifest: ' + (error instanceof Error ? error.message : String(error)));
  }
  if (!isRecord(manifest) || manifest.version !== '1' || !Array.isArray(manifest.control_planes)) {
    throw new Error('The manifest must use version "1" and contain a control_planes array.');
  }
  if (manifest.control_planes.length < 2 || manifest.control_planes.length > 32) {
    throw new Error('The manifest must define between 2 and 32 control planes.');
  }
  const allowedTopLevel = new Set(['version', 'control_planes']);
  const unknownTopLevel = Object.keys(manifest).find((key) => !allowedTopLevel.has(key));
  if (unknownTopLevel) throw new Error('Unknown manifest field: ' + unknownTopLevel);

  const ids = new Set();
  for (const [index, plane] of manifest.control_planes.entries()) {
    const label = 'control_planes[' + index + ']';
    if (!isRecord(plane)) throw new Error(label + ' must be an object.');
    const allowedPlane = new Set([
      'id', 'label', 'engine', 'baseline_snapshot', 'candidate_snapshot', 'baseline_policy', 'policy', 'fixtures', 'options',
    ]);
    const unknownPlane = Object.keys(plane).find((key) => !allowedPlane.has(key));
    if (unknownPlane) throw new Error(label + ' contains unknown field ' + unknownPlane + '.');
    requireString(plane.id, label + '.id');
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(plane.id)) throw new Error(label + '.id may contain only letters, digits, dot, underscore, colon, and hyphen.');
    if (ids.has(plane.id)) throw new Error('Duplicate control plane id: ' + plane.id);
    ids.add(plane.id);
    if (plane.label !== undefined) requireString(plane.label, label + '.label');
    if (!['opa', 'cedar'].includes(plane.engine)) throw new Error(label + '.engine must be "opa" or "cedar".');
    for (const field of ['baseline_snapshot', 'candidate_snapshot', 'baseline_policy', 'policy', 'fixtures']) {
      requireString(plane[field], label + '.' + field);
    }
    if (plane.options !== undefined && !isRecord(plane.options)) throw new Error(label + '.options must be an object.');
    for (const key of Object.keys(plane.options ?? {})) {
      if (!engineOptions[plane.engine].has(key)) throw new Error(label + '.options.' + key + ' is not valid for the ' + plane.engine + ' engine.');
      const value = plane.options[key];
      if ((typeof value !== 'string' && typeof value !== 'number') || String(value).trim() === '') {
        throw new Error(label + '.options.' + key + ' must be a non-empty string or number.');
      }
    }
  }
  return { manifest, bytes };
}

function validateFixtureIds(fixturePath, planeId) {
  const fixtureSet = readFixtureSet(root, fixturePath);
  const seen = new Set();
  for (const [index, fixture] of fixtureSet.fixtures.entries()) {
    if (typeof fixture.id !== 'string' || fixture.id.trim() === '') {
      throw new Error('Every fixture in control plane "' + planeId + '" must have an id used as its cross-plane scenario key (fixtures[' + index + ']).');
    }
    if (seen.has(fixture.id)) throw new Error('Duplicate scenario id "' + fixture.id + '" in control plane "' + planeId + '".');
    seen.add(fixture.id);
  }
  return fixtureSet;
}

function inputDefinitions(plane) {
  const definitions = [
    ['baseline_snapshot', plane.baseline_snapshot],
    ['candidate_snapshot', plane.candidate_snapshot],
    ['baseline_policy', plane.baseline_policy],
    ['policy', plane.policy],
    ['fixtures', plane.fixtures],
  ];
  for (const [key, value] of Object.entries(plane.options ?? {})) {
    if (pathOptions.has(key)) definitions.push([key, value]);
  }
  return definitions;
}

function preparePlane(plane, index, manifestDirectory, workspaceRoot) {
  const label = 'control_planes[' + index + ']';
  const resolved = {};
  const sourceHashes = [];
  for (const [role, value] of inputDefinitions(plane)) {
    const inputPath = resolveInput(value, label + '.' + role, manifestDirectory, workspaceRoot);
    resolved[role] = inputPath;
    sourceHashes.push({ role, ...hashInputPath(inputPath) });
  }
  const resolvedOptions = {};
  for (const [key, value] of Object.entries(plane.options ?? {})) {
    if (pathOptions.has(key)) resolvedOptions[key] = resolved[key];
    else resolvedOptions[key] = String(value);
  }
  const fixtureSet = validateFixtureIds(resolved.fixtures, plane.id);
  return {
    id: plane.id,
    label: plane.label ?? plane.id,
    engine: plane.engine,
    resolved,
    engineOptions: resolvedOptions,
    sourcePaths: sourceHashes.map(({ role }) => ({ role, path: resolved[role] })),
    fixtureIds: fixtureSet.fixtures.map((fixture) => fixture.id),
    sourceHashes,
  };
}

function childArgs(plane, gates) {
  const args = [
    'mcp-review', '--engine', plane.engine,
    '--baseline-snapshot', plane.resolved.baseline_snapshot,
    '--candidate-snapshot', plane.resolved.candidate_snapshot,
    '--baseline-policy', plane.resolved.baseline_policy,
    '--policy', plane.resolved.policy,
    '--fixtures', plane.resolved.fixtures,
  ];
  for (const [key, value] of Object.entries(plane.engineOptions)) {
    args.push('--' + key.replaceAll('_', '-'), String(value));
  }
  if (gates.require_policy_coverage) args.push('--require-policy-coverage');
  if (gates.fail_on_unexpected_new_allow) args.push('--fail-on-unexpected-new-allow');
  if (gates.fail_on_any_policy_change) args.push('--fail-on-any-policy-change');
  args.push('--format', 'json');
  return args;
}

function summarizeReview(review) {
  return {
    passed: review.summary.passed,
    tool_changes: review.summary.tool_changes,
    covered_tools: review.summary.covered_tools,
    incomplete_tools: review.summary.incomplete_tools,
    policy_passed: review.summary.policy_passed,
    policy_failed: review.summary.policy_failed,
    policy_total: review.policy.summary.total,
    policy_decision_changes: review.policy.summary.changed,
    policy_new_allows: review.policy.summary.new_allows,
    inventory_changes: review.inventory.results.map((item) => ({
      server_id: item.server_id,
      tool_name: item.tool_name,
      change_type: item.change_type,
      changed_fields: item.changed_fields,
      fingerprint: item.fingerprint,
    })),
    tool_reviews: review.tool_reviews.map((item) => ({
      server_id: item.server_id,
      tool_name: item.tool_name,
      change_type: item.change_type,
      changed_fields: item.changed_fields,
      coverage: item.coverage,
      cases: item.policy_cases.map((entry) => ({
        id: entry.result.id ?? entry.fixture.id,
        expected: entry.fixture.expected,
        baseline_actual: entry.result.baseline_actual,
        actual: entry.result.actual,
        passed: entry.result.passed,
      })),
    })),
    policy_results: review.policy.results.map((item) => ({
      id: item.id,
      severity: item.severity,
      expected: item.expected,
      baseline_actual: item.baseline_actual,
      actual: item.actual,
      changed: item.changed,
      new_allow: item.new_allow,
      change_type: item.change_type,
      passed: item.passed,
    })),
  };
}

function runPlane(plane, gates) {
  const child = spawnSync(process.execPath, [cli, ...childArgs(plane, gates)], {
    cwd: process.cwd(),
    env: process.env,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (child.error) {
    return { status: 'error', exit_code: 2, error: 'Could not start the review runner; see command stderr for details.' };
  }
  if (child.status === null) return { status: 'error', exit_code: 2, error: 'Review runner ended without an exit code.' };
  let review;
  try {
    review = JSON.parse(child.stdout);
  } catch {
    if (child.stderr) process.stderr.write(child.stderr);
    return { status: 'error', exit_code: child.status === 1 ? 2 : child.status, error: 'The ' + plane.engine.toUpperCase() + ' review did not return a JSON report; see command stderr for details.' };
  }
  if (![0, 1].includes(child.status) || !review.summary || !Array.isArray(review.policy?.results)) {
    return { status: 'error', exit_code: child.status || 2, error: 'The ' + plane.engine.toUpperCase() + ' review returned an invalid report or execution error.' };
  }
  return {
    status: review.summary.passed ? 'passed' : 'failed',
    exit_code: child.status,
    summary: summarizeReview(review),
  };
}

function buildScenarios(planes) {
  const scenarios = new Map();
  for (const plane of planes) {
    for (const result of plane.summary?.policy_results ?? []) {
      const id = result.id;
      if (!id) continue;
      if (!scenarios.has(id)) scenarios.set(id, { id, results: Object.create(null) });
      scenarios.get(id).results[plane.id] = {
        engine: plane.engine,
        expected: result.expected,
        baseline: result.baseline_actual,
        candidate: result.actual,
        changed: result.changed,
        passed: result.passed,
      };
    }
  }
  return [...scenarios.values()].sort((a, b) => a.id.localeCompare(b.id)).map((scenario) => {
    const present = planes.filter((plane) => Object.hasOwn(scenario.results, plane.id));
    const missing = planes.filter((plane) => !Object.hasOwn(scenario.results, plane.id)).map((plane) => plane.id);
    const unique = (values) => [...new Set(values.filter((value) => value !== undefined).map(String))].sort();
    const baselines = unique(present.map((plane) => scenario.results[plane.id].baseline));
    const candidates = unique(present.map((plane) => scenario.results[plane.id].candidate));
    const expectations = unique(present.map((plane) => scenario.results[plane.id].expected));
    const transitions = unique(present.map((plane) => scenario.results[plane.id].baseline + ' → ' + scenario.results[plane.id].candidate));
    return {
      id: scenario.id,
      results: scenario.results,
      missing_control_planes: missing,
      baseline_divergence: baselines.length > 1,
      candidate_divergence: candidates.length > 1,
      transition_divergence: transitions.length > 1,
      expected_divergence: expectations.length > 1,
    };
  });
}

function markdownCell(value) {
  return String(value ?? '—').replaceAll('&', '&amp;').replaceAll('|', '\\|')
    .replace(/[\r\n]+/g, ' ').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

function renderText(report) {
  const lines = [
    'MCP cross-control-plane change review',
    'Evidence SHA-256: ' + report.evidence.sha256 + ' (unsigned fingerprint)',
    'Control planes: ' + report.summary.control_planes_passed + '/' + report.summary.control_planes + ' passed; '
      + report.summary.candidate_divergences + ' candidate divergences; ' + report.summary.transition_divergences + ' transition divergences.',
    '',
  ];
  for (const plane of report.control_planes) {
    lines.push(plane.id + ' [' + plane.engine + ']: ' + plane.status
      + (plane.summary ? ' · ' + plane.summary.policy_passed + '/' + plane.summary.policy_total + ' policy cases · '
        + plane.summary.tool_changes + ' tool changes · ' + plane.summary.covered_tools + ' covered' : ' · ' + plane.error));
  }
  lines.push('', 'Scenario matrix:');
  for (const scenario of report.scenarios) {
    const outcomes = Object.entries(scenario.results).map(([id, result]) => id + ' ' + result.baseline + ' → ' + result.candidate).join('; ');
    lines.push(scenario.id + ': ' + (outcomes || 'no results')
      + (scenario.missing_control_planes.length ? '; missing ' + scenario.missing_control_planes.join(', ') : '')
      + (scenario.candidate_divergence ? '; candidate divergence' : '')
      + (scenario.transition_divergence ? '; transition divergence' : ''));
  }
  return lines.join('\n');
}

function renderGitHub(report) {
  const emoji = report.summary.passed ? '✅' : '❌';
  const lines = [
    '## ' + emoji + ' MCP cross-control-plane change review',
    '**Result:** ' + report.summary.control_planes_passed + '/' + report.summary.control_planes + ' control planes passed'
      + ' · **Candidate divergences:** ' + report.summary.candidate_divergences
      + ' · **Transition divergences:** ' + report.summary.transition_divergences,
    '**Evidence SHA-256:** `' + report.evidence.sha256 + '` (unsigned fingerprint)',
    '',
    '| Control plane | Engine | Policy cases | MCP changes | Coverage | Result |',
    '| --- | --- | ---: | ---: | ---: | --- |',
  ];
  for (const plane of report.control_planes) {
    lines.push('| ' + markdownCell(plane.label) + ' (`' + markdownCell(plane.id) + '`)' + ' | ' + markdownCell(plane.engine)
      + ' | ' + markdownCell(plane.summary ? plane.summary.policy_passed + '/' + plane.summary.policy_total : 'error')
      + ' | ' + markdownCell(plane.summary?.tool_changes ?? '—')
      + ' | ' + markdownCell(plane.summary ? plane.summary.covered_tools + '/' + plane.summary.tool_changes : '—')
      + ' | ' + markdownCell(plane.status) + ' |');
  }
  lines.push('', '| Scenario | Baseline → candidate by control plane | Missing planes | Expected divergence | Candidate divergence | Transition divergence |',
    '| --- | --- | --- | --- | --- | --- |');
  for (const scenario of report.scenarios) {
    const decisions = Object.entries(scenario.results).map(([id, result]) => id + ': ' + result.baseline + ' → ' + result.candidate).join('; ');
    lines.push('| ' + markdownCell(scenario.id) + ' | ' + markdownCell(decisions || '—')
      + ' | ' + markdownCell(scenario.missing_control_planes.join(', ') || '—')
      + ' | ' + (scenario.expected_divergence ? 'yes' : 'no')
      + ' | ' + (scenario.candidate_divergence ? 'yes' : 'no')
      + ' | ' + (scenario.transition_divergence ? 'yes' : 'no') + ' |');
  }
  lines.push('', 'Input and result hashes identify the reviewed material; they do not sign or authenticate it.');
  return lines.join('\n') + '\n';
}

function main() {
  try {
    const options = parseOptions(process.argv.slice(2));
    const format = options.get('--format') ?? 'text';
    if (!['text', 'json', 'github'].includes(format)) throw new Error('--format must be "text", "json", or "github".');
    const workspaceRoot = realpathSync(process.env.GITHUB_WORKSPACE || process.cwd());
    const reportPath = options.has('--report-file')
      ? resolveReportPath(options.get('--report-file'), process.cwd(), workspaceRoot)
      : undefined;
    const manifestPath = resolveWorkspacePath(options.get('--manifest'), 'manifest', process.cwd(), workspaceRoot);
    const { manifest, bytes } = loadManifest(manifestPath);
    const manifestDirectory = dirname(manifestPath);
    const prepared = manifest.control_planes.map((plane, index) => preparePlane(plane, index, manifestDirectory, workspaceRoot));
    const gates = {
      require_policy_coverage: options.has('--require-policy-coverage'),
      fail_on_unexpected_new_allow: options.has('--fail-on-unexpected-new-allow'),
      fail_on_any_policy_change: options.has('--fail-on-any-policy-change'),
    };

    const controlPlanes = [];
    for (const plane of prepared) {
      const result = runPlane(plane, gates);
      controlPlanes.push({
        id: plane.id,
        label: plane.label,
        engine: plane.engine,
        status: result.status,
        exit_code: result.exit_code,
        ...(result.summary ? { summary: result.summary } : { error: result.error }),
      });
    }
    let sourceInputsStable = true;
    try {
      if (hashInputPath(manifestPath).sha256 !== sha256(bytes)) sourceInputsStable = false;
    } catch {
      sourceInputsStable = false;
    }
    for (const plane of prepared) {
      for (const source of plane.sourceHashes) {
        const sourcePath = plane.sourcePaths.find((entry) => entry.role === source.role)?.path;
        try {
          if (!sourcePath || hashInputPath(sourcePath).sha256 !== source.sha256) sourceInputsStable = false;
        } catch {
          sourceInputsStable = false;
        }
      }
    }
    const scenarios = buildScenarios(controlPlanes);
    const missingScenarios = scenarios.filter((scenario) => scenario.missing_control_planes.length > 0).length;
    const candidateDivergences = scenarios.filter((scenario) => scenario.candidate_divergence).length;
    const transitionDivergences = scenarios.filter((scenario) => scenario.transition_divergence).length;
    const errorPlanes = controlPlanes.filter((plane) => plane.status === 'error').length;
    const failedPlanes = controlPlanes.filter((plane) => plane.status === 'failed').length;
    const gatesPassed = (!options.has('--fail-on-candidate-divergence') || candidateDivergences === 0)
      && (!options.has('--fail-on-transition-divergence') || transitionDivergences === 0)
      && (options.has('--allow-missing-cases') || missingScenarios === 0);
    const summary = {
      passed: errorPlanes === 0 && failedPlanes === 0 && gatesPassed && sourceInputsStable,
      complete: errorPlanes === 0,
      source_inputs_stable: sourceInputsStable,
      control_planes: controlPlanes.length,
      control_planes_passed: controlPlanes.filter((plane) => plane.status === 'passed').length,
      control_planes_failed: failedPlanes,
      control_planes_errored: errorPlanes,
      scenarios: scenarios.length,
      scenarios_missing_control_planes: missingScenarios,
      candidate_divergences: candidateDivergences,
      transition_divergences: transitionDivergences,
      gates: {
        require_policy_coverage: gates.require_policy_coverage,
        fail_on_unexpected_new_allow: gates.fail_on_unexpected_new_allow,
        fail_on_any_policy_change: gates.fail_on_any_policy_change,
        fail_on_candidate_divergence: options.has('--fail-on-candidate-divergence'),
        fail_on_transition_divergence: options.has('--fail-on-transition-divergence'),
        require_common_scenarios: !options.has('--allow-missing-cases'),
      },
    };
    const manifestHash = sha256(bytes);
    const sourceHashes = prepared.map((plane) => ({ control_plane_id: plane.id, sources: plane.sourceHashes }));
    const evidenceBody = { manifest_sha256: manifestHash, source_hashes: sourceHashes, control_planes: controlPlanes, scenarios, summary };
    const report = {
      version: 1,
      engine: 'mcp-multi-review',
      evidence: {
        algorithm: 'SHA-256',
        manifest_sha256: manifestHash,
        source_hashes: sourceHashes,
        sha256: sha256(JSON.stringify(evidenceBody)),
        signed: false,
        source_inputs_stable: sourceInputsStable,
      },
      control_planes: controlPlanes,
      scenarios,
      summary,
    };
    if (format === 'json') console.log(JSON.stringify(report, null, 2));
    else if (format === 'github') process.stdout.write(renderGitHub(report));
    else console.log(renderText(report));
    if (reportPath && errorPlanes === 0) writeReportFile(reportPath, report);
    if (!summary.passed) process.exitCode = errorPlanes > 0 ? 2 : 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  }
}

main();
