import { appendFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const actionDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(actionDirectory, '../..');
const cli = resolve(packageRoot, 'bin', 'agent-policy-check.js');

function input(name) {
  return process.env['INPUT_' + name.toUpperCase()]?.trim() ?? '';
}

function appendOutput(name, value) {
  const path = process.env.GITHUB_OUTPUT;
  if (path) appendFileSync(path, name + '=' + value + '\n', { encoding: 'utf8' });
}

function booleanInput(name, defaultValue = false) {
  const value = input(name).toLowerCase();
  if (!value) return defaultValue;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error('Action input "' + name + '" must be "true" or "false".');
}

function main() {
  if (!input('manifest')) {
    console.error('Missing required action input: manifest.');
    appendOutput('passed', 'false');
    appendOutput('exit-code', '2');
    process.exitCode = 2;
    return;
  }

  let args;
  try {
    const requireCommon = booleanInput('require-common-cases', true);
    const requireCoverage = booleanInput('require-policy-coverage', true);
    const failNewAllow = booleanInput('fail-on-unexpected-new-allow', true);
    const failAnyChange = booleanInput('fail-on-any-policy-change');
    const failCandidateDivergence = booleanInput('fail-on-candidate-divergence');
    const failTransitionDivergence = booleanInput('fail-on-transition-divergence');
    args = ['mcp-multi-review', '--manifest', input('manifest'), '--format', 'github'];
    if (!requireCommon) args.push('--allow-missing-cases');
    if (requireCoverage) args.push('--require-policy-coverage');
    if (failNewAllow) args.push('--fail-on-unexpected-new-allow');
    if (failAnyChange) args.push('--fail-on-any-policy-change');
    if (failCandidateDivergence) args.push('--fail-on-candidate-divergence');
    if (failTransitionDivergence) args.push('--fail-on-transition-divergence');
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    appendOutput('passed', 'false');
    appendOutput('exit-code', '2');
    process.exitCode = 2;
    return;
  }

  const child = spawnSync(process.execPath, [cli, ...args], {
    cwd: process.env.GITHUB_WORKSPACE || process.cwd(),
    env: process.env,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (child.error) {
    console.error('Could not start MCP multi-plane review: ' + child.error.message);
    appendOutput('passed', 'false');
    appendOutput('exit-code', '2');
    process.exitCode = 2;
    return;
  }
  if (child.stderr) process.stderr.write(child.stderr);
  if (child.stdout) {
    process.stdout.write(child.stdout);
    if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, child.stdout, { encoding: 'utf8' });
  }
  const exitCode = child.status ?? 2;
  appendOutput('passed', exitCode === 0 ? 'true' : 'false');
  appendOutput('exit-code', String(exitCode));
  if (exitCode !== 0) process.exitCode = exitCode;
}

main();
