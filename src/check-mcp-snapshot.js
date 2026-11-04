#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { basename, isAbsolute, resolve } from 'node:path';

const maxSnapshotBytes = 10 * 1024 * 1024;
const valueOptions = new Set(['--baseline', '--candidate', '--format']);
const flagOptions = new Set(['--fail-on-any-change']);
const options = new Map();

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireString(value, label, path) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error('Invalid MCP snapshot in ' + path + ': ' + label + ' must be a non-empty string.');
  }
}

function parseOptions(args) {
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
  for (const required of ['--baseline', '--candidate']) {
    if (!options.has(required)) throw new Error('MCP snapshot comparison requires ' + required + ' <path>.');
  }
}

function canonicalJson(value, depth = 0) {
  if (depth > 128) throw new Error('Snapshot data exceeds the maximum nesting depth of 128.');
  if (Array.isArray(value)) return '[' + value.map((entry) => canonicalJson(entry, depth + 1)).join(',') + ']';
  if (isRecord(value)) {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key], depth + 1)).join(',') + '}';
  }
  return JSON.stringify(value);
}

function readSnapshot(pathArgument, label) {
  const path = isAbsolute(pathArgument) ? pathArgument : resolve(process.cwd(), pathArgument);
  let size;
  try {
    size = statSync(path).size;
  } catch (error) {
    throw new Error('Could not read ' + label + ' snapshot "' + path + '": ' + (error instanceof Error ? error.message : String(error)));
  }
  if (size > maxSnapshotBytes) throw new Error(label + ' snapshot exceeds the 10 MB size limit: ' + path);

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error('Could not parse ' + label + ' snapshot "' + path + '": ' + (error instanceof Error ? error.message : String(error)));
  }
  if (isRecord(parsed) && parsed.version === '1' && typeof parsed.server_id === 'string' && Array.isArray(parsed.tools)) {
    parsed = { version: parsed.version, servers: [{ server_id: parsed.server_id, tools: parsed.tools }] };
  }
  if (!isRecord(parsed) || parsed.version !== '1' || !Array.isArray(parsed.servers) || parsed.servers.length === 0) {
    throw new Error('Invalid MCP snapshot in ' + path + ': expected version "1" and a non-empty servers array.');
  }

  const serverIds = new Set();
  const toolKeys = new Set();
  for (const [serverIndex, server] of parsed.servers.entries()) {
    const serverLabel = 'servers[' + serverIndex + ']';
    if (!isRecord(server)) throw new Error('Invalid MCP snapshot in ' + path + ': ' + serverLabel + ' must be an object.');
    requireString(server.server_id, serverLabel + '.server_id', path);
    if (serverIds.has(server.server_id)) throw new Error('Invalid MCP snapshot in ' + path + ': duplicate server_id "' + server.server_id + '".');
    serverIds.add(server.server_id);
    if (!Array.isArray(server.tools)) throw new Error('Invalid MCP snapshot in ' + path + ': ' + serverLabel + '.tools must be an array.');

    for (const [toolIndex, tool] of server.tools.entries()) {
      const toolLabel = serverLabel + '.tools[' + toolIndex + ']';
      if (!isRecord(tool)) throw new Error('Invalid MCP snapshot in ' + path + ': ' + toolLabel + ' must be an object.');
      requireString(tool.name, toolLabel + '.name', path);
      if (!isRecord(tool.inputSchema)) throw new Error('Invalid MCP snapshot in ' + path + ': ' + toolLabel + '.inputSchema must be an object.');
      if (tool.outputSchema !== undefined && !isRecord(tool.outputSchema)) {
        throw new Error('Invalid MCP snapshot in ' + path + ': ' + toolLabel + '.outputSchema must be an object when supplied.');
      }
      if (tool.annotations !== undefined && !isRecord(tool.annotations)) {
        throw new Error('Invalid MCP snapshot in ' + path + ': ' + toolLabel + '.annotations must be an object when supplied.');
      }
      const key = JSON.stringify([server.server_id, tool.name]);
      if (toolKeys.has(key)) throw new Error('Invalid MCP snapshot in ' + path + ': duplicate tool "' + server.server_id + '/' + tool.name + '".');
      toolKeys.add(key);
    }
  }
  return { path, data: parsed };
}

function indexTools(snapshot) {
  const tools = new Map();
  for (const server of snapshot.servers) {
    for (const definition of server.tools) {
      tools.set(JSON.stringify([server.server_id, definition.name]), {
        server_id: server.server_id,
        tool_name: definition.name,
        definition,
      });
    }
  }
  return tools;
}

function fingerprint(definition) {
  return createHash('sha256').update(canonicalJson(definition)).digest('hex');
}

function changedFields(baseline, candidate) {
  const fields = [...new Set([...Object.keys(baseline), ...Object.keys(candidate)])].sort();
  return fields.filter((field) => {
    const baselineHasField = Object.hasOwn(baseline, field);
    const candidateHasField = Object.hasOwn(candidate, field);
    return baselineHasField !== candidateHasField
      || (baselineHasField && canonicalJson(baseline[field]) !== canonicalJson(candidate[field]));
  });
}

function markdownCell(value) {
  return String(value ?? '—')
    .replaceAll('&', '&amp;')
    .replaceAll('|', '\\|')
    .replace(/[\r\n]+/g, ' ')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function renderGitHubSummary(report) {
  const changeCount = report.summary.changes;
  const failedGate = report.fail_on_any_change && changeCount > 0;
  const icon = failedGate ? '❌' : changeCount > 0 ? '⚠️' : '✅';
  const lines = [
    '## ' + icon + ' MCP tool surface comparison',
    '**Baseline:** ' + markdownCell(basename(report.baseline)) + ' · **Candidate:** ' + markdownCell(basename(report.candidate)),
    '**Tools:** ' + report.summary.baseline_tools + ' → ' + report.summary.candidate_tools
      + ' · **Added:** ' + report.summary.added + ' · **Removed:** ' + report.summary.removed
      + ' · **Modified:** ' + report.summary.modified + ' · **Unchanged:** ' + report.summary.unchanged,
    '',
    '| Server ID | Tool | Change | Changed fields | Baseline SHA-256 | Candidate SHA-256 |',
    '| --- | --- | --- | --- | --- | --- |',
  ];
  for (const result of report.results) {
    lines.push('| ' + markdownCell(result.server_id)
      + ' | ' + markdownCell(result.tool_name)
      + ' | ' + markdownCell(result.change_type)
      + ' | ' + markdownCell(result.changed_fields.join(', '))
      + ' | ' + markdownCell(result.baseline_sha256)
      + ' | ' + markdownCell(result.candidate_sha256) + ' |');
  }
  if (changeCount === 0) lines.push('| — | — | No changes | — | — | — |');
  lines.push('');
  return lines.join('\n');
}

function main() {
  try {
    parseOptions(process.argv.slice(2));
    const format = options.get('--format') ?? 'text';
    if (!['text', 'json', 'github'].includes(format)) throw new Error('--format must be "text", "json", or "github".');

    const baseline = readSnapshot(options.get('--baseline'), 'Baseline');
    const candidate = readSnapshot(options.get('--candidate'), 'Candidate');
    const baselineTools = indexTools(baseline.data);
    const candidateTools = indexTools(candidate.data);
    const keys = [...new Set([...baselineTools.keys(), ...candidateTools.keys()])].sort();
    const results = [];
    let unchanged = 0;

    for (const key of keys) {
      const before = baselineTools.get(key);
      const after = candidateTools.get(key);
      let changeType;
      let fields;
      if (!before) {
        changeType = 'added';
        fields = Object.keys(after.definition).sort();
      } else if (!after) {
        changeType = 'removed';
        fields = Object.keys(before.definition).sort();
      } else {
        fields = changedFields(before.definition, after.definition);
        if (fields.length === 0) {
          unchanged += 1;
          continue;
        }
        changeType = 'modified';
      }
      results.push({
        server_id: (after ?? before).server_id,
        tool_name: (after ?? before).tool_name,
        change_type: changeType,
        changed_fields: fields,
        baseline_sha256: before ? fingerprint(before.definition) : undefined,
        candidate_sha256: after ? fingerprint(after.definition) : undefined,
      });
    }

    const summary = {
      baseline_tools: baselineTools.size,
      candidate_tools: candidateTools.size,
      added: results.filter((result) => result.change_type === 'added').length,
      removed: results.filter((result) => result.change_type === 'removed').length,
      modified: results.filter((result) => result.change_type === 'modified').length,
      unchanged,
      changes: results.length,
    };
    const report = {
      version: 1,
      engine: 'mcp-snapshot',
      baseline: baseline.path,
      candidate: candidate.path,
      fail_on_any_change: options.has('--fail-on-any-change'),
      summary,
      results,
    };

    if (format === 'json') {
      console.log(JSON.stringify(report, null, 2));
    } else if (format === 'github') {
      process.stdout.write(renderGitHubSummary(report));
    } else {
      for (const result of results) {
        console.log(result.change_type.toUpperCase() + '  ' + result.server_id + '/' + result.tool_name
          + ' · fields: ' + result.changed_fields.join(', ')
          + ' · baseline: ' + (result.baseline_sha256 ?? '—')
          + ' · candidate: ' + (result.candidate_sha256 ?? '—'));
      }
      console.log('\n' + summary.changes + ' changed; ' + summary.unchanged + ' unchanged'
        + ' (' + summary.added + ' added, ' + summary.removed + ' removed, ' + summary.modified + ' modified).');
    }

    if (report.fail_on_any_change && summary.changes > 0) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  }
}

main();
