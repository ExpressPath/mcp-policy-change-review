import { readFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';

const decisions = new Set(['allow', 'deny', 'approval_required']);
const severities = new Set(['low', 'medium', 'high', 'critical']);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireString(value, label, path) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`Invalid fixture set in ${path}: ${label} must be a non-empty string.`);
}

function validateFixtureSet(parsed, path) {
  if (!isRecord(parsed) || parsed.version !== '1' || !isRecord(parsed.subjects) || !Array.isArray(parsed.fixtures) || parsed.fixtures.length === 0) {
    throw new Error(`Invalid fixture set in ${path}: expected version "1", a subjects object, and a non-empty fixtures array.`);
  }
  if (parsed.pack !== undefined) {
    if (!isRecord(parsed.pack)) throw new Error(`Invalid fixture set in ${path}: pack must be an object.`);
    for (const key of ['id', 'version', 'title', 'description']) requireString(parsed.pack[key], `pack.${key}`, path);
    if (parsed.pack.source !== undefined && typeof parsed.pack.source !== 'string') {
      throw new Error(`Invalid fixture set in ${path}: pack.source must be a string.`);
    }
  }

  for (const [key, subject] of Object.entries(parsed.subjects)) {
    if (!isRecord(subject)) throw new Error(`Invalid fixture set in ${path}: subjects.${key} must be an object.`);
    requireString(subject.id, `subjects.${key}.id`, path);
    if (!['active', 'revoked'].includes(subject.status)) throw new Error(`Invalid fixture set in ${path}: subjects.${key}.status must be "active" or "revoked".`);
    for (const field of ['allowed_tools', 'scopes']) {
      if (!Array.isArray(subject[field]) || subject[field].some((value) => typeof value !== 'string' || value.trim() === '')) {
        throw new Error(`Invalid fixture set in ${path}: subjects.${key}.${field} must be an array of non-empty strings.`);
      }
    }
  }

  const ids = new Set();
  for (const [index, fixture] of parsed.fixtures.entries()) {
    const label = isRecord(fixture) ? fixture.id ?? fixture.name ?? `fixtures[${index}]` : `fixtures[${index}]`;
    if (!isRecord(fixture)) throw new Error(`Invalid fixture set in ${path}: ${label} must be an object.`);
    if (fixture.id !== undefined) {
      requireString(fixture.id, `${label}.id`, path);
      if (ids.has(fixture.id)) throw new Error(`Invalid fixture set in ${path}: duplicate fixture id "${fixture.id}".`);
      ids.add(fixture.id);
    }
    for (const field of ['name', 'tool', 'action', 'resource']) requireString(fixture[field], `${label}.${field}`, path);
    if (fixture.subject !== null && (typeof fixture.subject !== 'string' || !Object.hasOwn(parsed.subjects, fixture.subject))) {
      throw new Error(`Invalid fixture set in ${path}: ${label}.subject must be null or name an entry in subjects.`);
    }
    if (!decisions.has(fixture.expected)) throw new Error(`Invalid fixture set in ${path}: ${label}.expected must be allow, deny, or approval_required.`);
    if (fixture.category !== undefined) requireString(fixture.category, `${label}.category`, path);
    if (fixture.severity !== undefined && !severities.has(fixture.severity)) {
      throw new Error(`Invalid fixture set in ${path}: ${label}.severity must be low, medium, high, or critical.`);
    }
    if (fixture.rationale !== undefined) requireString(fixture.rationale, `${label}.rationale`, path);
    if (fixture.mcp !== undefined) {
      if (!isRecord(fixture.mcp)) throw new Error(`Invalid fixture set in ${path}: ${label}.mcp must be an object.`);
      requireString(fixture.mcp.server_id, `${label}.mcp.server_id`, path);
      requireString(fixture.mcp.tool_name, `${label}.mcp.tool_name`, path);
      if (typeof fixture.mcp.annotations_trusted !== 'boolean') throw new Error(`Invalid fixture set in ${path}: ${label}.mcp.annotations_trusted must be a boolean.`);
      if (fixture.mcp.annotations !== undefined && !isRecord(fixture.mcp.annotations)) {
        throw new Error(`Invalid fixture set in ${path}: ${label}.mcp.annotations must be an object.`);
      }
    }
    if (fixture.mcp_binding !== undefined) {
      if (!isRecord(fixture.mcp_binding)) throw new Error(`Invalid fixture set in ${path}: ${label}.mcp_binding must be an object.`);
      if (fixture.mcp === undefined || !Object.hasOwn(fixture, 'opa_input')) {
        throw new Error(`Invalid fixture set in ${path}: ${label}.mcp_binding requires both mcp metadata and opa_input.`);
      }
      for (const field of ['opa_server_id_path', 'opa_tool_name_path']) {
        requireString(fixture.mcp_binding[field], `${label}.mcp_binding.${field}`, path);
        if (!fixture.mcp_binding[field].startsWith('/') || fixture.mcp_binding[field].length < 2) {
          throw new Error(`Invalid fixture set in ${path}: ${label}.mcp_binding.${field} must be a non-root JSON Pointer.`);
        }
      }
    }
    if (fixture.cedar_input !== undefined) {
      if (!isRecord(fixture.cedar_input) || !isRecord(fixture.cedar_input.request)) {
        throw new Error(`Invalid fixture set in ${path}: ${label}.cedar_input.request must be an object.`);
      }
      for (const field of ['principal', 'action', 'resource']) requireString(fixture.cedar_input.request[field], `${label}.cedar_input.request.${field}`, path);
      if (fixture.cedar_input.request.context !== undefined && !isRecord(fixture.cedar_input.request.context)) {
        throw new Error(`Invalid fixture set in ${path}: ${label}.cedar_input.request.context must be an object.`);
      }
      if (fixture.cedar_input.entities !== undefined && !Array.isArray(fixture.cedar_input.entities)) {
        throw new Error(`Invalid fixture set in ${path}: ${label}.cedar_input.entities must be an array.`);
      }
    }
  }
}

/**
 * @param {string} root
 * @param {string} [fixturePath]
 */
export function readFixtureSet(root, fixturePath) {
  const path = fixturePath
    ? (isAbsolute(fixturePath) ? fixturePath : resolve(process.cwd(), fixturePath))
    : join(root, 'policy-packs', 'mcp-agent-baseline.json');
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  validateFixtureSet(parsed, path);
  return parsed;
}

/**
 * @param {{ subjects: Record<string, object> }} set
 * @param {{ subject: string | null, name: string, tool: string, action: string, resource: string, mcp?: object }} fixture
 * @param {number} index
 */
export function fixtureInput(set, fixture, index) {
  const subject = fixture.subject === null ? null : set.subjects[fixture.subject];
  if (fixture.subject !== null && !subject) throw new Error(`Fixture "${fixture.name}" refers to unknown subject "${fixture.subject}".`);
  return {
    subject,
    action: { name: fixture.action },
    resource: { id: fixture.resource },
    context: {
      tool: fixture.tool,
      task_id: `fixture-${index + 1}`,
      ...(fixture.mcp ? { mcp: fixture.mcp } : {}),
    },
  };
}

/**
 * @param {{ subjects: Record<string, object> }} set
 * @param {{ opa_input?: unknown, subject: string | null, name: string, tool: string, action: string, resource: string, mcp?: object }} fixture
 * @param {number} index
 */
export function opaFixtureInput(set, fixture, index) {
  return Object.hasOwn(fixture, 'opa_input') ? fixture.opa_input : fixtureInput(set, fixture, index);
}
