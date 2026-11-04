function markdownCell(value) {
  return String(value ?? '—')
    .replaceAll('|', '\\|')
    .replace(/[\r\n]+/g, ' ')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

/**
 * @param {{ engine: string, pack?: { id: string, version: string, title: string }, results: Array<{ id?: string, name: string, severity?: string, expected: string, actual: string, passed: boolean, rationale?: string, baseline_actual?: string, baseline_rule_id?: string, rule_id?: string, changed?: boolean, new_allow?: boolean, change_type?: string }> }} report
 */
export function renderGitHubSummary(report) {
  const passed = report.results.filter((result) => result.passed).length;
  const failed = report.results.length - passed;
  const hasBaseline = report.results.some((result) => result.baseline_actual !== undefined);
  const changes = report.results.filter((result) => result.changed).length;
  const newAllows = report.results.filter((result) => result.new_allow).length;
  const title = report.pack?.title ?? 'Agent policy replay';
  const heading = failed === 0 ? '✅' : '❌';
  const lines = [
    `## ${heading} ${markdownCell(title)}`,
    `**Engine:** ${markdownCell(report.engine)} · **Pack:** ${markdownCell(report.pack?.id)} v${markdownCell(report.pack?.version)} · **Result:** ${passed}/${report.results.length} passed${hasBaseline ? ` · **Decision changes:** ${changes} · **New allows:** ${newAllows}` : ''}`,
    '',
    hasBaseline
      ? '| Case | Severity | Baseline | Candidate | Expected | Baseline rule | Candidate rule | Result |'
      : '| Case | Severity | Expected | Actual | Result |',
    hasBaseline
      ? '| --- | --- | --- | --- | --- | --- | --- | --- |'
      : '| --- | --- | --- | --- | --- |',
  ];

  for (const result of report.results) {
    const label = result.id ? `${result.id}: ${result.name}` : result.name;
    const status = `${result.passed ? 'PASS' : 'FAIL'}${result.changed ? ` · ${markdownCell(result.change_type ?? 'changed')}` : ''}`;
    lines.push(hasBaseline
      ? `| ${markdownCell(label)} | ${markdownCell(result.severity)} | ${markdownCell(result.baseline_actual)} | ${markdownCell(result.actual)} | ${markdownCell(result.expected)} | ${markdownCell(result.baseline_rule_id)} | ${markdownCell(result.rule_id)} | ${status} |`
      : `| ${markdownCell(label)} | ${markdownCell(result.severity)} | ${markdownCell(result.expected)} | ${markdownCell(result.actual)} | ${status} |`);
  }

  if (failed > 0) {
    lines.push('', '### Cases needing review');
    for (const result of report.results.filter((entry) => !entry.passed)) {
      const comparison = result.baseline_actual !== undefined ? ` (${markdownCell(result.baseline_actual)} → ${markdownCell(result.actual)}; ${markdownCell(result.baseline_rule_id)} → ${markdownCell(result.rule_id)})` : '';
      lines.push(`- **${markdownCell(result.id ?? result.name)}**${comparison} — ${markdownCell(result.rationale ?? 'Decision did not match the expected result.')}`);
    }
  }
  lines.push('');
  return lines.join('\n');
}
