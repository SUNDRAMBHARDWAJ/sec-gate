const path = require('path');

// Language detection for @pensar/semgrep-node
function getLanguage(filePath) {
  if (filePath.endsWith('.go')) return 'go';
  if (filePath.endsWith('.py')) return 'python';
  if (filePath.endsWith('.ts') || filePath.endsWith('.tsx')) return 'ts';
  return 'js';
}

function normalizeSemgrepNodeFinding(issue, filePath) {
  return {
    checkId: issue.issueId || issue.rule || 'semgrep',
    path: filePath,
    line: issue.startLineNumber,
    message: issue.message,
    severity: issue.severity,
    owasp: issue.owasp || [],
    raw: issue
  };
}

async function runSemgrep({ files }) {
  let semgrepScan;
  try {
    semgrepScan = require('@pensar/semgrep-node').default;
  } catch {
    throw new Error(
      'sec-gate: @pensar/semgrep-node not found. Run `npm i -g sec-gate` again to reinstall.'
    );
  }

  const allFindings = [];

  for (const filePath of files) {
    const lang = getLanguage(filePath);
    const absPath = path.resolve(filePath);

    try {
      // Scan with OWASP Top 10 rules bundled inside @pensar/semgrep-node
      const issues = await semgrepScan(absPath, {
        language: lang,
        ruleSets: ['owasp-top10']
      });

      for (const issue of issues) {
        allFindings.push(normalizeSemgrepNodeFinding(issue, filePath));
      }
    } catch (err) {
      // If semgrep binary not yet downloaded for this platform, warn but don't crash.
      if (err && err.message && err.message.includes('ENOENT')) {
        console.warn(`sec-gate: semgrep binary not ready for ${lang}; skipping ${filePath}`);
      } else {
        throw err;
      }
    }
  }

  return allFindings;
}

module.exports = { runSemgrep };
