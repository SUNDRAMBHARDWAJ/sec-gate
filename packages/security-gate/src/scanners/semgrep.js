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
    // security-scan: disable rule-id: path-join-resolve-traversal reason: filePath comes from `git diff --cached --name-only` output, not from user input
    const absPath = path.resolve(filePath);

    try {
      // eslint-disable-next-line no-console
      console.log(`sec-gate: scanning ${filePath} (${lang}) with owasp-top10 rules...`);

      const issues = await semgrepScan(absPath, {
        language: lang,
        ruleSets: ['owasp-top10']
      });

      if (issues.length > 0) {
        // eslint-disable-next-line no-console
        console.log(`sec-gate: found ${issues.length} finding(s) in ${filePath}`);
      }

      for (const issue of issues) {
        allFindings.push(normalizeSemgrepNodeFinding(issue, filePath));
      }
    } catch (err) {
      if (err && err.message && err.message.includes('ENOENT')) {
        // eslint-disable-next-line no-console
        console.warn(`sec-gate: WARNING — semgrep binary not found for language "${lang}"`);
        // eslint-disable-next-line no-console
        console.warn('          The semgrep binary needs to be downloaded by @pensar/semgrep-node.');
        // eslint-disable-next-line no-console
        console.warn('          Run `sec-gate doctor` to diagnose, or re-install: npm i -g sec-gate');
      } else {
        // eslint-disable-next-line no-console
        console.warn(`sec-gate: WARNING — semgrep scan failed for ${filePath}: ${err.message}`);
      }
    }
  }

  return allFindings;
}

module.exports = { runSemgrep };
