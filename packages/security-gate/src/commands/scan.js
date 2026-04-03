const { getStagedFiles, hasStagedDependencyFiles } = require('../git/stagedFiles');
const { listTrackedFiles } = require('../git/trackedFiles');
const { runSemgrep } = require('../scanners/semgrep');
const { runOsvScanner } = require('../scanners/osv');
const { runGovulncheck } = require('../scanners/govulncheck');
const { applyInlineSuppressions } = require('../suppressions/inlineTag');
const { scanFileWithCustomRules } = require('../../rules/custom-security');

function formatFinding(f) {
  const loc = f.line ? `${f.path}:${f.line}` : f.path;
  const owasp = f.owasp ? ` (${f.owasp})` : '';
  return `- ${loc} [${f.checkId}]${owasp}\n  ${f.message}`;
}

function isSemgrepTargetPath(p) {
  if (!p) return false;
  if (p.endsWith('pnpm-lock.yaml')) return false;
  if (p === 'go.mod' || p === 'go.sum') return false;

  return (
    p.endsWith('.js') ||
    p.endsWith('.jsx') ||
    p.endsWith('.mjs') ||
    p.endsWith('.cjs') ||
    p.endsWith('.ts') ||
    p.endsWith('.tsx') ||
    p.endsWith('.go')
  );
}

async function scan({ staged }) {
  const files = staged ? getStagedFiles() : listTrackedFiles();
  const depChanged = staged ? hasStagedDependencyFiles(files) : true;

  // eslint-disable-next-line no-console
  console.log(`sec-gate: scan started (${staged ? 'staged files' : 'tracked files'})`);

  const allFindings = [];
  const semgrepTargets = (files || []).filter(isSemgrepTargetPath);

  if (semgrepTargets.length > 0) {
    // SAST — owasp-top10 via @pensar/semgrep-node
    const sast = await runSemgrep({ files: semgrepTargets });
    allFindings.push(...sast);

    // Custom rules — patterns not covered by owasp-top10 ruleset
    for (const filePath of semgrepTargets) {
      const custom = scanFileWithCustomRules(filePath);
      allFindings.push(...custom);
    }
  } else {
    // eslint-disable-next-line no-console
    console.log('sec-gate: no relevant staged/tracked source files; skipping SAST');
  }

  // SCA (only when dependency lockfiles or go module files are staged)
  if (staged && !depChanged) {
    // eslint-disable-next-line no-console
    console.log('sec-gate: dependency files not staged; skipping SCA');
  } else {
    const fs = require('fs');

    if (fs.existsSync('pnpm-lock.yaml')) {
      const scaOsv = await runOsvScanner({ lockfile: 'pnpm-lock.yaml' });
      allFindings.push(...scaOsv);
    } else {
      // eslint-disable-next-line no-console
      console.log('sec-gate: pnpm-lock.yaml not found; skipping OSV-Scanner');
    }

    if (fs.existsSync('go.mod')) {
      const scaGo = await runGovulncheck({ pattern: './...' });
      allFindings.push(...scaGo);
    } else {
      // eslint-disable-next-line no-console
      console.log('sec-gate: go.mod not found; skipping govulncheck');
    }
  }

  const filtered = applyInlineSuppressions({ findings: allFindings });

  if (filtered.length > 0) {
    // eslint-disable-next-line no-console
    console.log('\nsec-gate: SECURITY FINDINGS (commit blocked):');
    for (const f of filtered) console.log(formatFinding(f));
    process.exit(1);
  }

  // eslint-disable-next-line no-console
  console.log('sec-gate: no findings after inline suppression');
}

module.exports = { scan };
