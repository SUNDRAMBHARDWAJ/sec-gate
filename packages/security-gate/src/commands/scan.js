// security-scan: disable rule-id: detect-non-literal-fs-filename reason: lockfile paths come from a hardcoded allowlist of known filenames, never user input
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

const LOCKFILES = new Set([
  'pnpm-lock.yaml',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'go.mod',
  'go.sum'
]);

function isSemgrepTargetPath(p) {
  if (!p) return false;

  const base = require('path').basename(p);
  if (LOCKFILES.has(base)) return false;

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

    // Detect which Node lockfile exists — support npm, pnpm and yarn
    const nodeLockfiles = [
      'pnpm-lock.yaml',      // pnpm
      'package-lock.json',   // npm
      'npm-shrinkwrap.json', // npm (legacy)
      'yarn.lock'            // yarn
    ];
    const foundLockfile = nodeLockfiles.find((lf) => fs.existsSync(lf));

    if (foundLockfile) {
      // eslint-disable-next-line no-console
      console.log(`sec-gate: running OSV-Scanner on ${foundLockfile}`);
      const scaOsv = await runOsvScanner({ lockfile: foundLockfile });
      allFindings.push(...scaOsv);
    } else {
      // eslint-disable-next-line no-console
      console.log('sec-gate: no Node lockfile found (pnpm-lock.yaml / package-lock.json / yarn.lock); skipping OSV-Scanner');
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

  // ── Success summary ────────────────────────────────────────────────────────
  const checks = [];
  if (semgrepTargets.length > 0) {
    checks.push(`SAST (${semgrepTargets.length} file${semgrepTargets.length > 1 ? 's' : ''})`);
  }
  if (depChanged || !staged) {
    const fs = require('fs');
    const nodeLockfilesCheck = ['pnpm-lock.yaml', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock'];
    const foundLock = nodeLockfilesCheck.find((lf) => fs.existsSync(lf));
    if (foundLock) checks.push(`SCA-node (${foundLock})`);
    if (fs.existsSync('go.mod')) checks.push('SCA-go (go.mod)');
  }

  const checksRan = checks.length > 0 ? checks.join(', ') : 'no checks applicable';
  // eslint-disable-next-line no-console
  console.log(`sec-gate: all checks passed — no vulnerabilities found by sec-gate`);
  // eslint-disable-next-line no-console
  console.log(`sec-gate: checks ran: ${checksRan}`);
}

module.exports = { scan };
