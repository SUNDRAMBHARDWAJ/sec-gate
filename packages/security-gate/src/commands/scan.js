// security-scan: disable rule-id: detect-non-literal-fs-filename reason: lockfile paths come from a hardcoded allowlist of known filenames, never user input
const { getStagedFiles, hasStagedDependencyFiles } = require('../git/stagedFiles');
const { listTrackedFiles } = require('../git/trackedFiles');
const { runSemgrep } = require('../scanners/semgrep');
const { runOsvScanner } = require('../scanners/osv');
const { runGovulncheck } = require('../scanners/govulncheck');
const { applyInlineSuppressions } = require('../suppressions/inlineTag');
const { scanFileWithCustomRules } = require('../../rules/custom-security');
const { loadConfig, meetsThreshold, isExcludedPath } = require('../config/loader');
const { getRepoRoot } = require('../git/repo');

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function formatFinding(f) {
  const loc  = f.line ? `${f.path}:${f.line}` : f.path;
  const owasp = f.owasp ? ` (${f.owasp})` : '';
  const sev  = f.severity ? ` [${f.severity.toUpperCase()}]` : '';
  return `- ${loc}${sev} [${f.checkId}]${owasp}\n  ${f.message}`;
}

const LOCKFILES = new Set([
  'pnpm-lock.yaml',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'go.mod',
  'go.sum'
]);

function isSemgrepTargetPath(p, config) {
  if (!p) return false;

  const base = require('path').basename(p);
  if (LOCKFILES.has(base)) return false;

  // Skip paths excluded in config
  if (isExcludedPath(p, config.exclude_paths)) return false;

  return (
    p.endsWith('.js')  ||
    p.endsWith('.jsx') ||
    p.endsWith('.mjs') ||
    p.endsWith('.cjs') ||
    p.endsWith('.ts')  ||
    p.endsWith('.tsx') ||
    p.endsWith('.go')
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply config filters to findings list
// ─────────────────────────────────────────────────────────────────────────────
function applyConfigFilters(findings, config) {
  const excludedRules  = new Set(config.exclude_rules || []);
  const threshold      = config.severity_threshold || 'all';

  const excluded  = [];
  const belowThreshold = [];
  const remaining = [];

  for (const f of findings) {
    // 1. Exclude by rule ID
    if (excludedRules.has(f.checkId)) {
      excluded.push(f);
      continue;
    }

    // 2. Exclude by path
    if (isExcludedPath(f.path || '', config.exclude_paths)) {
      excluded.push(f);
      continue;
    }

    // 3. Filter by severity threshold
    if (!meetsThreshold(f.severity, threshold)) {
      belowThreshold.push(f);
      continue;
    }

    remaining.push(f);
  }

  return { remaining, excluded, belowThreshold };
}

// ─────────────────────────────────────────────────────────────────────────────
// Main scan
// ─────────────────────────────────────────────────────────────────────────────
async function scan({ staged }) {
  // Load per-repo config (.sec-gate.yml)
  let repoRoot;
  try { repoRoot = getRepoRoot(); } catch { repoRoot = process.cwd(); }
  const config = loadConfig(repoRoot);

  const files      = staged ? getStagedFiles() : listTrackedFiles();
  const depChanged = staged ? hasStagedDependencyFiles(files) : true;

  // eslint-disable-next-line no-console
  console.log(`sec-gate: scan started (${staged ? 'staged files' : 'tracked files'})`);

  // Print active config summary
  if (config.severity_threshold !== 'all') {
    // eslint-disable-next-line no-console
    console.log(`sec-gate: severity threshold: ${config.severity_threshold} and above`);
  }
  if (config.exclude_rules.length > 0) {
    // eslint-disable-next-line no-console
    console.log(`sec-gate: excluding ${config.exclude_rules.length} high-noise rule(s)`);
  }

  const allFindings    = [];
  const semgrepTargets = (files || []).filter((f) => isSemgrepTargetPath(f, config));

  // ── SAST ──────────────────────────────────────────────────────────────────
  if (semgrepTargets.length > 0) {
    const sast = await runSemgrep({ files: semgrepTargets });
    allFindings.push(...sast);

    if (config.custom_rules !== false) {
      for (const filePath of semgrepTargets) {
        const custom = scanFileWithCustomRules(filePath);
        allFindings.push(...custom);
      }
    }
  } else {
    // eslint-disable-next-line no-console
    console.log('sec-gate: no relevant staged/tracked source files; skipping SAST');
  }

  // ── SCA ───────────────────────────────────────────────────────────────────
  if (config.sca === false) {
    // eslint-disable-next-line no-console
    console.log('sec-gate: SCA disabled in config; skipping');
  } else if (staged && !depChanged) {
    // eslint-disable-next-line no-console
    console.log('sec-gate: dependency files not staged; skipping SCA');
  } else {
    const fs = require('fs');

    const nodeLockfiles = [
      'pnpm-lock.yaml',
      'package-lock.json',
      'npm-shrinkwrap.json',
      'yarn.lock'
    ];
    const foundLockfile = nodeLockfiles.find((lf) => fs.existsSync(lf));

    if (foundLockfile) {
      // eslint-disable-next-line no-console
      console.log(`sec-gate: running OSV-Scanner on ${foundLockfile}`);
      const scaOsv = await runOsvScanner({ lockfile: foundLockfile });
      allFindings.push(...scaOsv);
    } else {
      // eslint-disable-next-line no-console
      console.log('sec-gate: no Node lockfile found; skipping OSV-Scanner');
    }

    if (fs.existsSync('go.mod')) {
      const scaGo = await runGovulncheck({ pattern: './...' });
      allFindings.push(...scaGo);
    } else {
      // eslint-disable-next-line no-console
      console.log('sec-gate: go.mod not found; skipping govulncheck');
    }
  }

  // ── Apply inline suppressions ─────────────────────────────────────────────
  const afterSuppressions = applyInlineSuppressions({ findings: allFindings });

  // ── Apply config filters (excluded rules, paths, severity threshold) ──────
  const { remaining, excluded, belowThreshold } = applyConfigFilters(afterSuppressions, config);

  // Report what was filtered (only in verbose — summarised in one line)
  if (excluded.length > 0) {
    // eslint-disable-next-line no-console
    console.log(`sec-gate: filtered ${excluded.length} finding(s) by excluded rules/paths`);
  }
  if (belowThreshold.length > 0) {
    // eslint-disable-next-line no-console
    console.log(`sec-gate: filtered ${belowThreshold.length} finding(s) below severity threshold (${config.severity_threshold})`);
  }

  // ── Block or pass ─────────────────────────────────────────────────────────
  if (remaining.length > 0) {
    // eslint-disable-next-line no-console
    console.log('\nsec-gate: SECURITY FINDINGS (commit blocked):');
    for (const f of remaining) console.log(formatFinding(f));

    // Show hint about severity threshold if there are lower-severity findings
    if (belowThreshold.length > 0 && config.severity_threshold === 'all') {
      // eslint-disable-next-line no-console
      console.log('\n  TIP: Set severity_threshold in .sec-gate.yml to only block on high/critical.');
    }

    process.exit(1);
  }

  // ── Success summary ───────────────────────────────────────────────────────
  const checks = [];
  if (semgrepTargets.length > 0) {
    checks.push(`SAST (${semgrepTargets.length} file${semgrepTargets.length > 1 ? 's' : ''})`);
  }
  if (config.sca !== false && (depChanged || !staged)) {
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
