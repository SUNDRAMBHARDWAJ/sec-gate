const fs = require('fs');
const path = require('path');
const { getRepoRoot } = require('../git/repo');

const HOOK_MARKER = '# installed-by: sec-gate';

function getHookPath(repoRoot) {
  return path.join(repoRoot, '.git', 'hooks', 'pre-commit');
}

function buildHookScript() {
  return [
    '#!/usr/bin/env sh',
    HOOK_MARKER,
    '',
    '# Set SEC_GATE_SKIP=1 to bypass (emergency only)',
    'if [ "$SEC_GATE_SKIP" = "1" ]; then',
    '  echo "sec-gate: skipped (SEC_GATE_SKIP=1)"',
    '  exit 0',
    'fi',
    '',
    'ROOT_DIR=$(git rev-parse --show-toplevel) || exit 1',
    'cd "$ROOT_DIR" || exit 1',
    '',
    'if command -v sec-gate >/dev/null 2>&1; then',
    '  sec-gate scan --staged',
    '  exit $?',
    'else',
    '  echo "sec-gate: not found in PATH. Install it: npm install -g sec-gate"',
    '  exit 1',
    'fi',
    ''
  ].join('\n');
}

function isAlreadyInstalled(hookPath) {
  if (!fs.existsSync(hookPath)) return false;
  const content = fs.readFileSync(hookPath, 'utf8');
  return content.includes(HOOK_MARKER);
}

function suggestPrepareScript(repoRoot) {
  const pkgPath = path.join(repoRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return;

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch {
    return;
  }

  const hasPrepare = pkg.scripts && pkg.scripts.prepare && pkg.scripts.prepare.includes('sec-gate install');

  if (!hasPrepare) {
    console.log('');
    console.log('  TIP: To auto-install this hook for every developer on your team,');
    console.log('  add this to your repo\'s package.json "scripts":');
    console.log('');
    console.log('    "prepare": "sec-gate install"');
    console.log('');
    console.log('  Then any developer who runs `npm install` in this repo');
    console.log('  gets the pre-commit hook automatically — no manual step needed.');
    console.log('');
  }
}

async function installHook() {
  const repoRoot = getRepoRoot();
  const hookPath = getHookPath(repoRoot);

  if (!fs.existsSync(path.join(repoRoot, '.git'))) {
    throw new Error('sec-gate install: .git directory not found. Run this inside a git repository.');
  }

  fs.mkdirSync(path.dirname(hookPath), { recursive: true });

  if (isAlreadyInstalled(hookPath)) {
    console.log('sec-gate: pre-commit hook is already installed.');
    suggestPrepareScript(repoRoot);
    return;
  }

  // Backup any existing hook that wasn't installed by us
  if (fs.existsSync(hookPath)) {
    const backupPath = `${hookPath}.sec-gate.bak`;
    fs.copyFileSync(hookPath, backupPath);
    console.log(`sec-gate: backed up existing hook to ${backupPath}`);
  }

  fs.writeFileSync(hookPath, buildHookScript(), { encoding: 'utf8', mode: 0o755 });
  console.log(`sec-gate: pre-commit hook installed at ${hookPath}`);

  suggestPrepareScript(repoRoot);
}

module.exports = { installHook };
