'use strict';

// security-scan: disable rule-id: path-join-resolve-traversal reason: all paths in this file are derived from `git rev-parse --show-toplevel` or hardcoded constants, never from user input
// security-scan: disable rule-id: detect-non-literal-fs-filename reason: all paths in this file are derived from `git rev-parse --show-toplevel` or hardcoded constants, never from user input

/**
 * sec-gate install — Generic pre-commit hook injector
 *
 * STRATEGY (tool-agnostic):
 * ─────────────────────────
 * Every git hook manager (husky, lefthook, simple-git-hooks, pre-commit,
 * custom hooksPath, etc.) ultimately tells git WHERE to look for hooks.
 * Git has one source of truth for this: `git config core.hooksPath`.
 * If that is not set, git falls back to `.git/hooks/`.
 *
 * So instead of enumerating every possible tool by name, we:
 *   1. Ask git itself: "where will you look for the pre-commit hook?"
 *   2. Resolve that path to an absolute location on disk.
 *   3. If a pre-commit file already exists there → inject sec-gate as
 *      the first real command (after any shebang/bootstrap lines).
 *   4. If no file exists yet → create a minimal shell hook.
 *
 * Special cases handled on top of the generic base:
 *   • Husky v4  — stores hooks in package.json, not in a shell file.
 *   • simple-git-hooks — same: package.json config, not a shell file.
 *   • lefthook  — YAML config, not a shell file.
 *   • pre-commit (Python) — YAML config.
 *   These are detected BEFORE the generic path logic and handled
 *   by patching their config files. After patching we still also
 *   write to whatever path git resolves, as a safety net.
 *
 * Result: works for any tool — known or unknown — as long as it
 * honours git's core.hooksPath or places hooks in .git/hooks/.
 */

const fs               = require('fs');
const path             = require('path');
const { execFileSync } = require('child_process');
const { getRepoRoot }  = require('../git/repo');

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
const HOOK_MARKER = '# installed-by: sec-gate';
const END_MARKER  = '# end-sec-gate';

// ─────────────────────────────────────────────────────────────────────────────
// Shell snippets
// ─────────────────────────────────────────────────────────────────────────────

/** Block injected into ANY existing shell hook file */
function secGateShellBlock() {
  return [
    '',
    HOOK_MARKER,
    'if [ "$SEC_GATE_SKIP" != "1" ]; then',
    '  if command -v sec-gate >/dev/null 2>&1; then',
    '    sec-gate scan --staged',
    '    _SG_EXIT=$?',
    '    if [ $_SG_EXIT -ne 0 ]; then exit $_SG_EXIT; fi',
    '  else',
    '    echo "sec-gate: WARNING — sec-gate not found in PATH, security scan skipped."',
    '    echo "sec-gate: To re-enable scanning run: npm install -g sec-gate"',
    '  fi',
    'fi',
    END_MARKER,
    ''
  ].join('\n');
}

/** Full standalone hook — used when no file exists yet */
function standaloneHook() {
  return [
    '#!/usr/bin/env sh',
    HOOK_MARKER,
    '',
    '# Bypass: SEC_GATE_SKIP=1 git commit -m "..."',
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
    '  echo "sec-gate: WARNING — sec-gate not found in PATH, security scan skipped."',
    '  echo "sec-gate: To re-enable scanning run: npm install -g sec-gate"',
    '  exit 0',
    'fi',
    ''
  ].join('\n');
}

// ─────────────────────────────────────────────────────────────────────────────
// Core: ask git where it will look for hooks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the absolute path to the pre-commit hook file that git WILL execute.
 * This is the single source of truth — works regardless of which hook manager
 * set core.hooksPath.
 *
 * Special cases handled:
 *  - .husky/_  → husky's internal bootstrap shim dir, read-only, never write here.
 *                Fall back to .husky/pre-commit (the real hook file).
 *  - .husky    → husky v6+ standard hooks dir, use .husky/pre-commit directly.
 */
function resolveGitHookPath(repoRoot) {
  let hooksDir;

  try {
    // git config core.hooksPath — set by husky v6, lefthook, custom configs, etc.
    const configured = execFileSync(
      'git', ['config', '--local', 'core.hooksPath'],
      { encoding: 'utf8', cwd: repoRoot, stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();

    if (configured) {
      // Resolve relative paths (e.g. ".husky", ".githooks") against repo root
      hooksDir = path.isAbsolute(configured)
        ? configured
        : path.join(repoRoot, configured);

      // .husky/_ is husky's internal bootstrap shim directory — it is read-only
      // and should never be written to. The actual user-editable hooks live in
      // .husky/ (one level up). Redirect there.
      const huskyShimDir = path.join(repoRoot, '.husky', '_');
      if (hooksDir === huskyShimDir || hooksDir.startsWith(huskyShimDir + path.sep)) {
        console.log('sec-gate: core.hooksPath points to .husky/_ (husky bootstrap shim) — redirecting to .husky/');
        hooksDir = path.join(repoRoot, '.husky');
      }
    }
  } catch {
    // core.hooksPath not set — use default
  }

  if (!hooksDir) {
    hooksDir = path.join(repoRoot, '.git', 'hooks');
  }

  return path.join(hooksDir, 'pre-commit');
}

// ─────────────────────────────────────────────────────────────────────────────
// Core: inject into a shell hook file (generic, works for any manager)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Injects the sec-gate shell block into hookPath.
 *
 * Insertion strategy (makes sec-gate run FIRST):
 *   - Skip shebang line (#!/...)
 *   - Skip any "bootstrap" lines (source/., export PATH, nvm/asdf/volta inits,
 *     husky.sh, lefthook bootstrap, etc.)
 *   - Insert sec-gate block after all those lines, before real commands
 *
 * This means sec-gate always runs before lint-staged, eslint, prettier,
 * or whatever else the hook manager added.
 */
function injectIntoShellHook(hookPath) {
  if (alreadyInstalled(hookPath)) {
    console.log(`sec-gate: already installed in ${hookPath}`);
    return;
  }

  let lines;
  if (fs.existsSync(hookPath)) {
    lines = fs.readFileSync(hookPath, 'utf8').split('\n');
  } else {
    // File does not exist — create it from scratch
    fs.mkdirSync(path.dirname(hookPath), { recursive: true });
    fs.writeFileSync(hookPath, standaloneHook(), { encoding: 'utf8', mode: 0o755 });
    console.log(`sec-gate: created pre-commit hook at ${hookPath}`);
    return;
  }

  // Find insertion point: after shebang + bootstrap/sourcing lines
  // Bootstrap patterns — lines that set up the environment, not real commands
  const BOOTSTRAP_PATTERNS = [
    /^#/,                        // comments (including shebang)
    /^\s*$/,                     // blank lines
    /\.\s+"[^"]*"/,              // . "path/to/something.sh"  (posix source)
    /\.\s+\S+/,                  // . /path/to/script
    /source\s+/i,                // source /path/to/script
    /export\s+/,                 // export PATH=...
    /^eval\s+/,                  // eval "$(nvm/asdf/volta)"
    /nvm|asdf|volta|rbenv|pyenv/ // version manager inits
  ];

  let insertAt = 0;
  for (let i = 0; i < lines.length; i++) {
    const isBootstrap = BOOTSTRAP_PATTERNS.some((re) => re.test(lines[i]));
    if (isBootstrap) {
      insertAt = i + 1; // keep moving insertion point past bootstrap lines
    } else {
      break; // first non-bootstrap line — stop here
    }
  }

  lines.splice(insertAt, 0, ...secGateShellBlock().split('\n'));
  fs.writeFileSync(hookPath, lines.join('\n'), { encoding: 'utf8', mode: 0o755 });
  console.log(`sec-gate: injected into ${hookPath}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function alreadyInstalled(filePath) {
  if (!fs.existsSync(filePath)) return false;
  return fs.readFileSync(filePath, 'utf8').includes(HOOK_MARKER);
}

function readPkg(repoRoot) {
  const p = path.join(repoRoot, 'package.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

function writePkg(repoRoot, pkg) {
  fs.writeFileSync(
    path.join(repoRoot, 'package.json'),
    JSON.stringify(pkg, null, 2) + '\n',
    'utf8'
  );
}

function hasDep(pkg, name) {
  if (!pkg) return false;
  return !!(
    (pkg.dependencies     && pkg.dependencies[name]) ||
    (pkg.devDependencies  && pkg.devDependencies[name]) ||
    (pkg.peerDependencies && pkg.peerDependencies[name])
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Config-file-based hook managers
// These store their hook commands in YAML/JSON config, not shell files.
// We patch those config files AND then also inject into the resolved shell
// hook path as a safety net.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Husky v4 — hooks live in package.json under "husky.hooks"
 */
function patchHuskyV4(repoRoot, pkg) {
  if (!pkg || !pkg.husky || !pkg.husky.hooks) return false;

  const existing = (pkg.husky.hooks['pre-commit'] || '').trim();
  if (existing.includes('sec-gate')) return false; // already there

  pkg.husky.hooks['pre-commit'] = existing
    ? `sec-gate scan --staged && ${existing}`
    : 'sec-gate scan --staged';

  writePkg(repoRoot, pkg);
  console.log('sec-gate: patched husky v4 hooks in package.json');
  return true;
}

/**
 * simple-git-hooks — hooks live in package.json under "simple-git-hooks"
 */
function patchSimpleGitHooks(repoRoot, pkg) {
  if (!pkg) return false;
  const sgh = pkg['simple-git-hooks'];
  if (!sgh && !hasDep(pkg, 'simple-git-hooks')) return false;

  const existing = ((sgh && sgh['pre-commit']) || '').trim();
  if (existing.includes('sec-gate')) return false;

  if (!pkg['simple-git-hooks']) pkg['simple-git-hooks'] = {};
  pkg['simple-git-hooks']['pre-commit'] = existing
    ? `sec-gate scan --staged && ${existing}`
    : 'sec-gate scan --staged';

  writePkg(repoRoot, pkg);
  console.log('sec-gate: patched simple-git-hooks in package.json');
  console.log('          run `npx simple-git-hooks` to apply.');
  return true;
}

/**
 * lefthook — hooks live in lefthook.yml / lefthook.json
 */
function patchLefthook(repoRoot) {
  const candidates = [
    'lefthook.yml', '.lefthook.yml',
    'lefthook.yaml', '.lefthook.yaml',
    'lefthook.json', '.lefthook.json'
  ].map((f) => path.join(repoRoot, f));

  const ymlPath = candidates.find(fs.existsSync);
  if (!ymlPath) return false;

  const content = fs.readFileSync(ymlPath, 'utf8');
  if (content.includes('sec-gate')) return false;

  // Inject a pre-commit command with priority 1 (runs first)
  const injection = [
    '',
    '# installed-by: sec-gate',
    'pre-commit:',
    '  commands:',
    '    sec-gate:',
    '      priority: 1',
    '      run: sec-gate scan --staged',
    ''
  ].join('\n');

  fs.writeFileSync(ymlPath, content + injection, 'utf8');
  console.log(`sec-gate: patched ${path.basename(ymlPath)}`);
  console.log('          run `lefthook install` to apply.');
  return true;
}

/**
 * pre-commit (Python tool) — .pre-commit-config.yaml
 */
function patchPreCommitPy(repoRoot) {
  const configPath = path.join(repoRoot, '.pre-commit-config.yaml');
  if (!fs.existsSync(configPath)) return false;

  const content = fs.readFileSync(configPath, 'utf8');
  if (content.includes('sec-gate')) return false;

  const localHook = [
    '',
    '# installed-by: sec-gate',
    '- repo: local',
    '  hooks:',
    '  - id: sec-gate',
    '    name: sec-gate OWASP security scan',
    '    language: system',
    '    entry: sec-gate scan --staged',
    '    pass_filenames: false',
    '    stages: [commit]',
    ''
  ].join('\n');

  fs.writeFileSync(configPath, content + localHook, 'utf8');
  console.log('sec-gate: patched .pre-commit-config.yaml');
  console.log('          run `pre-commit install` to apply.');
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Suggest prepare script tip
// ─────────────────────────────────────────────────────────────────────────────
function suggestPrepareScript(pkg) {
  if (!pkg) return;
  const hasPrepare = pkg.scripts && pkg.scripts.prepare &&
    pkg.scripts.prepare.includes('sec-gate install');
  if (!hasPrepare) {
    console.log('');
    console.log('  TIP: Add to package.json so teammates get the hook automatically:');
    console.log('    "scripts": { "prepare": "sec-gate install" }');
    console.log('  Then npm/pnpm/yarn install auto-runs sec-gate install for everyone.');
    console.log('');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
async function installHook() {
  const repoRoot = getRepoRoot();

  if (!fs.existsSync(path.join(repoRoot, '.git'))) {
    throw new Error('sec-gate install: .git not found. Run inside a git repository.');
  }

  const pkg = readPkg(repoRoot);

  // ── Step 1: patch any config-file-based hook managers ─────────────────────
  // These tools store hooks in YAML/JSON, not shell files.
  // We patch their config so their runner also executes sec-gate.
  patchHuskyV4(repoRoot, pkg);
  patchSimpleGitHooks(repoRoot, pkg);
  patchLefthook(repoRoot);
  patchPreCommitPy(repoRoot);

  // ── Step 2: resolve where git ACTUALLY runs the pre-commit hook ───────────
  // This works for ANY tool — husky v6, lefthook, custom hooksPath, or bare.
  // We just ask git itself where it will look, then inject there.
  const resolvedHookPath = resolveGitHookPath(repoRoot);
  console.log(`sec-gate: git will execute pre-commit hook from: ${resolvedHookPath}`);
  injectIntoShellHook(resolvedHookPath);

  // ── Step 3: suggest prepare script for team auto-setup ────────────────────
  suggestPrepareScript(pkg);
}

module.exports = { installHook };
