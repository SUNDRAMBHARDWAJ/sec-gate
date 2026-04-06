#!/usr/bin/env node
// security-scan: disable rule-id: detect-non-literal-fs-filename reason: all paths derived from git rev-parse, never user input
// security-scan: disable rule-id: path-join-resolve-traversal reason: all paths derived from git rev-parse, never user input

/**
 * sec-gate preuninstall script
 *
 * Runs automatically when the developer executes:
 *   npm uninstall -g sec-gate
 *   pnpm remove -g sec-gate
 *   yarn global remove sec-gate
 *
 * WHAT IT DOES:
 *   - Finds the git repo the developer is currently inside (if any)
 *   - Locates the pre-commit hook file that sec-gate injected into
 *   - Removes ONLY the sec-gate block (between HOOK_MARKER and END_MARKER)
 *   - If the file becomes empty / only a shebang after removal, deletes it
 *   - Never touches anything outside the sec-gate markers
 */

const fs   = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const HOOK_MARKER = '# installed-by: sec-gate';
const END_MARKER  = '# end-sec-gate';

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

function getRepoRoot() {
  try {
    return execFileSync('git', ['rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Resolve the actual pre-commit hook path git would use,
 * identical logic to install.js so we always find the same file.
 */
function resolveHookPath(repoRoot) {
  let hooksDir;
  try {
    const configured = execFileSync(
      'git', ['config', '--local', 'core.hooksPath'],
      { encoding: 'utf8', cwd: repoRoot, stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    if (configured) {
      hooksDir = path.isAbsolute(configured)
        ? configured
        : path.join(repoRoot, configured);

      // Husky shim redirect (same as install.js)
      const huskyShimDir = path.join(repoRoot, '.husky', '_');
      if (hooksDir === huskyShimDir || hooksDir.startsWith(huskyShimDir + path.sep)) {
        hooksDir = path.join(repoRoot, '.husky');
      }
    }
  } catch { /* no custom hooksPath configured */ }

  if (!hooksDir) hooksDir = path.join(repoRoot, '.git', 'hooks');
  return path.join(hooksDir, 'pre-commit');
}

/**
 * Remove the sec-gate block from content string.
 * Handles two cases:
 *   1. Standalone hook  — entire file starts with HOOK_MARKER
 *   2. Injected block   — block is between HOOK_MARKER and END_MARKER
 */
function removeSecGateBlock(content) {
  const lines = content.split('\n');

  // Find marker boundaries
  let startIdx = -1;
  let endIdx   = -1;

  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === HOOK_MARKER && startIdx === -1) startIdx = i;
    if (lines[i].trim() === END_MARKER  && startIdx !== -1) { endIdx = i; break; }
  }

  // Case: standalone hook — HOOK_MARKER appears right after the shebang (line 0 or 1)
  // In this case the whole file is sec-gate's, so signal full removal
  if (startIdx !== -1 && startIdx <= 1 && endIdx === -1) {
    // No END_MARKER means the whole file is ours (standalone format)
    return null; // caller should delete the file
  }

  // Case: no markers found — nothing to remove
  if (startIdx === -1) return content;

  // Case: injected block — remove from startIdx to endIdx (inclusive)
  // Also eat the blank line immediately before the marker if present
  const removeFrom = (startIdx > 0 && lines[startIdx - 1].trim() === '') ? startIdx - 1 : startIdx;
  const removeTo   = endIdx !== -1 ? endIdx : lines.length - 1;

  lines.splice(removeFrom, removeTo - removeFrom + 1);
  return lines.join('\n');
}

/**
 * Returns true if the file content is effectively empty
 * (only shebang and/or blank lines remain).
 */
function isEffectivelyEmpty(content) {
  const meaningful = content.split('\n').filter(
    (l) => l.trim() !== '' && !l.trim().startsWith('#!')
  );
  return meaningful.length === 0;
}

// ─────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────

function main() {
  const repoRoot = getRepoRoot();
  if (!repoRoot) {
    console.log('sec-gate: not inside a git repo — nothing to clean up');
    return;
  }

  const hookPath = resolveHookPath(repoRoot);

  if (!fs.existsSync(hookPath)) {
    console.log('sec-gate: no pre-commit hook found — nothing to clean up');
    return;
  }

  const original = fs.readFileSync(hookPath, 'utf8');

  if (!original.includes(HOOK_MARKER)) {
    console.log('sec-gate: pre-commit hook was not installed by sec-gate — leaving it untouched');
    return;
  }

  const cleaned = removeSecGateBlock(original);

  if (cleaned === null || isEffectivelyEmpty(cleaned)) {
    // The whole file was sec-gate's — remove it entirely
    fs.unlinkSync(hookPath);
    console.log(`sec-gate: removed pre-commit hook from ${hookPath}`);
  } else {
    fs.writeFileSync(hookPath, cleaned, { encoding: 'utf8', mode: 0o755 });
    console.log(`sec-gate: removed sec-gate block from ${hookPath}`);
  }

  console.log('sec-gate: cleanup complete. Goodbye!');
}

try {
  main();
} catch (err) {
  // Never block the uninstall itself
  console.warn('sec-gate preuninstall warning:', err.message);
  process.exit(0);
}
