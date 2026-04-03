const { execSync } = require('child_process');

function getStagedFiles() {
  // Includes added/copied/modified/renamed/typed.
  const out = execSync('git diff --cached --name-only --diff-filter=ACMRTUXB', {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore']
  });

  const files = out
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);

  return files;
}

function hasStagedDependencyFiles(files) {
  if (!files || files.length === 0) return false;
  const depNames = new Set(['pnpm-lock.yaml', 'go.mod', 'go.sum']);
  return files.some((f) => depNames.has(f));
}

module.exports = { getStagedFiles, hasStagedDependencyFiles };
