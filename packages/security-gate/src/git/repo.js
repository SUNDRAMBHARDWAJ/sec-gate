const { execSync } = require('child_process');

function getRepoRoot() {
  try {
    return execSync('git rev-parse --show-toplevel', { encoding: 'utf8' }).trim();
  } catch {
    throw new Error('sec-gate: run this command inside a git repository');
  }
}

module.exports = { getRepoRoot };
