const { execSync } = require('child_process');

function listTrackedFiles() {
  const out = execSync('git ls-files', {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore']
  });

  return out
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

module.exports = { listTrackedFiles };
