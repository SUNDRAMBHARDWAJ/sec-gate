#!/usr/bin/env node

/**
 * Runs automatically after `npm install -g sec-gate`.
 * Does three things:
 *   1. Downloads osv-scanner binary for this platform
 *   2. Installs govulncheck via `go install` (if Go is available)
 *   3. Auto-installs the pre-commit hook in the current directory
 *      if it is a git repo — so developers never need to run `sec-gate install` manually
 */

const fs   = require('fs');
const path = require('path');
const https = require('https');
const { execSync, execFileSync } = require('child_process');

const BIN_DIR = path.join(__dirname, '..', 'vendor-bin');
fs.mkdirSync(BIN_DIR, { recursive: true });

const platform = process.platform; // darwin, linux, win32
const arch     = process.arch;     // x64, arm64

// ─────────────────────────────────────────────────────────
// 1. OSV-Scanner binary download
// ─────────────────────────────────────────────────────────
const OSV_VERSION = 'v2.3.5';

function osvDownloadUrl() {
  const os  = platform === 'darwin' ? 'darwin' : platform === 'win32' ? 'windows' : 'linux';
  const a   = arch === 'arm64' ? 'arm64' : 'amd64';
  const ext = platform === 'win32' ? '.exe' : '';
  return `https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_${os}_${a}${ext}`;
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);

    function get(u) {
      https.get(u, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          return get(res.headers.location);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode} for ${u}`));
        }
        res.pipe(file);
        file.on('finish', () => file.close(resolve));
        file.on('error', reject);
      }).on('error', reject);
    }

    get(url);
  });
}

async function installOsvScanner() {
  const ext  = platform === 'win32' ? '.exe' : '';
  const dest = path.join(BIN_DIR, `osv-scanner${ext}`);

  if (fs.existsSync(dest)) {
    console.log('sec-gate [1/3]: osv-scanner already present');
    return;
  }

  const url = osvDownloadUrl();
  console.log(`sec-gate [1/3]: downloading osv-scanner...`);

  try {
    await downloadFile(url, dest);
    fs.chmodSync(dest, 0o755);
    console.log('sec-gate [1/3]: osv-scanner ready');
  } catch (err) {
    console.warn(`sec-gate [1/3]: WARNING — osv-scanner download failed: ${err.message}`);
    console.warn('                Node/pnpm SCA will be skipped until this is resolved.');
  }
}

// ─────────────────────────────────────────────────────────
// 2. govulncheck via `go install`
// ─────────────────────────────────────────────────────────
function installGovulncheck() {
  const ext  = platform === 'win32' ? '.exe' : '';
  const dest = path.join(BIN_DIR, `govulncheck${ext}`);

  if (fs.existsSync(dest)) {
    console.log('sec-gate [2/3]: govulncheck already present');
    return;
  }

  try {
    execSync('go version', { stdio: 'ignore' });
  } catch {
    console.warn('sec-gate [2/3]: WARNING — Go not found. Go SCA will be skipped.');
    console.warn('                Install Go from https://go.dev/dl/ and re-run: npm i -g sec-gate');
    return;
  }

  try {
    console.log('sec-gate [2/3]: installing govulncheck...');
    const gopath = execSync('go env GOPATH', { encoding: 'utf8' }).trim();
    execSync('go install golang.org/x/vuln/cmd/govulncheck@latest', { stdio: 'inherit' });

    const goSrc = path.join(gopath, 'bin', `govulncheck${ext}`);
    if (fs.existsSync(goSrc)) {
      fs.copyFileSync(goSrc, dest);
      fs.chmodSync(dest, 0o755);
      console.log('sec-gate [2/3]: govulncheck ready');
    }
  } catch (err) {
    console.warn(`sec-gate [2/3]: WARNING — govulncheck install failed: ${err.message}`);
    console.warn('                Go SCA will be skipped.');
  }
}

// ─────────────────────────────────────────────────────────
// 3. Auto-install pre-commit hook in the current git repo
// ─────────────────────────────────────────────────────────
const HOOK_MARKER = '# installed-by: sec-gate';

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
    '  echo "sec-gate: not found in PATH. Run: npm install -g sec-gate"',
    '  exit 1',
    'fi',
    ''
  ].join('\n');
}

function autoInstallHook() {
  let repoRoot;

  try {
    repoRoot = execSync('git rev-parse --show-toplevel', {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    // Not inside a git repo — skip silently (e.g., CI machines, temp dirs)
    console.log('sec-gate [3/3]: not inside a git repo, skipping hook install');
    return;
  }

  const hookDir  = path.join(repoRoot, '.git', 'hooks');
  const hookPath = path.join(hookDir, 'pre-commit');

  fs.mkdirSync(hookDir, { recursive: true });

  // Already installed by us — nothing to do
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf8');
    if (existing.includes(HOOK_MARKER)) {
      console.log('sec-gate [3/3]: pre-commit hook already installed');
      return;
    }

    // Back up a hook that belongs to something else
    const backup = `${hookPath}.sec-gate.bak`;
    fs.copyFileSync(hookPath, backup);
    console.log(`sec-gate [3/3]: backed up existing hook → ${backup}`);
  }

  fs.writeFileSync(hookPath, buildHookScript(), { encoding: 'utf8', mode: 0o755 });
  console.log(`sec-gate [3/3]: pre-commit hook installed in ${repoRoot}`);
}

// ─────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────
async function main() {
  console.log('\nsec-gate: setting up...\n');
  await installOsvScanner();
  installGovulncheck();
  autoInstallHook();
  console.log('\nsec-gate: ready. Your commits are now security-checked.\n');
}

main().catch((err) => {
  // Never fail the install — degraded mode is always better than a blocked install.
  console.warn('sec-gate postinstall warning:', err.message);
  process.exit(0);
});
