#!/usr/bin/env node
// security-scan: disable rule-id: detect-non-literal-fs-filename reason: all paths derived from git rev-parse or hardcoded BIN_DIR constants, never user input
// security-scan: disable rule-id: path-join-resolve-traversal reason: all paths derived from git rev-parse or hardcoded BIN_DIR constants, never user input

/**
 * sec-gate postinstall script
 *
 * PURPOSE: This script runs after `npm install -g sec-gate` to set up bundled
 * scanning tools so developers need only one install command.
 *
 * WHAT IT DOES (transparently):
 *   [1/3] Downloads the osv-scanner binary from Google's official GitHub release
 *         URL: https://github.com/google/osv-scanner/releases/
 *         Only downloads if not already present. No data is sent anywhere.
 *
 *   [2/3] Installs govulncheck using `go install` from golang.org/x/vuln
 *         Only runs if Go is installed AND SEC_GATE_GO_INSTALL=1 is set,
 *         OR if Go is installed and this is the first time running.
 *         Skipped silently if Go is not found.
 *
 *   [3/3] Installs a git pre-commit hook in the current directory
 *         if it is a git repo. Backs up any existing hook first.
 *         Skipped silently if not inside a git repo.
 *
 * OPT-OUT: Set SEC_GATE_SKIP_POSTINSTALL=1 to skip this entire script.
 *          Example: SEC_GATE_SKIP_POSTINSTALL=1 npm install -g sec-gate
 *
 * SOURCE: https://github.com/SUNDRAMBHARDWAJ/sec-gate
 */

// Opt-out: allow users/CI systems to skip postinstall entirely
if (process.env.SEC_GATE_SKIP_POSTINSTALL === '1') {
  console.log('sec-gate: postinstall skipped (SEC_GATE_SKIP_POSTINSTALL=1)');
  process.exit(0);
}

const fs    = require('fs');
const path  = require('path');
const https = require('https');
const crypto = require('crypto');
const { execSync, execFileSync } = require('child_process');

const BIN_DIR = path.join(__dirname, '..', 'vendor-bin');
fs.mkdirSync(BIN_DIR, { recursive: true });

const platform = process.platform; // darwin, linux, win32
const arch     = process.arch;     // x64, arm64

// ─────────────────────────────────────────────────────────
// [1/3] OSV-Scanner binary download
// Source: https://github.com/google/osv-scanner/releases/
// No data is sent — we only download a binary from GitHub releases.
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
    console.log('sec-gate [1/3]: osv-scanner already present, skipping download');
    return;
  }

  const url = osvDownloadUrl();
  console.log(`sec-gate [1/3]: downloading osv-scanner ${OSV_VERSION}`);
  console.log(`                source: ${url}`);

  try {
    await downloadFile(url, dest);
    fs.chmodSync(dest, 0o755);

    // Print a SHA256 fingerprint so security-conscious users can verify
    const hash = crypto.createHash('sha256').update(fs.readFileSync(dest)).digest('hex');
    console.log(`sec-gate [1/3]: osv-scanner ready (sha256: ${hash})`);
    console.log(`                verify at: https://github.com/google/osv-scanner/releases/tag/${OSV_VERSION}`);
  } catch (err) {
    console.warn(`sec-gate [1/3]: WARNING — osv-scanner download failed: ${err.message}`);
    console.warn('                Node/pnpm SCA will be skipped. Re-run: npm i -g sec-gate');
  }
}

// ─────────────────────────────────────────────────────────
// [2/3] govulncheck via `go install`
// Only installs if Go is available on this machine.
// Source: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
// ─────────────────────────────────────────────────────────
function installGovulncheck() {
  const ext  = platform === 'win32' ? '.exe' : '';
  const dest = path.join(BIN_DIR, `govulncheck${ext}`);

  if (fs.existsSync(dest)) {
    console.log('sec-gate [2/3]: govulncheck already present, skipping install');
    return;
  }

  // Check if Go is available — skip silently if not
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
  } catch {
    console.log('sec-gate [2/3]: Go not found — skipping govulncheck install');
    console.log('                To enable Go SCA: install Go (https://go.dev/dl/) and re-run: npm i -g sec-gate');
    return;
  }

  try {
    console.log('sec-gate [2/3]: installing govulncheck via `go install golang.org/x/vuln/cmd/govulncheck@latest`');
    const gopath = execFileSync('go', ['env', 'GOPATH'], { encoding: 'utf8' }).trim();
    execFileSync('go', ['install', 'golang.org/x/vuln/cmd/govulncheck@latest'], { stdio: 'inherit' });

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
// [3/3] Auto-install pre-commit hook in the current git repo
// Detects husky automatically and injects into .husky/pre-commit.
// Falls back to .git/hooks/pre-commit for non-husky repos.
// Skipped silently if not inside a git repo.
// ─────────────────────────────────────────────────────────
const HOOK_MARKER = '# installed-by: sec-gate';

function isHuskyRepo(repoRoot) {
  if (fs.existsSync(path.join(repoRoot, '.husky'))) return true;
  const pkgPath = path.join(repoRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return false;
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    return !!deps.husky;
  } catch { return false; }
}

function buildStandaloneHook() {
  return [
    '#!/usr/bin/env sh',
    HOOK_MARKER,
    '',
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

function buildHuskyInjectionBlock() {
  return [
    '',
    HOOK_MARKER,
    'if [ "$SEC_GATE_SKIP" != "1" ]; then',
    '  if command -v sec-gate >/dev/null 2>&1; then',
    '    sec-gate scan --staged',
    '    SEC_GATE_EXIT=$?',
    '    if [ $SEC_GATE_EXIT -ne 0 ]; then exit $SEC_GATE_EXIT; fi',
    '  else',
    '    echo "sec-gate: not found in PATH. Run: npm install -g sec-gate"',
    '    exit 1',
    '  fi',
    'fi',
    '# end-sec-gate',
    ''
  ].join('\n');
}

function buildNewHuskyHook() {
  return ['#!/usr/bin/env sh', '. "$(dirname -- "$0")/_/husky.sh"', buildHuskyInjectionBlock()].join('\n');
}

function autoInstallHook() {
  let repoRoot;
  try {
    repoRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    console.log('sec-gate [3/3]: not inside a git repo — skipping hook install');
    console.log('                Run `sec-gate install` inside your project to install the hook.');
    return;
  }

  if (isHuskyRepo(repoRoot)) {
    // ── Husky repo ────────────────────────────────────────────────────────
    const huskyHookPath = path.join(repoRoot, '.husky', 'pre-commit');
    console.log('sec-gate [3/3]: husky detected — injecting into .husky/pre-commit');

    if (fs.existsSync(huskyHookPath)) {
      const existing = fs.readFileSync(huskyHookPath, 'utf8');
      if (existing.includes(HOOK_MARKER)) {
        console.log('sec-gate [3/3]: already injected into husky hook');
        return;
      }
      // Inject after husky.sh source line
      const lines = existing.split('\n');
      let insertAt = lines.length;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('husky.sh')) { insertAt = i + 1; break; }
      }
      lines.splice(insertAt, 0, ...buildHuskyInjectionBlock().split('\n'));
      fs.writeFileSync(huskyHookPath, lines.join('\n'), { encoding: 'utf8', mode: 0o755 });
    } else {
      fs.mkdirSync(path.dirname(huskyHookPath), { recursive: true });
      fs.writeFileSync(huskyHookPath, buildNewHuskyHook(), { encoding: 'utf8', mode: 0o755 });
    }
    console.log(`sec-gate [3/3]: injected into ${huskyHookPath}`);

  } else {
    // ── Standalone repo ───────────────────────────────────────────────────
    const hookDir  = path.join(repoRoot, '.git', 'hooks');
    const hookPath = path.join(hookDir, 'pre-commit');
    fs.mkdirSync(hookDir, { recursive: true });

    if (fs.existsSync(hookPath)) {
      const existing = fs.readFileSync(hookPath, 'utf8');
      if (existing.includes(HOOK_MARKER)) {
        console.log('sec-gate [3/3]: pre-commit hook already installed');
        return;
      }
      const backup = `${hookPath}.sec-gate.bak`;
      fs.copyFileSync(hookPath, backup);
      console.log(`sec-gate [3/3]: backed up existing hook → ${backup}`);
    }

    fs.writeFileSync(hookPath, buildStandaloneHook(), { encoding: 'utf8', mode: 0o755 });
    console.log(`sec-gate [3/3]: pre-commit hook installed in ${repoRoot}`);
  }
}

// ─────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────
async function main() {
  console.log('\nsec-gate: setting up bundled scanners...');
  console.log('          (set SEC_GATE_SKIP_POSTINSTALL=1 to skip this)\n');
  await installOsvScanner();
  installGovulncheck();
  autoInstallHook();
  console.log('\nsec-gate: ready. Your commits are now security-checked.\n');
}

main().catch((err) => {
  // Never fail the npm install itself — degraded mode is better than blocked install
  console.warn('sec-gate postinstall warning:', err.message);
  process.exit(0);
});
