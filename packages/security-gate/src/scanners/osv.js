const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

// Path to the binary downloaded by postinstall
const ext = process.platform === 'win32' ? '.exe' : '';
const VENDOR_BIN = path.join(__dirname, '..', '..', 'vendor-bin', `osv-scanner${ext}`);

function getOsvBinary() {
  if (fs.existsSync(VENDOR_BIN)) return VENDOR_BIN;

  // Fallback: check PATH (manual installs)
  try {
    const found = execFileSync('which', ['osv-scanner'], {
      stdio: ['ignore', 'pipe', 'ignore']
    }).toString().trim();
    if (found) return 'osv-scanner';
  } catch {}

  return null;
}

async function runOsvScanner({ lockfile }) {
  const bin = getOsvBinary();

  if (!bin) {
    console.warn(
      'sec-gate: osv-scanner not found. Node/pnpm dependency SCA will be skipped.\n' +
      '  Run `npm i -g sec-gate` again, or install manually: https://google.github.io/osv-scanner/installation'
    );
    return [];
  }

  if (!fs.existsSync(lockfile)) {
    return [];
  }

  const out = path.join(os.tmpdir(), `sec-gate-osv-${Date.now()}.json`);

  const args = ['scan', '-L', lockfile, '--format', 'json', '--output-file', out];

  try {
    execFileSync(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch {
    // exit code 1 = vulnerabilities found — expected, not an error
  }

  if (!fs.existsSync(out)) return [];
  const text = fs.readFileSync(out, 'utf8');
  if (!text) return [];

  const parsed = JSON.parse(text);
  const results = parsed.results || [];

  const findings = [];
  for (const result of results) {
    for (const pkg of result.packages || []) {
      for (const vuln of pkg.vulnerabilities || []) {
        findings.push({
          checkId: `OSV:${vuln.id || 'unknown'}`,
          path: lockfile,
          line: undefined,
          message: `${pkg.package && pkg.package.name ? pkg.package.name : 'dependency'}: ${vuln.summary || vuln.id}`,
          severity: undefined,
          raw: vuln
        });
      }
    }
  }

  return findings;
}

module.exports = { runOsvScanner };
