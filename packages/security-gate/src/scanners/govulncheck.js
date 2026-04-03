const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// Path to the binary installed by postinstall via `go install`
const ext = process.platform === 'win32' ? '.exe' : '';
const VENDOR_BIN = path.join(__dirname, '..', '..', 'vendor-bin', `govulncheck${ext}`);

function getGovulncheckBinary() {
  if (fs.existsSync(VENDOR_BIN)) return VENDOR_BIN;

  // Fallback: check PATH
  try {
    const found = execFileSync('which', ['govulncheck'], {
      stdio: ['ignore', 'pipe', 'ignore']
    }).toString().trim();
    if (found) return 'govulncheck';
  } catch {}

  return null;
}

function parseGovulncheckOutput(stdout) {
  const trimmed = (stdout || '').trim();
  if (!trimmed) return [];

  // govulncheck streams newline-delimited JSON objects.
  const findings = [];

  const lines = trimmed.split(/\n+/).map((l) => l.trim()).filter(Boolean);

  for (const line of lines) {
    let obj;
    try { obj = JSON.parse(line); } catch { continue; }

    // Each message has a `finding` key when a vulnerability is detected.
    if (obj && obj.finding) {
      const f = obj.finding;
      findings.push({
        checkId: `GOVULN:${f.osv || f.trace && f.trace[0] && f.trace[0].function || 'unknown'}`,
        path: (f.trace && f.trace[0] && f.trace[0].position && f.trace[0].position.filename) || 'go.mod',
        line: (f.trace && f.trace[0] && f.trace[0].position && f.trace[0].position.line) || undefined,
        message: `${f.osv || 'vulnerability'}: ${f.trace && f.trace[0] && f.trace[0].function ? `called via ${f.trace[0].function}` : 'vulnerable module in use'}`,
        severity: undefined,
        raw: f
      });
    }
  }

  return findings;
}

async function runGovulncheck({ pattern }) {
  const bin = getGovulncheckBinary();

  if (!bin) {
    console.warn(
      'sec-gate: govulncheck not found. Go dependency SCA will be skipped.\n' +
      '  Install Go and run: go install golang.org/x/vuln/cmd/govulncheck@latest'
    );
    return [];
  }

  try {
    const stdout = execFileSync(bin, ['-json', pattern], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
    return parseGovulncheckOutput(stdout);
  } catch (e) {
    // exit code 3 = vulnerabilities found — parse stdout anyway
    const stdout = e && e.stdout ? e.stdout.toString('utf8') : '';
    return parseGovulncheckOutput(stdout);
  }
}

module.exports = { runGovulncheck };
