const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function check(label, fn) {
  try {
    const result = fn();
    console.log(`  [OK]  ${label}${result ? ': ' + result : ''}`);
    return true;
  } catch (err) {
    console.log(`  [FAIL] ${label}: ${err.message}`);
    return false;
  }
}

async function doctor() {
  console.log('\nsec-gate doctor — checking all components\n');

  // 1. sec-gate itself
  check('sec-gate CLI', () => {
    const pkg = require('../../package.json');
    return `v${pkg.version}`;
  });

  // 2. @pensar/semgrep-node
  console.log('\n--- SAST (Semgrep) ---');
  const semgrepOk = check('@pensar/semgrep-node installed', () => {
    const pkg = require('@pensar/semgrep-node');
    return 'found';
  });

  if (semgrepOk) {
    // Try actually loading the binary by doing a tiny scan on a temp file
    await (async () => {
      try {
        const os = require('os');
        const tmpFile = path.join(os.tmpdir(), 'sec-gate-test.js');
        fs.writeFileSync(tmpFile, '// test\nconst x = 1;\n');
        const scan = require('@pensar/semgrep-node').default;
        await scan(tmpFile, { language: 'js', ruleSets: ['owasp-top10'] });
        fs.unlinkSync(tmpFile);
        console.log('  [OK]  semgrep binary: working');
      } catch (err) {
        console.log(`  [FAIL] semgrep binary: ${err.message}`);
        console.log('         Fix: the semgrep binary may not be downloaded yet.');
        console.log('         Try running `sec-gate scan` on a JS file once to trigger download.');
      }
    })();
  }

  // 3. osv-scanner
  console.log('\n--- SCA: Node/pnpm (OSV-Scanner) ---');
  const ext = process.platform === 'win32' ? '.exe' : '';
  const vendorOsv = path.join(__dirname, '..', '..', 'vendor-bin', `osv-scanner${ext}`);

  check('osv-scanner binary (vendor-bin)', () => {
    if (fs.existsSync(vendorOsv)) return vendorOsv;
    throw new Error('not found in vendor-bin');
  });

  check('osv-scanner executable', () => {
    if (!fs.existsSync(vendorOsv)) throw new Error('binary missing');
    const out = execFileSync(vendorOsv, ['--version'], { encoding: 'utf8' }).trim();
    return out;
  });

  // 4. govulncheck
  console.log('\n--- SCA: Go (govulncheck) ---');
  const vendorGo = path.join(__dirname, '..', '..', 'vendor-bin', `govulncheck${ext}`);

  check('govulncheck binary (vendor-bin)', () => {
    if (fs.existsSync(vendorGo)) return vendorGo;
    throw new Error('not found — Go SCA will be skipped (Go may not be installed)');
  });

  // 5. git hook
  console.log('\n--- Pre-commit hook ---');
  check('git available', () => {
    execFileSync('git', ['--version'], { stdio: ['ignore', 'pipe', 'ignore'] });
    return 'found';
  });

  try {
    const repoRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();

    const hookPath = path.join(repoRoot, '.git', 'hooks', 'pre-commit');
    check('pre-commit hook installed', () => {
      if (!fs.existsSync(hookPath)) throw new Error('not found — run `sec-gate install`');
      const content = fs.readFileSync(hookPath, 'utf8');
      if (!content.includes('installed-by: sec-gate')) throw new Error('hook exists but was not installed by sec-gate');
      return hookPath;
    });
  } catch {
    console.log('  [SKIP] pre-commit hook: not inside a git repo');
  }

  console.log('\nsec-gate doctor done.\n');
}

module.exports = { doctor };
