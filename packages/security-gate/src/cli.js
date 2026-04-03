const path = require('path');

function usage() {
  // eslint-disable-next-line no-console
  console.log([
    'sec-gate - OWASP Top 10 security gate',
    '',
    'Usage:',
    '  sec-gate install        Install the pre-commit hook in this repo',
    '  sec-gate scan           Scan all tracked files',
    '  sec-gate scan --staged  Scan only staged files (used by pre-commit hook)',
    '  sec-gate doctor         Check all components are installed and working',
    ''
  ].join('\n'));
}

function parseArgs(argv) {
  const args = { _: [] };
  for (const a of argv) {
    if (a === '--staged') args.staged = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else args._.push(a);
  }
  return args;
}

async function run() {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);

  if (args.help || args._.length === 0) {
    usage();
    process.exit(0);
  }

  const cmd = args._[0];

  if (cmd === 'install') {
    const { installHook } = require('./commands/install');
    await installHook();
    return;
  }

  if (cmd === 'scan') {
    const { scan } = require('./commands/scan');
    await scan({ staged: !!args.staged });
    return;
  }

  if (cmd === 'doctor') {
    const { doctor } = require('./commands/doctor');
    await doctor();
    return;
  }

  usage();
  process.exit(1);
}

module.exports = { run };
