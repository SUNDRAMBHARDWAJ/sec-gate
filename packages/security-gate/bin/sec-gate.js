#!/usr/bin/env node

const { run } = require('../src/cli');

run().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
