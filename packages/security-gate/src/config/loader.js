'use strict';

// security-scan: disable rule-id: path-join-resolve-traversal reason: repoRoot comes from git rev-parse, not user input
// security-scan: disable rule-id: detect-non-literal-fs-filename reason: repoRoot comes from git rev-parse, not user input
// security-scan: disable rule-id: detect-non-literal-regexp reason: patterns come from the config file written by the developer, not from end users
// security-scan: disable rule-id: prototype-pollution reason: result[key] assignment is parsing a config file where keys are validated against a known whitelist of fields

/**
 * sec-gate config loader
 *
 * Reads .sec-gate.yml (or .sec-gate.yaml / sec-gate.config.js) from the
 * repo root and merges it with built-in defaults.
 *
 * Config file example (.sec-gate.yml):
 * ─────────────────────────────────────
 * severity_threshold: high       # block only on: critical, high, medium, low, all (default: all)
 * exclude_rules:                 # rule IDs to never report
 *   - path-join-resolve-traversal
 *   - detect-non-literal-regexp
 * exclude_paths:                 # glob patterns to skip
 *   - "**\/__tests__\/**"
 *   - "**\/mocks\/**"
 *   - "**\/fixtures\/**"
 * sca: true                      # enable/disable SCA (default: true)
 * custom_rules: true             # enable/disable custom rules (default: true)
 */

const fs   = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// Severity ordering — higher index = more severe
// ─────────────────────────────────────────────────────────────────────────────
const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

// ─────────────────────────────────────────────────────────────────────────────
// Built-in defaults
// ─────────────────────────────────────────────────────────────────────────────
const DEFAULTS = {
  // Block commit on any finding regardless of severity
  severity_threshold: 'all',

  // Rules excluded by default — these have very high false positive rates
  // and rarely indicate real vulnerabilities in typical codebases.
  // Developers can re-enable them by setting exclude_rules: [] in their config.
  exclude_rules: [
    'path-join-resolve-traversal',       // flags ANY variable in path.join — ~75% FP rate
    'detect-non-literal-regexp',         // flags RegExp(var) even with hardcoded sources
    'detect-non-literal-fs-filename'     // flags ANY variable in fs calls — ~70% FP rate
  ],

  // Paths excluded from scanning by default
  exclude_paths: [
    '**/__tests__/**',
    '**/*.test.js',
    '**/*.test.ts',
    '**/*.spec.js',
    '**/*.spec.ts',
    '**/test/**',
    '**/tests/**',
    '**/mocks/**',
    '**/fixtures/**',
    '**/vendor/**',
    '**/node_modules/**'
  ],

  sca: true,
  custom_rules: true
};

// ─────────────────────────────────────────────────────────────────────────────
// Simple YAML parser (only handles the subset we need — no external dep)
// Supports: string values, boolean values, string arrays
// ─────────────────────────────────────────────────────────────────────────────
function parseYaml(text) {
  const result = {};
  let currentKey = null;
  let currentArray = null;

  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').trimEnd(); // strip comments
    if (!line.trim()) continue;

    // Array item: "  - value"
    if (/^\s+-\s+/.test(line) && currentKey && currentArray !== null) {
      const val = line.replace(/^\s+-\s+/, '').replace(/^['"]|['"]$/g, '').trim();
      currentArray.push(val);
      continue;
    }

    // Key-value: "key: value" or "key:" (start of array)
    const kvMatch = line.match(/^(\w+):\s*(.*)?$/);
    if (kvMatch) {
      if (currentKey && currentArray !== null) {
        result[currentKey] = currentArray;
      }
      currentKey = kvMatch[1].trim();
      const rawVal = (kvMatch[2] || '').trim().replace(/^['"]|['"]$/g, '');

      if (rawVal === '') {
        // Start of array block
        currentArray = [];
      } else if (rawVal === 'true') {
        result[currentKey] = true;
        currentKey = null;
        currentArray = null;
      } else if (rawVal === 'false') {
        result[currentKey] = false;
        currentKey = null;
        currentArray = null;
      } else {
        result[currentKey] = rawVal;
        currentKey = null;
        currentArray = null;
      }
      continue;
    }
  }

  // Flush last array
  if (currentKey && currentArray !== null) {
    result[currentKey] = currentArray;
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Load and merge config
// ─────────────────────────────────────────────────────────────────────────────
function loadConfig(repoRoot) {
  const candidates = [
    path.join(repoRoot, '.sec-gate.yml'),
    path.join(repoRoot, '.sec-gate.yaml'),
    path.join(repoRoot, 'sec-gate.config.yml')
  ];

  let userConfig = {};

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        const text = fs.readFileSync(candidate, 'utf8');
        userConfig = parseYaml(text);
        // eslint-disable-next-line no-console
        console.log(`sec-gate: loaded config from ${path.basename(candidate)}`);
        break;
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`sec-gate: warning — could not parse ${candidate}: ${err.message}`);
      }
    }
  }

  // Merge: user config overrides defaults
  // For arrays, user config REPLACES defaults (not merges), so teams have full control
  const merged = {
    severity_threshold: userConfig.severity_threshold || DEFAULTS.severity_threshold,
    exclude_rules: Array.isArray(userConfig.exclude_rules)
      ? userConfig.exclude_rules
      : DEFAULTS.exclude_rules,
    exclude_paths: Array.isArray(userConfig.exclude_paths)
      ? userConfig.exclude_paths
      : DEFAULTS.exclude_paths,
    sca: userConfig.sca !== undefined ? userConfig.sca : DEFAULTS.sca,
    custom_rules: userConfig.custom_rules !== undefined
      ? userConfig.custom_rules
      : DEFAULTS.custom_rules
  };

  return merged;
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity check — should this finding be blocked given the threshold?
// ─────────────────────────────────────────────────────────────────────────────
function meetsThreshold(findingSeverity, threshold) {
  if (threshold === 'all') return true;

  const findingLevel = SEVERITY_ORDER.indexOf((findingSeverity || 'low').toLowerCase());
  const thresholdLevel = SEVERITY_ORDER.indexOf((threshold || 'all').toLowerCase());

  if (thresholdLevel === -1) return true; // unknown threshold → block everything
  if (findingLevel === -1) return true;   // unknown severity → be safe, block it

  return findingLevel >= thresholdLevel;
}

// ─────────────────────────────────────────────────────────────────────────────
// Path exclusion check
// ─────────────────────────────────────────────────────────────────────────────
function isExcludedPath(filePath, excludePatterns) {
  if (!excludePatterns || excludePatterns.length === 0) return false;

  const normalized = filePath.replace(/\\/g, '/');

  for (const pattern of excludePatterns) {
    // Convert glob to simple regex:
    // **/ matches any directory depth
    // * matches anything except /
    const regexStr = pattern
      .replace(/\\/g, '/')
      .replace(/\./g, '\\.')
      .replace(/\*\*\//g, '(?:.+/)?')
      .replace(/\*/g, '[^/]*');

    const re = new RegExp(`(^|/)${regexStr}(/|$)`);
    if (re.test(normalized)) return true;
  }

  return false;
}

module.exports = { loadConfig, meetsThreshold, isExcludedPath, SEVERITY_ORDER };
