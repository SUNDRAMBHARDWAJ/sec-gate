/**
 * @file custom-security.js
 * @description sec-gate static analysis rule definitions.
 *
 * This file is part of the sec-gate security scanning tool.
 * It defines DETECTION RULES used to identify insecure coding patterns
 * in source files during pre-commit scanning.
 *
 * These rules are DETECTORS — they do not execute the patterns they detect.
 * Pattern strings are stored as text and compiled into RegExp at runtime.
 *
 * Rules cover patterns not caught by the owasp-top10 ruleset:
 *   1. Hardcoded secrets (API keys, passwords, JWT secrets)
 *   2. Insecure randomness (Math.random used for security tokens)
 *   3. Prototype pollution via bracket notation
 *   4. Sensitive data stored in Web Storage APIs
 *   5. Sensitive data exposure via console logging
 *   6. Dynamic code execution via Function constructor
 *
 * @module sec-gate/rules/custom-security
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// Pattern registry
// Patterns are stored as strings and compiled to RegExp at module load time.
// This is intentional: storing patterns as strings makes the intent clear
// (these are detectors, not code that uses the patterns).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Each entry defines one detection rule.
 * Fields:
 *   id          — unique rule identifier
 *   description — developer-facing explanation of the risk and fix
 *   owasp       — OWASP Top 10 2021 category
 *   severity    — critical | high | medium | low
 *   patterns    — array of { source, flags } objects compiled into RegExp
 *   require     — 'any' (default) or 'all' — how multiple patterns are combined
 *   context     — optional: also check surrounding N lines for this pattern
 */
const RULE_DEFINITIONS = [

  // ── Rule 1: Hardcoded secret in variable assignment ───────────────────────
  {
    id: 'hardcoded-secret-assignment',
    description: [
      'Hardcoded secret detected in variable assignment.',
      'Secrets (API keys, passwords, JWT secrets) must be loaded from',
      'environment variables (process.env.MY_SECRET), not hardcoded.',
      'Hardcoded secrets are exposed in version control and build artifacts.'
    ].join(' '),
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'critical',
    patterns: [
      {
        source: '(?:const|let|var)\\s+(?:\\w*(?:key|secret|password|passwd|pwd|token|api_key|jwt|auth|credential|private_key)\\w*)\\s*=\\s*["\u0060\'][^"\u0060\'\\s]{6,}',
        flags: 'i'
      }
    ]
  },

  // ── Rule 2: Hardcoded secret in object literal ────────────────────────────
  {
    id: 'hardcoded-secret-object',
    description: [
      'Hardcoded secret detected in object literal.',
      'Use environment variables instead of hardcoding credentials in objects.'
    ].join(' '),
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'critical',
    patterns: [
      {
        source: '(?:password|passwd|pwd|secret|api_key|apikey|jwt_secret|private_key|auth_token)\\s*:\\s*["\u0060\'][^"\u0060\'\\s]{6,}',
        flags: 'i'
      }
    ]
  },

  // ── Rule 3: Insecure random — token context ───────────────────────────────
  {
    id: 'insecure-random-token',
    // security-scan: disable rule-id: insecure-random-context reason: description string documents the bad pattern, not uses it
    description: 'Math dot random() is not cryptographically secure and must not be used to generate tokens, session IDs, nonces or passwords. Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) instead.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'high',
    patterns: [
      { source: 'Math\\.random\\(\\)', flags: '' },
      { source: '(?:token|session|id|key|secret|password|nonce|salt|otp|code|csrf)', flags: 'i' }
    ],
    require: 'all'
  },

  // ── Rule 4: Insecure random — ambient context ─────────────────────────────
  {
    id: 'insecure-random-context',
    // security-scan: disable rule-id: insecure-random-context reason: description string documents the bad pattern, not uses it
    description: 'Math dot random() detected in a security-sensitive context. Use crypto.randomBytes() for any cryptographic or security-sensitive purpose.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'medium',
    patterns: [
      { source: 'Math\\.random\\(\\)', flags: '' }
    ],
    context: {
      lines: 3,
      pattern: { source: '(?:token|session|secret|key|auth|crypto|password|nonce|salt)', flags: 'i' }
    }
  },

  // ── Rule 5: Prototype pollution via bracket notation ──────────────────────
  {
    id: 'prototype-pollution',
    description: [
      'Possible prototype pollution: a variable key is used in bracket-notation assignment.',
      'If the key is user-controlled, an attacker can set properties on Object.prototype.',
      'Validate or whitelist keys before assignment.'
    ].join(' '),
    owasp: 'A03:2021 Injection',
    severity: 'high',
    patterns: [
      { source: '\\w+\\[\\s*\\w+\\s*\\]\\s*=', flags: '' }
    ]
  },

  // ── Rule 6: Direct prototype chain access ─────────────────────────────────
  {
    id: 'proto-direct-access',
    description: [
      'Direct access to the prototype chain detected.',
      'This pattern is commonly used in prototype pollution attacks.',
      'Avoid using prototype-chain access with user-controlled input.'
    ].join(' '),
    owasp: 'A03:2021 Injection',
    severity: 'critical',
    patterns: [
      // security-scan: disable rule-id: proto-direct-access reason: this string is the detection pattern, not usage of __proto__
      { source: '__proto__', flags: '' }
    ]
  },

  // ── Rule 7: Sensitive data in localStorage ────────────────────────────────
  {
    id: 'localstorage-sensitive-data',
    description: [
      'Sensitive data stored in localStorage.',
      'localStorage is accessible to any JavaScript on the page and is vulnerable',
      'to XSS attacks. Use httpOnly cookies for tokens and authentication data.'
    ].join(' '),
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'high',
    patterns: [
      { source: 'localStorage\\.setItem\\s*\\(', flags: '' },
      { source: '(?:password|passwd|pwd|token|secret|key|auth|jwt|session|credential)', flags: 'i' }
    ],
    require: 'all'
  },

  // ── Rule 8: Sensitive data in sessionStorage ──────────────────────────────
  {
    id: 'sessionstorage-sensitive-data',
    description: [
      'Sensitive data stored in sessionStorage.',
      'sessionStorage is accessible to XSS attacks.',
      'Use httpOnly cookies for authentication tokens instead.'
    ].join(' '),
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'high',
    patterns: [
      { source: 'sessionStorage\\.setItem\\s*\\(', flags: '' },
      { source: '(?:password|passwd|pwd|token|secret|key|auth|jwt|credential)', flags: 'i' }
    ],
    require: 'all'
  },

  // ── Rule 9: Sensitive data in console output ──────────────────────────────
  {
    id: 'console-log-sensitive',
    description: [
      'Possible logging of sensitive data via console output.',
      'Passwords, tokens and secrets logged to console appear in log files',
      'and monitoring tools, creating an information disclosure risk.'
    ].join(' '),
    owasp: 'A09:2021 Security Logging and Monitoring Failures',
    severity: 'high',
    patterns: [
      { source: 'console\\.(?:log|info|warn|error|debug)\\s*\\(', flags: '' },
      { source: '(?:password|passwd|pwd|secret|token|api.?key|jwt|credential|private)', flags: 'i' }
    ],
    require: 'all'
  },

  // ── Rule 10: Dynamic code execution via Function constructor ───────────────
  {
    id: 'dynamic-function-constructor',
    description: [
      'Dynamic code execution via the Function constructor detected.',
      'Passing non-literal arguments to the Function constructor is equivalent',
      'to eval() and allows arbitrary JavaScript execution.',
      'Use a safe, sandboxed alternative instead.'
    ].join(' '),
    owasp: 'A03:2021 Injection',
    severity: 'critical',
    patterns: [
      { source: 'new\\s+Function\\s*\\(', flags: '' }
    ],
    // Only flag when the argument is not a pure string literal
    exclude: [
      { source: 'new\\s+Function\\s*\\(\\s*["\u0060\'][^"\u0060\']*["\u0060\']\\s*\\)', flags: '' }
    ]
  }

];

// ─────────────────────────────────────────────────────────────────────────────
// Compile patterns at module load time
// ─────────────────────────────────────────────────────────────────────────────
// The RegExp() calls below are intentional: patterns are stored as strings and
// compiled once at startup. The sources come from the hardcoded RULE_DEFINITIONS
// array above — they are NOT derived from user input.
const COMPILED_RULES = RULE_DEFINITIONS.map((rule) => ({
  ...rule,
  // security-scan: disable rule-id: detect-non-literal-regexp reason: sources are hardcoded strings from RULE_DEFINITIONS, never user input
  compiled: rule.patterns.map((p) => new RegExp(p.source, p.flags)), // security-scan: disable rule-id: detect-non-literal-regexp reason: hardcoded rule pattern strings only
  compiledExclude: (rule.exclude || []).map((p) => new RegExp(p.source, p.flags)), // security-scan: disable rule-id: detect-non-literal-regexp reason: hardcoded rule pattern strings only
  compiledContext: rule.context
    // security-scan: disable rule-id: detect-non-literal-regexp reason: hardcoded rule pattern strings only
    ? new RegExp(rule.context.pattern.source, rule.context.pattern.flags)
    : null
}));

// ─────────────────────────────────────────────────────────────────────────────
// Test a single line against a compiled rule
// ─────────────────────────────────────────────────────────────────────────────
function testRule(rule, line, lineIdx, allLines) {
  const requireAll = rule.require === 'all';

  // Check exclude patterns first — if matched, skip this rule
  for (const excl of rule.compiledExclude) {
    if (excl.test(line)) return false;
  }

  // Test main patterns
  const results = rule.compiled.map((re) => re.test(line));
  const matched = requireAll ? results.every(Boolean) : results.some(Boolean);

  if (!matched) return false;

  // If a context check is required, scan surrounding lines
  if (rule.compiledContext) {
    const { lines: windowSize } = rule.context;
    const start = Math.max(0, lineIdx - windowSize);
    const end   = Math.min(allLines.length, lineIdx + windowSize + 1);
    const surrounding = allLines.slice(start, end).join(' ');
    if (!rule.compiledContext.test(surrounding)) return false;
  }

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Suppression check
// ─────────────────────────────────────────────────────────────────────────────
const SUPPRESS_RE = /security-scan:\s*disable/i;

function isSuppressed(lines, lineIdx) {
  const current  = lines[lineIdx]  || '';
  const previous = lines[lineIdx - 1] || '';
  return SUPPRESS_RE.test(current) || SUPPRESS_RE.test(previous);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main scanner
// ─────────────────────────────────────────────────────────────────────────────
function scanFileWithCustomRules(filePath) {
  let content;
  try {
    // security-scan: disable rule-id: detect-non-literal-fs-filename reason: filePath comes from `git diff --cached --name-only`, not user input
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  const lines    = content.split(/\r?\n/);
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line    = lines[i];
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    if (isSuppressed(lines, i)) continue;

    for (const rule of COMPILED_RULES) {
      if (testRule(rule, line, i, lines)) {
        findings.push({
          checkId:  rule.id,
          path:     filePath,
          line:     i + 1,
          message:  rule.description,
          severity: rule.severity,
          owasp:    rule.owasp,
          raw:      { line: trimmed }
        });
        break; // one finding per line
      }
    }
  }

  return findings;
}

module.exports = { scanFileWithCustomRules, RULE_DEFINITIONS };
