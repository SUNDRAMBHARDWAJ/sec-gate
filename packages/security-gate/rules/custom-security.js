/**
 * sec-gate custom security rules
 *
 * These rules cover patterns NOT caught by @pensar/semgrep-node's owasp-top10 ruleset:
 *   1. Hardcoded secrets (API keys, passwords, JWT secrets)
 *   2. Insecure randomness (Math.random for tokens/sessions)
 *   3. Prototype pollution
 *   4. Sensitive data in localStorage
 *   5. console.log with passwords/secrets
 *   6. new Function() with dynamic input
 */

const fs   = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────
// Rule definitions
// Each rule: { id, description, owasp, severity, test(line, lineNum, allLines) }
// Returns a finding object or null
// ─────────────────────────────────────────────────────────

const RULES = [

  // ── 1. Hardcoded secrets ──────────────────────────────
  {
    id: 'hardcoded-secret-assignment',
    description: 'Hardcoded secret detected. Secrets should be loaded from environment variables, not hardcoded in source code.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'critical',
    test(line) {
      // Match: const/let/var API_KEY = "...", DB_PASSWORD = '...', etc.
      return /(?:const|let|var)\s+(?:\w*(?:key|secret|password|passwd|pwd|token|api_key|jwt|auth|credential|private_key)\w*)\s*=\s*["'`][^"'`\s]{6,}/i.test(line);
    }
  },

  {
    id: 'hardcoded-secret-object',
    description: 'Hardcoded secret in object literal. Use environment variables instead.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'critical',
    test(line) {
      // Match: { password: "...", apiKey: "...", secret: "..." }
      return /(?:password|passwd|pwd|secret|api_key|apikey|jwt_secret|private_key|auth_token)\s*:\s*["'`][^"'`\s]{6,}/i.test(line);
    }
  },

  // ── 2. Insecure randomness ────────────────────────────
  {
    id: 'insecure-random-token',
    // security-scan: disable rule-id: insecure-random-token reason: this is a rule description string, not actual Math.random() usage
    description: 'Math.random() is not cryptographically secure. For tokens, session IDs or passwords use crypto.randomBytes() or crypto.getRandomValues() instead.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'high',
    test(line) {
      return /Math\.random\(\)/.test(line) &&
        /(?:token|session|id|key|secret|password|nonce|salt|otp|code|csrf)/i.test(line);
    }
  },

  {
    id: 'insecure-random-standalone',
    // security-scan: disable rule-id: insecure-random-standalone reason: rule description string, not actual usage
    description: 'Math.random() used in a security-sensitive context. Use crypto.randomBytes() for cryptographic purposes.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'medium',
    test(line, lineNum, allLines) {
      if (!(/Math\.random\(\)/.test(line))) return false;
      // Check surrounding 3 lines for security context
      const ctx = allLines.slice(Math.max(0, lineNum - 3), lineNum + 3).join(' ');
      return /(?:token|session|secret|key|auth|crypto|password|nonce|salt)/i.test(ctx);
    }
  },

  // ── 3. Prototype pollution ────────────────────────────
  {
    id: 'prototype-pollution',
    description: 'Possible prototype pollution: assigning to a bracket-notation property using a variable key. Validate or whitelist keys before assignment.',
    owasp: 'A03:2021 Injection',
    severity: 'high',
    test(line) {
      // obj[userKey] = value  or  target[key] = val where key is variable
      return /\w+\[\s*\w+\s*\]\s*=/.test(line) &&
        !/\/\//.test(line.split('=')[0]); // not in a comment
    }
  },

  {
    id: 'proto-direct-access',
    // security-scan: disable rule-id: proto-direct-access reason: description string contains __proto__ as text only, not as code
    description: 'Direct __proto__ access detected. This can lead to prototype pollution.',
    owasp: 'A03:2021 Injection',
    severity: 'critical',
    test(line) {
      // security-scan: disable rule-id: proto-direct-access reason: __proto__ is inside a regex literal used as a detection pattern, not actual prototype access
      return /__proto__/.test(line);
    }
  },

  // ── 4. Sensitive data in localStorage ────────────────
  {
    id: 'localstorage-sensitive-data',
    description: 'Sensitive data stored in localStorage. localStorage is accessible to any JS on the page (XSS). Use httpOnly cookies for tokens and passwords.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'high',
    test(line) {
      return /localStorage\.setItem\s*\(/.test(line) &&
        /(?:password|passwd|pwd|token|secret|key|auth|jwt|session|credential)/i.test(line);
    }
  },

  {
    id: 'sessionstorage-sensitive-data',
    description: 'Sensitive data stored in sessionStorage. sessionStorage is accessible to XSS attacks. Use httpOnly cookies instead.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'high',
    test(line) {
      return /sessionStorage\.setItem\s*\(/.test(line) &&
        /(?:password|passwd|pwd|token|secret|key|auth|jwt|credential)/i.test(line);
    }
  },

  // ── 5. console.log with sensitive data ───────────────
  {
    id: 'console-log-sensitive',
    description: 'Possible logging of sensitive data. Passwords, tokens and secrets should never be logged as they appear in log files and monitoring tools.',
    owasp: 'A09:2021 Security Logging and Monitoring Failures',
    severity: 'high',
    test(line) {
      return /console\.\s*(?:log|info|warn|error|debug)\s*\(/.test(line) &&
        /(?:password|passwd|pwd|secret|token|api_?key|jwt|credential|private)/i.test(line);
    }
  },

  // ── 6. new Function() with dynamic input ─────────────
  {
    id: 'new-function-injection',
    // security-scan: disable rule-id: new-function-injection reason: this is a rule description string, not actual new Function() usage
    description: 'new Function() with dynamic input is equivalent to eval(). An attacker can execute arbitrary JavaScript. Use a safe alternative.',
    owasp: 'A03:2021 Injection',
    severity: 'critical',
    test(line) {
      // new Function(variable) or new Function("..." + variable)
      return /new\s+Function\s*\(/.test(line) &&
        !/new\s+Function\s*\(\s*["'`][^"'`]*["'`]\s*\)/.test(line); // not pure string literal
    }
  },

];

// ─────────────────────────────────────────────────────────
// Scanner: run all rules against a file
// ─────────────────────────────────────────────────────────
function scanFileWithCustomRules(filePath) {
  let content;
  try {
    // security-scan: disable rule-id: detect-non-literal-fs-filename reason: filePath comes from `git diff --cached --name-only`, not from user input
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  const lines = content.split(/\r?\n/);
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line     = lines[i];
    const lineNum  = i + 1;
    const trimmed  = line.trim();

    // Skip blank lines and pure comments
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    // Skip lines with suppression tag
    if (/security-scan:\s*disable/i.test(line)) continue;

    // Also check the line immediately above for suppression
    const prevLine = i > 0 ? lines[i - 1] : '';
    if (/security-scan:\s*disable/i.test(prevLine)) continue;

    for (const rule of RULES) {
      if (rule.test(line, i, lines)) {
        findings.push({
          checkId:  rule.id,
          path:     filePath,
          line:     lineNum,
          message:  rule.description,
          severity: rule.severity,
          owasp:    rule.owasp,
          raw:      { line: trimmed }
        });
        break; // one finding per line per pass — avoid duplicates
      }
    }
  }

  return findings;
}

module.exports = { scanFileWithCustomRules, RULES };
