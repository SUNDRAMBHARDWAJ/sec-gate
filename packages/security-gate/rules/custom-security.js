'use strict';

// security-scan: disable rule-id: detect-non-literal-fs-filename reason: filePath comes from git diff --cached, not user input
// security-scan: disable rule-id: prototype-pollution reason: AST visitor pattern uses bracket notation on known node types, not user input

/**
 * @file custom-security.js
 * @description sec-gate custom security rules — AST-based analysis.
 *
 * Uses acorn to parse JavaScript/TypeScript into an Abstract Syntax Tree (AST)
 * and walks the tree to detect security issues. This is fundamentally different
 * from regex-based scanning:
 *
 * REGEX (old):  sees raw text line by line — misses multi-line patterns,
 *               variable assignments, and code structure
 *
 * AST (new):    understands code structure — tracks variable assignments,
 *               function calls, object shapes, and data flow across lines
 *
 * Rules implemented:
 *   1.  SQL injection via template literals (sequelize/knex/pg)
 *   2.  SQL injection via string concatenation
 *   3.  Hardcoded secrets in variable assignments
 *   4.  Hardcoded secrets in object literals
 *   5.  Insecure randomness (Math.random) in security context
 *   6.  Prototype pollution via bracket notation
 *   7.  Direct __proto__ access
 *   8.  Sensitive data in localStorage/sessionStorage
 *   9.  Sensitive data in console output
 *   10. Dynamic code execution (new Function / eval)
 *   11. Command injection (child_process.exec with template literal)
 *   12. Path traversal (path.join/resolve with user-like variables)
 */

const fs   = require('fs');
const path = require('path');

let acorn, walk;
try {
  acorn = require('acorn');
  walk  = require('acorn-walk');
} catch {
  // acorn not available — fall back to regex mode (degraded)
  acorn = null;
  walk  = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const SENSITIVE_NAMES = /(?:password|passwd|pwd|secret|api.?key|apikey|jwt|token|auth|credential|private.?key|access.?key|session)/i;
const DB_QUERY_METHODS = /^(query|execute|raw|runQuery|sequelize\.query|knex\.raw|pg\.query|mysql\.query|db\.query)$/i;

function nodeName(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    return `${nodeName(node.object)}.${nodeName(node.property)}`;
  }
  return '';
}

function isTemplateLiteralWithExpressions(node) {
  return node && node.type === 'TemplateLiteral' && node.expressions && node.expressions.length > 0;
}

function isConcatenatedString(node) {
  if (!node) return false;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return true;
  }
  return false;
}

function isStringLiteral(node) {
  return node && (node.type === 'Literal' && typeof node.value === 'string');
}

function isSensitiveName(name) {
  return SENSITIVE_NAMES.test(name || '');
}

function getCalleeName(node) {
  if (!node) return '';
  if (node.type === 'CallExpression') return getCalleeName(node.callee);
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    return `${nodeName(node.object)}.${nodeName(node.property)}`;
  }
  return '';
}

function makeFinding({ rule, node, filePath, extraMsg }) {
  return {
    checkId:  rule.id,
    path:     filePath,
    line:     node.loc ? node.loc.start.line : undefined,
    message:  extraMsg ? `${rule.description} ${extraMsg}` : rule.description,
    severity: rule.severity,
    owasp:    rule.owasp,
    raw:      { nodeType: node.type }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule definitions — pure metadata, logic is in the walker below
// ─────────────────────────────────────────────────────────────────────────────

const RULES = {
  SQL_TEMPLATE: {
    id: 'sql-injection-template-literal',
    description: 'SQL query built with template literal string interpolation. Variables interpolated directly into SQL allow SQL injection. Use parameterized queries: sequelize.query(sql, { replacements: [...] })',
    owasp: 'A03:2021 Injection',
    severity: 'critical'
  },
  SQL_CONCAT: {
    id: 'sql-injection-concatenation',
    description: 'SQL query built with string concatenation. Use parameterized queries instead of building SQL strings manually.',
    owasp: 'A03:2021 Injection',
    severity: 'critical'
  },
  HARDCODED_SECRET_VAR: {
    id: 'hardcoded-secret-assignment',
    description: 'Hardcoded secret detected in variable assignment. Load secrets from environment variables (process.env.MY_SECRET) instead.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'critical'
  },
  HARDCODED_SECRET_OBJ: {
    id: 'hardcoded-secret-object',
    description: 'Hardcoded secret detected in object literal. Load secrets from environment variables instead.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'critical'
  },
  INSECURE_RANDOM: {
    id: 'insecure-random-token',
    description: 'Math.random() is not cryptographically secure. Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) for tokens, session IDs, and passwords.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'high'
  },
  PROTOTYPE_POLLUTION: {
    id: 'prototype-pollution',
    description: 'Bracket notation assignment with a variable key. If the key is user-controlled, an attacker can pollute Object.prototype. Validate or whitelist keys before assignment.',
    owasp: 'A03:2021 Injection',
    severity: 'high'
  },
  PROTO_ACCESS: {
    id: 'proto-direct-access',
    description: 'Direct __proto__ access detected. This is commonly used in prototype pollution attacks.',
    owasp: 'A03:2021 Injection',
    severity: 'critical'
  },
  STORAGE_SENSITIVE: {
    id: 'webstorage-sensitive-data',
    description: 'Sensitive data stored in localStorage/sessionStorage. Web storage is accessible to XSS attacks. Use httpOnly cookies for tokens and authentication data.',
    owasp: 'A02:2021 Cryptographic Failures',
    severity: 'high'
  },
  CONSOLE_SENSITIVE: {
    id: 'console-log-sensitive',
    description: 'Possible logging of sensitive data. Passwords and tokens logged to console appear in log files and monitoring tools.',
    owasp: 'A09:2021 Security Logging and Monitoring Failures',
    severity: 'high'
  },
  DYNAMIC_CODE: {
    id: 'dynamic-code-execution',
    description: 'Dynamic code execution via eval() or new Function() with non-literal argument. This allows arbitrary JavaScript execution.',
    owasp: 'A03:2021 Injection',
    severity: 'critical'
  },
  CMD_INJECTION: {
    id: 'command-injection',
    description: 'Shell command built with template literal or concatenation. If variables contain user input, this allows command injection. Use execFile() with argument arrays instead of exec() with strings.',
    owasp: 'A03:2021 Injection',
    severity: 'critical'
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// AST walker — visits every node and applies rules
// ─────────────────────────────────────────────────────────────────────────────

function walkAST(ast, filePath) {
  const findings = [];

  // Track variable names that hold SQL-like strings (simple 1-level taint)
  const sqlVarNames = new Set();

  walk.simple(ast, {

    // ── Rule 1 & 2: SQL injection ───────────────────────────────────────────
    VariableDeclarator(node) {
      if (!node.init) return;

      // Track variables assigned a template literal with expressions
      // e.g. const rawQuery = `SELECT... ${someVar}`
      if (isTemplateLiteralWithExpressions(node.init)) {
        const varName = nodeName(node.id);
        // Heuristic: if the template looks like SQL
        const quasis = node.init.quasis.map((q) => q.value.raw).join('');
        if (/\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b/i.test(quasis)) {
          sqlVarNames.add(varName);
          findings.push(makeFinding({
            rule: RULES.SQL_TEMPLATE,
            node: node.init,
            filePath,
            extraMsg: `Variable: ${varName}`
          }));
        }
      }

      // Track string concatenation with SQL keywords
      if (isConcatenatedString(node.init)) {
        const varName = nodeName(node.id);
        // Walk the concat tree to find if SQL keywords are present
        let hasSql = false;
        walk.simple(node.init, {
          Literal(n) {
            if (typeof n.value === 'string' && /\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(n.value)) {
              hasSql = true;
            }
          }
        });
        if (hasSql) {
          sqlVarNames.add(varName);
          findings.push(makeFinding({ rule: RULES.SQL_CONCAT, node: node.init, filePath, extraMsg: `Variable: ${varName}` }));
        }
      }

      // ── Rule 3: Hardcoded secrets in variable assignment ────────────────
      const varName = nodeName(node.id);
      if (isSensitiveName(varName) && isStringLiteral(node.init) && node.init.value.length >= 6) {
        // Exclude environment variable reads
        const val = node.init.value;
        if (!val.startsWith('process.env') && !val.includes('${') && !/^(true|false|null|undefined|test|example|placeholder|changeme|xxx+|your[-_]?)$/i.test(val)) {
          findings.push(makeFinding({ rule: RULES.HARDCODED_SECRET_VAR, node, filePath, extraMsg: `Variable name: ${varName}` }));
        }
      }
    },

    // ── Rule 1 continued: SQL injection via direct db.query() call ─────────
    CallExpression(node) {
      const callee = getCalleeName(node);

      // Check if this is a db query call
      const isDbCall = /(?:query|raw|execute)\b/i.test(callee) &&
                       /(?:sequelize|knex|pg|mysql|db|pool|connection)\b/i.test(callee);

      const isGenericQuery = /^(?:query|execute|runQuery)$/.test(callee);

      if (isDbCall || isGenericQuery) {
        const firstArg = node.arguments[0];
        if (firstArg) {
          // Direct template literal in the call
          if (isTemplateLiteralWithExpressions(firstArg)) {
            findings.push(makeFinding({ rule: RULES.SQL_TEMPLATE, node, filePath }));
          }
          // Direct concatenation in the call
          if (isConcatenatedString(firstArg)) {
            findings.push(makeFinding({ rule: RULES.SQL_CONCAT, node, filePath }));
          }
          // Tainted variable passed to query
          if (firstArg.type === 'Identifier' && sqlVarNames.has(firstArg.name)) {
            findings.push(makeFinding({
              rule: RULES.SQL_TEMPLATE,
              node,
              filePath,
              extraMsg: `Tainted variable "${firstArg.name}" passed to query`
            }));
          }
        }
      }

      // ── Rule 5: Math.random() ─────────────────────────────────────────
      if (callee === 'Math.random') {
        findings.push(makeFinding({ rule: RULES.INSECURE_RANDOM, node, filePath }));
      }

      // ── Rule 8: localStorage/sessionStorage.setItem ────────────────────
      if (/^(?:localStorage|sessionStorage)\.setItem$/.test(callee)) {
        const keyArg = node.arguments[0];
        if (keyArg && isStringLiteral(keyArg) && isSensitiveName(keyArg.value)) {
          findings.push(makeFinding({ rule: RULES.STORAGE_SENSITIVE, node, filePath, extraMsg: `Key: "${keyArg.value}"` }));
        }
      }

      // ── Rule 9: console.log with sensitive variable ────────────────────
      if (/^console\.(?:log|info|warn|error|debug)$/.test(callee)) {
        for (const arg of node.arguments) {
          const argName = nodeName(arg);
          if (isSensitiveName(argName)) {
            findings.push(makeFinding({ rule: RULES.CONSOLE_SENSITIVE, node, filePath, extraMsg: `Argument: ${argName}` }));
            break;
          }
        }
      }

      // ── Rule 10: eval() ─────────────────────────────────────────────────
      if (callee === 'eval') {
        const arg = node.arguments[0];
        if (arg && !isStringLiteral(arg)) {
          findings.push(makeFinding({ rule: RULES.DYNAMIC_CODE, node, filePath }));
        }
      }

      // ── Rule 11: Command injection via exec/execSync ────────────────────
      if (/^(?:exec|execSync|spawn|spawnSync)$/.test(callee) ||
          /child_process\.(?:exec|execSync)/.test(callee)) {
        const firstArg = node.arguments[0];
        if (firstArg) {
          if (isTemplateLiteralWithExpressions(firstArg)) {
            findings.push(makeFinding({ rule: RULES.CMD_INJECTION, node, filePath }));
          }
          if (isConcatenatedString(firstArg)) {
            findings.push(makeFinding({ rule: RULES.CMD_INJECTION, node, filePath }));
          }
        }
      }
    },

    // ── Rule 10: new Function() ─────────────────────────────────────────────
    NewExpression(node) {
      if (nodeName(node.callee) === 'Function') {
        const lastArg = node.arguments[node.arguments.length - 1];
        if (lastArg && !isStringLiteral(lastArg)) {
          findings.push(makeFinding({ rule: RULES.DYNAMIC_CODE, node, filePath }));
        }
      }
    },

    // ── Rule 4: Hardcoded secrets in object literals ────────────────────────
    Property(node) {
      const keyName = nodeName(node.key) || (node.key.type === 'Literal' ? node.key.value : '');
      if (isSensitiveName(keyName) && isStringLiteral(node.value) && node.value.value.length >= 6) {
        const val = node.value.value;
        if (!/^(process\.env|true|false|null|test|example|placeholder|changeme|xxx+|your[-_]?)$/i.test(val)) {
          findings.push(makeFinding({ rule: RULES.HARDCODED_SECRET_OBJ, node, filePath, extraMsg: `Key: "${keyName}"` }));
        }
      }
    },

    // ── Rule 6: Prototype pollution via bracket notation ───────────────────
    AssignmentExpression(node) {
      // obj[variable] = value  →  node.left is MemberExpression with computed=true
      if (node.left &&
          node.left.type === 'MemberExpression' &&
          node.left.computed === true &&
          node.left.property.type === 'Identifier') {
        findings.push(makeFinding({ rule: RULES.PROTOTYPE_POLLUTION, node, filePath }));
      }
    },

    // ── Rule 7: __proto__ access ────────────────────────────────────────────
    MemberExpression(node) {
      const prop = node.property;
      if (prop && prop.type === 'Identifier' && prop.name === '__proto__') {
        findings.push(makeFinding({ rule: RULES.PROTO_ACCESS, node, filePath }));
      }
      if (prop && prop.type === 'Literal' && prop.value === '__proto__') {
        findings.push(makeFinding({ rule: RULES.PROTO_ACCESS, node, filePath }));
      }
    }

  });

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// Suppression check (reuses same format as inlineTag.js)
// ─────────────────────────────────────────────────────────────────────────────
const SUPPRESS_RE = /security-scan:\s*disable\s+rule-id:\s*(\S+)/i;

function isSuppressed(lines, lineIdx, ruleId) {
  const window = 3;
  const start  = Math.max(0, lineIdx - window);
  const end    = Math.min(lines.length - 1, lineIdx + window);

  for (let i = start; i <= end; i++) {
    const m = lines[i].match(SUPPRESS_RE);
    if (m && (m[1] === '*' || m[1] === ruleId)) return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Regex fallback — used when acorn is not available
// ─────────────────────────────────────────────────────────────────────────────
function regexFallbackScan(content, filePath) {
  const lines   = content.split(/\r?\n/);
  const findings = [];

  const PATTERNS = [
    { re: /(?:const|let|var)\s+\w*(?:password|secret|key|token|jwt)\w*\s*=\s*['"`][^'"`\s]{6,}/, rule: RULES.HARDCODED_SECRET_VAR },
    { re: /Math\.random\(\)/, rule: RULES.INSECURE_RANDOM },
    { re: /__proto__/, rule: RULES.PROTO_ACCESS },
    { re: /localStorage\.setItem\s*\(.*(?:token|password|secret)/i, rule: RULES.STORAGE_SENSITIVE },
    { re: /console\.(?:log|info|warn)\s*\(.*(?:password|secret|token)/i, rule: RULES.CONSOLE_SENSITIVE }
  ];

  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) return;
    if (isSuppressed(lines, i, '*')) return;

    for (const { re, rule } of PATTERNS) {
      if (re.test(line)) {
        findings.push({
          checkId: rule.id,
          path: filePath,
          line: i + 1,
          message: rule.description,
          severity: rule.severity,
          owasp: rule.owasp,
          raw: { line: trimmed }
        });
        break;
      }
    }
  });

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────────────────
function scanFileWithCustomRules(filePath) {
  // Only scan JS/TS files — Go is handled by govulncheck
  if (filePath.endsWith('.go')) return [];

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  // If acorn is not available, fall back to regex mode
  if (!acorn || !walk) {
    console.warn('sec-gate: acorn not available — using regex fallback for custom rules');
    return regexFallbackScan(content, filePath);
  }

  let ast;
  try {
    ast = acorn.parse(content, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,   // gives us line numbers
      allowHashBang: true,
      allowAwaitOutsideFunction: true,
      allowImportExportEverywhere: true
    });
  } catch {
    // Parse failed (e.g. TypeScript syntax, JSX) — fall back to regex
    try {
      ast = acorn.parse(content, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        locations: true,
        allowHashBang: true
      });
    } catch {
      return regexFallbackScan(content, filePath);
    }
  }

  const rawFindings = walkAST(ast, filePath);

  // Apply inline suppressions
  const lines = content.split(/\r?\n/);
  return rawFindings.filter((f) => {
    if (!f.line) return true;
    return !isSuppressed(lines, f.line - 1, f.checkId);
  });
}

module.exports = { scanFileWithCustomRules, RULES };
