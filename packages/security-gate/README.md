<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=28&pause=1000&color=FF6B6B&center=true&vCenter=true&width=600&lines=sec-gate+%F0%9F%94%90;OWASP+Top+10+Security+Gate;Block+Vulnerabilities+Before+Commit" alt="sec-gate" />

<br/>

[![npm version](https://img.shields.io/npm/v/sec-gate?style=for-the-badge&color=FF6B6B&labelColor=1a1a2e)](https://www.npmjs.com/package/sec-gate)
[![npm downloads](https://img.shields.io/npm/dm/sec-gate?style=for-the-badge&color=4ECDC4&labelColor=1a1a2e)](https://www.npmjs.com/package/sec-gate)
[![License: MIT](https://img.shields.io/badge/License-MIT-FFE66D?style=for-the-badge&labelColor=1a1a2e)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-43B883?style=for-the-badge&labelColor=1a1a2e)](https://nodejs.org)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-FF6B6B?style=for-the-badge&labelColor=1a1a2e)](https://owasp.org/Top10/)

<br/>

> **A pre-commit security gate that automatically blocks vulnerable code before every `git commit`.**
> Covers SAST · SCA · Misconfigurations · SQL Injection · Hardcoded Secrets and more.

<br/>

```
  git commit  →  sec-gate scans  →  vulnerability?  →  BLOCKED ✗
                                 →  clean?          →  committed ✓
```

</div>

---

## ⚡ Quick Start

```bash
# Step 1 — Install globally (once per machine)
npm install -g sec-gate

# Step 2 — Hook into your repo (once per clone)
cd your-project
sec-gate install

# Step 3 — Commit as normal — scans run automatically
git commit -m "your changes"
```

> **That's it.** No config needed. No extra tools to install. Everything is bundled.

---

## 🛡️ What gets scanned

<div align="center">

| Layer | Tool | What it catches |
|:---:|:---:|:---|
| ![SAST](https://img.shields.io/badge/SAST-Semgrep-FF6B6B?style=flat-square) | Semgrep + AST rules | SQL injection, XSS, command injection, hardcoded secrets |
| ![SCA](https://img.shields.io/badge/SCA-OSV--Scanner-4ECDC4?style=flat-square) | OSV-Scanner | Known CVEs in npm/pnpm/yarn dependencies |
| ![GO](https://img.shields.io/badge/SCA-govulncheck-43B883?style=flat-square) | govulncheck | Known CVEs in Go modules |
| ![CUSTOM](https://img.shields.io/badge/AST-Custom%20Rules-FFE66D?style=flat-square) | acorn AST walker | Prototype pollution, insecure random, eval injection |

</div>

---

## 🔴 What blocked output looks like

```
sec-gate: scan started (staged files)
sec-gate: excluding 3 high-noise rule(s)
sec-gate: scanning src/services/payment.js (js) with owasp-top10 rules...

sec-gate: SECURITY FINDINGS (commit blocked):

- src/services/payment.js:40 [CRITICAL] [sql-injection-template-literal] (A03:2021 Injection)
  SQL query built with template literal interpolation.
  Use parameterized queries: sequelize.query(sql, { replacements: [...] })

- src/services/payment.js:82 [LOW] [insecure-object-assign] (A01:2021)
  Object.assign with potentially user-controlled data.

- package-lock.json [OSV:GHSA-r5fr-rjxr-66jc]
  lodash: vulnerable to Code Injection via _.template
```

## 🟢 What a clean commit looks like

```
sec-gate: scan started (staged files)
sec-gate: excluding 3 high-noise rule(s)
sec-gate: all checks passed — no vulnerabilities found by sec-gate
sec-gate: checks ran: SAST (3 files), SCA-node (package-lock.json)
```

---

## 🗂️ OWASP Top 10 (2021) Coverage

<div align="center">

| # | Category | Status |
|:---:|:---|:---:|
| A01 | Broken Access Control | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A02 | Cryptographic Failures | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A03 | Injection (SQL · XSS · CMD) | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A04 | Insecure Design | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A05 | Security Misconfiguration | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A06 | Vulnerable Components | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A07 | Authentication Failures | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A08 | Software Integrity Failures | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A09 | Security Logging Failures | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |
| A10 | Server-Side Request Forgery | ![covered](https://img.shields.io/badge/covered-4ECDC4?style=flat-square) |

</div>

---

## 🔧 All Commands

```bash
sec-gate install        # Install/inject pre-commit hook (auto-detects husky, lefthook etc.)
sec-gate scan           # Scan all tracked files
sec-gate scan --staged  # Scan only staged files
sec-gate doctor         # Diagnose installation issues
sec-gate --version      # Print installed version
sec-gate --help         # Show help
```

---

## 🔕 Suppressing False Positives

Two formats supported — use whichever you prefer:

**Short format** _(quick)_
```js
// sec-gate-disable: sql-injection-template-literal
const rawQuery = `SELECT * FROM payments WHERE status = '${status}'`;
```

**Long format** _(recommended for PRs — shows reason)_
```js
// security-scan: disable rule-id: sql-injection-template-literal reason: status validated against enum
const rawQuery = `SELECT * FROM payments WHERE status = '${status}'`;
```

**Suppress all rules on a line**
```js
// sec-gate-disable: *
dangerousLegacyFunction();
```

---

## ⚙️ Configuration (`.sec-gate.yml`)

Create this file in your project root to tune the scanner:

```yaml
# .sec-gate.yml

# Block only on high/critical findings
severity_threshold: high

# Exclude specific rules globally
exclude_rules:
  - path-join-resolve-traversal
  - detect-non-literal-regexp

# Skip test and mock files
exclude_paths:
  - "**/__tests__/**"
  - "**/*.test.js"
  - "**/mocks/**"

# Toggle scanners
sca: true
custom_rules: true
```

<details>
<summary>📋 All severity threshold options</summary>

| Value | Blocks on |
|---|---|
| `all` (default) | Every finding |
| `high` | High + Critical only |
| `critical` | Critical only |
| `medium` | Medium + High + Critical |
| `low` | Everything (same as all) |

</details>

---

## 🪝 Hook Manager Support

`sec-gate install` automatically detects your hook manager — no manual config needed:

<div align="center">

| Tool | Detection | Auto-injected |
|:---:|:---:|:---:|
| ![Husky](https://img.shields.io/badge/Husky-v6%2B-FF6B6B?style=flat-square) | `.husky/` directory | ✅ `.husky/pre-commit` |
| ![Husky](https://img.shields.io/badge/Husky-v4-FF6B6B?style=flat-square) | `package.json` hooks | ✅ prepended to command |
| ![lefthook](https://img.shields.io/badge/lefthook-FFE66D?style=flat-square) | `lefthook.yml` | ✅ priority 1 command |
| ![simple-git-hooks](https://img.shields.io/badge/simple--git--hooks-4ECDC4?style=flat-square) | `package.json` | ✅ prepended to command |
| ![pre-commit](https://img.shields.io/badge/pre--commit%20(py)-43B883?style=flat-square) | `.pre-commit-config.yaml` | ✅ local hook entry |
| ![bare git](https://img.shields.io/badge/bare%20git-lightgrey?style=flat-square) | no manager | ✅ `.git/hooks/pre-commit` |

</div>

---

## 🔒 Supported Package Managers

<div align="center">

[![npm](https://img.shields.io/badge/npm-package--lock.json-CC3534?style=for-the-badge&logo=npm)](https://www.npmjs.com)
[![pnpm](https://img.shields.io/badge/pnpm-pnpm--lock.yaml-F69220?style=for-the-badge&logo=pnpm)](https://pnpm.io)
[![yarn](https://img.shields.io/badge/yarn-yarn.lock-2C8EBB?style=for-the-badge&logo=yarn)](https://yarnpkg.com)
[![go](https://img.shields.io/badge/Go-go.mod-00ADD8?style=for-the-badge&logo=go)](https://go.dev)

</div>

---

## 🚨 Emergency Bypass

```bash
# Skip the scan for this commit only (emergency use only)
SEC_GATE_SKIP=1 git commit -m "emergency fix"
```

> ⚠️ This only skips the **local** pre-commit hook. CI will still catch it.

---

## 👥 Team Auto-Setup

Add to your project's `package.json` so every developer gets the hook automatically on `npm install`:

```json
{
  "scripts": {
    "prepare": "sec-gate install"
  }
}
```

Then new developer onboarding is just:

```bash
npm install -g sec-gate   # once per machine
npm install               # installs hook automatically via prepare script
```

---

## 🏗️ How it works internally

```
git commit
    │
    ▼
pre-commit hook
    │
    ├── Load .sec-gate.yml config
    │
    ├── SAST ──► Semgrep (owasp-top10)
    │        ──► AST walker (acorn) — SQL injection, secrets, prototype pollution
    │
    ├── SCA  ──► osv-scanner (npm/pnpm/yarn lockfile)
    │        ──► govulncheck (go.mod)
    │
    ├── Apply inline suppressions (sec-gate-disable / security-scan: disable)
    │
    ├── Apply config filters (exclude_rules, exclude_paths, severity_threshold)
    │
    ├── Findings? → exit 1 → commit BLOCKED ✗
    └── Clean?   → exit 0 → commit proceeds ✓
```

---

<div align="center">

**Built with ❤️ to make security automatic, not optional.**

[![npm](https://img.shields.io/badge/npm-sec--gate-FF6B6B?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/sec-gate)
[![GitHub](https://img.shields.io/badge/GitHub-SUNDRAMBHARDWAJ%2Fsec--gate-181717?style=for-the-badge&logo=github)](https://github.com/SUNDRAMBHARDWAJ/sec-gate)

</div>
