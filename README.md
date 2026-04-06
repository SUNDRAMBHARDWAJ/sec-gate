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

## 🗂️ Repository Structure

```
packages/
  security-gate/         ← the npm package (published as sec-gate)
    bin/                 ← CLI entry point
    src/
      cli.js             ← command router
      commands/          ← install, scan, doctor
      scanners/          ← semgrep, osv, govulncheck runners
      suppressions/      ← inline tag filter
      git/               ← staged files, repo root helpers
      config/            ← .sec-gate.yml loader
    rules/
      custom-security.js ← AST-based custom rules (acorn)
    scripts/
      postinstall.js     ← auto-setup on npm install
    vendor-bin/          ← downloaded binaries (osv-scanner, govulncheck)
.github/
  workflows/
    security-gate.yml    ← CI gate + PR comment workflow
```

---

## 🔕 Suppressing False Positives

**Short format** _(quick)_
```js
// sec-gate-disable: sql-injection-template-literal
const rawQuery = `SELECT * FROM payments WHERE status = '${status}'`;
```

**Long format** _(recommended for PRs)_
```js
// security-scan: disable rule-id: sql-injection-template-literal reason: status validated against enum
const rawQuery = `SELECT * FROM payments WHERE status = '${status}'`;
```

---

## 🚨 Emergency Bypass

```bash
SEC_GATE_SKIP=1 git commit -m "emergency fix"
```

> ⚠️ Skips local hook only — CI will still catch it.

---

## 🔒 Supported Package Managers

<div align="center">

[![npm](https://img.shields.io/badge/npm-package--lock.json-CC3534?style=for-the-badge&logo=npm)](https://www.npmjs.com)
[![pnpm](https://img.shields.io/badge/pnpm-pnpm--lock.yaml-F69220?style=for-the-badge&logo=pnpm)](https://pnpm.io)
[![yarn](https://img.shields.io/badge/yarn-yarn.lock-2C8EBB?style=for-the-badge&logo=yarn)](https://yarnpkg.com)
[![go](https://img.shields.io/badge/Go-go.mod-00ADD8?style=for-the-badge&logo=go)](https://go.dev)

</div>

---

<div align="center">

**Built with ❤️ to make security automatic, not optional.**

[![npm](https://img.shields.io/badge/npm-sec--gate-FF6B6B?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/sec-gate)
[![GitHub](https://img.shields.io/badge/GitHub-SUNDRAMBHARDWAJ%2Fsec--gate-181717?style=for-the-badge&logo=github)](https://github.com/SUNDRAMBHARDWAJ/sec-gate)

📦 See [`packages/security-gate/README.md`](packages/security-gate/README.md) for full documentation.

</div>
