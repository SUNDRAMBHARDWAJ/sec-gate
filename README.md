# sec-gate

> Pre-commit security gate for Node/Express, Go and React codebases — enforces **OWASP Top 10 (2021)** before every `git commit`.

---

## Install — one command

```bash
npm install -g sec-gate
```

This single command does everything:
- Installs the `sec-gate` CLI globally
- Downloads the osv-scanner binary for your OS
- Installs govulncheck (if Go is available)
- Installs the pre-commit hook in your current git repo

Your next `git commit` is already security-checked. No extra steps.

---

## What gets checked

| Layer | Tool | What it finds |
|---|---|---|
| SAST | Semgrep (`owasp-top10` ruleset) | Injection, broken auth, crypto failures, SSRF, logging issues... |
| Misconfig | Semgrep (Express rules) | CORS wildcard, missing headers, auth bypass |
| SCA (Node) | OSV-Scanner | Vulnerable packages in `pnpm-lock.yaml` |
| SCA (Go) | govulncheck | Vulnerable modules in `go.mod` |

---

## Inline suppression

Add a comment near the flagged line to acknowledge a known false positive:

```js
// security-scan: disable rule-id: <RULE_ID> reason: <why this is safe>
someCode();
```

---

## Bypass (emergency only)

```bash
SEC_GATE_SKIP=1 git commit -m "emergency"
```

---

## Repository structure

```
packages/
  security-gate/       ← the npm package (published as `sec-gate`)
    bin/               ← CLI entry point
    src/
      cli.js           ← command router
      commands/        ← install, scan
      scanners/        ← semgrep, osv, govulncheck runners
      suppressions/    ← inline tag filter
      git/             ← staged files, repo root helpers
    scripts/
      postinstall.js   ← auto-setup on npm install
    vendor-bin/        ← downloaded binaries (osv-scanner, govulncheck)
.github/
  workflows/
    security-gate.yml  ← CI gate + PR comment workflow
```

---

## Full documentation

See [`packages/security-gate/README.md`](packages/security-gate/README.md) for complete usage, inline suppression syntax, team setup, and OWASP coverage details.
