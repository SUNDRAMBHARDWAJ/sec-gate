# sec-gate

A pre-commit security gate that enforces **OWASP Top 10 (2021)** checks before every `git commit`.

Covers:
- **SAST** — static analysis of JS/TS/Go/React code via Semgrep (OWASP Top 10 rules + Express misconfig rules)
- **SCA** — dependency vulnerability scanning via OSV-Scanner (pnpm) and govulncheck (Go)
- **Misconfig** — CORS, headers, auth bypass patterns

Supports **inline suppression** so developers can acknowledge known false positives with an explicit reason.

---

## Install — one command, everything is set up automatically

```bash
npm install -g sec-gate
```

That's it. This single command:

1. Installs the `sec-gate` CLI globally
2. Downloads the **osv-scanner** binary for your OS automatically
3. Installs **govulncheck** via `go install` (if Go is available on your machine)
4. **Installs the pre-commit hook** in your current git repo automatically

No extra steps. No separate tool installs. Your next `git commit` is already security-checked.

> **Note:** If you run `npm install -g sec-gate` from outside a git repo (e.g. your home directory), run `sec-gate install` once inside the repo afterwards.

---

## What happens on every `git commit`

```
git commit
    ↓
pre-commit hook fires automatically
    ↓
sec-gate scan --staged
    ↓
┌─────────────────────────────────────────────────────┐
│  SAST   — Semgrep scans staged .js/.ts/.go files    │
│           against OWASP Top 10 + Express rules      │
├─────────────────────────────────────────────────────┤
│  SCA    — OSV-Scanner checks pnpm-lock.yaml         │
│           govulncheck checks go.mod                 │
│           (only when those files are staged)        │
└─────────────────────────────────────────────────────┘
    ↓
Inline suppression tags filtered out
    ↓
Any findings? → commit BLOCKED, findings printed
No findings?  → commit proceeds
```

---

## Commands

```
sec-gate --help

  install   Installs the pre-commit hook in the current git repo
  scan      Runs SAST/SCA checks
              --staged   scan only staged files (used by pre-commit hook)
              (no flag)  scan all tracked files
```

---

## Inline suppression

If a finding is a known false positive, add a comment **near the flagged line**:

```js
// security-scan: disable rule-id: javascript.express.security.cors-misconfiguration.cors-misconfiguration reason: internal-only API, safe
app.use(cors({ origin: '*' }));
```

```go
// security-scan: disable rule-id: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command reason: input validated upstream
exec.Command(cmd)
```

Use `rule-id: *` to suppress **all** findings near that line:

```js
// security-scan: disable rule-id: * reason: test fixture only
doSomethingDangerous();
```

---

## Bypass (emergency only)

```bash
SEC_GATE_SKIP=1 git commit -m "emergency fix"
```

---

## Auto-setup for the whole team (optional but recommended)

Add this to your **project's** `package.json` so every developer gets the hook automatically when they run `npm install`:

```json
"scripts": {
  "prepare": "sec-gate install"
}
```

Then the workflow for any new developer joining the team is:

```bash
npm install -g sec-gate   # global tool install (once per machine)
npm install               # prepare script auto-installs the hook
```

---

## GitHub Actions — CI gate + PR comments

Copy `.github/workflows/security-gate.yml` from this repo into your project to get:
- Full scan on every pull request
- Automatic PR comment with findings output
- PR check blocked if any findings remain

---

## OWASP Top 10 (2021) coverage

| # | Category | How covered |
|---|---|---|
| A01 | Broken Access Control | Semgrep `owasp-top10` ruleset |
| A02 | Cryptographic Failures | Semgrep `owasp-top10` ruleset |
| A03 | Injection | Semgrep `owasp-top10` ruleset |
| A04 | Insecure Design | Semgrep `owasp-top10` ruleset |
| A05 | Security Misconfiguration | Semgrep `owasp-top10` + Express rules |
| A06 | Vulnerable Components | OSV-Scanner (pnpm) + govulncheck (Go) |
| A07 | Authentication Failures | Semgrep `owasp-top10` ruleset |
| A08 | Software Integrity Failures | Semgrep `owasp-top10` ruleset |
| A09 | Logging Failures | Semgrep `owasp-top10` ruleset |
| A10 | Server-Side Request Forgery | Semgrep `owasp-top10` ruleset |

---

## Go SCA note

`govulncheck` requires Go to be installed on the developer's machine. If Go is not present, Go SCA is skipped with a warning — the install never fails. To enable it:

```bash
# Install Go: https://go.dev/dl/
# Then re-run:
npm install -g sec-gate
```
