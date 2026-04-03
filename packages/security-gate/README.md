# sec-gate

A pre-commit security gate that enforces **OWASP Top 10 (2021)** checks before every `git commit`.

Covers:
- **SAST** — static analysis of JS/TS/Go/React code via Semgrep (OWASP Top 10 rules + Express misconfig rules)
- **SCA** — dependency vulnerability scanning via OSV-Scanner (pnpm) and govulncheck (Go)
- **Misconfig** — CORS, headers, auth bypass patterns

Supports **inline suppression** so developers can acknowledge known false positives with an explicit reason.

---

## Getting started — developer setup

### Step 1 — Install the tool globally (once per machine)

```bash
npm install -g sec-gate
```

This single command installs the `sec-gate` CLI and automatically downloads **osv-scanner** and **govulncheck** for you. No separate tool installs needed.

> You only run this once per machine, not once per project.

---

### Step 2 — Connect it to your repo (once per cloned repo)

```bash
cd your-project      # go into the cloned repo root
sec-gate install     # writes the pre-commit hook into .git/hooks/
```

This tells Git to run `sec-gate scan` automatically before every commit in this repo.

> **You must run this in every repo you want protected.** The global install alone does not activate the hook anywhere — it just makes the `sec-gate` command available on your machine.

---

### Step 3 — Develop normally, commit as usual

```bash
git add src/services/payment.js src/routes/user.js
git commit -m "feat: add payment service"   # scan fires automatically here
```

No extra commands. The hook handles everything.

---

### Full example from scratch

```bash
# On a fresh machine or a fresh clone:
npm install -g sec-gate        # Step 1 — install tool globally (once per machine)
cd fmt-os                      # go into your project
sec-gate install               # Step 2 — hook up this repo (once per clone)

# Now develop as normal:
git add .
git commit -m "my changes"    # Step 3 — scan runs automatically here
```

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

To avoid teammates forgetting `sec-gate install`, add this to your **project's** `package.json`:

```json
"scripts": {
  "prepare": "sec-gate install"
}
```

Then the full onboarding flow for any new developer is just two commands:

```bash
npm install -g sec-gate   # Step 1 — install tool globally (once per machine)
npm install               # Step 2 — prepare script auto-runs sec-gate install
```

No need to remember `sec-gate install` separately — `npm install` handles it.

> Tip: document these two commands in your project's `CONTRIBUTING.md` so every new joiner knows the setup.

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
