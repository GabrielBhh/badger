# badger — CLI tool project guide

badger is a Rust command-line tool (binary: `badger`) developed on Linux. This
file is the standing instruction set for Claude Code in this repo: how to talk
to me, how we build, and the exact process every change goes through. Follow it
exactly — it overrides default behavior.

---

## How to talk to me (Gabriel)

I have ADHD and I'm not a developer. Hard rules for every reply:

- **Be concise.** Short answers. No walls of text — I won't read them.
- **No code.** Don't show code, diffs, or file dumps unless I explicitly ask.
  Tell me what changed in plain words.
- **No developer jargon.** Explain in everyday language.
- **Lead with the answer / what I need to decide.** Skip the build-up.
- Just do the technical work; surface only the decisions that are mine.

---

## Coding posture (defaults for every task)

Bias toward caution; for trivial tasks (rename, one-line fix, obvious bug), use
judgment.

1. **Think before coding.** State assumptions. If uncertain, ask. If there are
   multiple interpretations, present them — don't silently pick one. Push back
   when a simpler approach exists.
2. **Simplicity first.** Minimum code that solves the problem. No features
   beyond what was asked. No abstractions for single-use code. No error handling
   for impossible scenarios. If it could be half the size, rewrite it.
3. **Surgical changes.** Touch only what you must. Don't "improve" adjacent
   code, comments, or formatting. Match existing style. Notice unrelated dead
   code → mention it, don't delete it. Every changed line traces to my request.
4. **Goal-driven.** Define verifiable success criteria *before* coding, then
   loop until they pass ("this exact input produces this exact output", "tests
   pass before and after").

---

## Test-Driven Development (default for every feature and change)

**Write the test before the code.** For any new feature, behavior change, or
refactor that alters observable behavior — failing test first, implementation
second.

Loop:
1. **Red.** Write a test describing the desired behavior. Run it. Confirm it
   fails for the *right* reason (missing implementation, not a typo).
2. **Green.** Write the minimum code to pass. Nothing more than the test needs.
3. **Refactor.** Clean up now that behavior is pinned. Re-run.
4. **Repeat** for the next slice.

Rules:
- The test goes in the **same commit** as the code it covers.
- No behavior change (formatting, docs, dependency bump)? Say so explicitly.
  Default is "test first".
- Hard to test directly (interactive TTY, spawning subprocesses, signals)?
  Extract a pure function / small module seam and test that. Drive the CLI
  end-to-end for the top few flows only (see E2E below).
- Name tests for behavior, not tickets: `test_rejects_duplicate_flag`, not
  `test_bug_123`.
- Multi-slice feature → test before each slice. Don't write all the code then
  backfill tests — that's not TDD.

---

## Bug-fix policy

A special case of TDD. **Failing regression test first, fix second, both in the
same commit.** The test must fail before the fix and pass after.

- Extract the bug's logic into a testable seam if needed — don't skip the test
  because "it's a CLI/argparse/runtime thing".
- Name the test so it documents the bug, and add a one-line comment at the top
  pointing to the symptom + root cause.
- Genuinely not unit-testable? Say so in the commit message and propose a manual
  reproduction check.

---

## The process every change goes through (strict)

This project uses **GitHub Issues**. Repo: **`GabrielBhh/badger`**. Default
is **branch-per-issue → PR → review → squash-merge**, never direct commits to
`main`.

1. **Open/pick the issue first**, before any work. Add priority + type labels.
   Every request and every bug becomes an issue.
2. `gh issue develop <N> --checkout` to create and switch to the branch.
3. **Implement** following the workflow: think → TDD (red/green/refactor) →
   clean up changed code → audit gate (below) → tests pass.
4. **Commit** with `Fixes #<N>` in the body (auto-closes the issue on merge).
   Commits atomic, buildable, focused; short "why" in the body.
5. **Audit gate over the full branch diff** before opening the PR (below).
6. `gh pr create --fill`.
7. Address any review findings; pushing more commits is fine.
8. `gh pr merge --squash --delete-branch`.
9. **Sync local with remote:** `git checkout main && git pull --prune origin main`.
   The `--prune` drops the stale remote branch ref the merge deleted.

Never `git push origin main` for issue-tracked work.

---

## Quality gates (run in this order, per change)

These are the checks that stand between me and a bad commit. Run the real tools —
never rely on reasoning alone for security or dependency scans.

### 1. Clean up the code you just changed
After a meaningful change, review the changed code for reuse, simplification,
efficiency, and over-engineering, and fix what you find. This is a *quality*
pass, not a bug hunt. Don't run it across massive multi-file changes or on code
you're still unsure about.

### 2. Static analysis + format (before every commit)
Run the analyzers for the language(s) in the diff and get to **zero findings**.
Auto-format first so formatting never shows up as a finding.

### 3. Dependency / CVE scan (when dependencies changed)
Run the ecosystem's vulnerability scanner on any dependency-file change. Treat a
CVE with severity ≥ 7.0 as a blocker.

### 4. Secret scan (git history)
Run `gitleaks detect --source . --no-banner` (or `trufflehog git file://.`)
before opening a PR. A detected secret is **critical even if already deleted
from the current files** — the commit is public the moment it was pushed. If a
real secret ever lands, rotate it; don't just delete it.

### 5. Convention compliance
Cross-check the change against this `CLAUDE.md` and any `CONTRIBUTING.md` /
`ARCHITECTURE.md` / ADRs in the repo. Cite the doc + line when flagging a
violation.

> If my personal Claude Code skills are installed on this machine, prefer them
> for gates 1–5: `/simplify` for gate 1 and `/code-audit staged` (then
> `/code-audit <branch>` before the PR) for gates 2–5. If they aren't installed,
> run the raw tools below directly — the gates are what matter, not the skill.

Severity handling: 🔴 fix, no exceptions. 🟡 fix unless justified. 🔵 fix if
cheap. Re-run until clean. **Never invoke two review passes back-to-back** — one
pass per change.

---

## Per-language tooling (use what matches the files in the diff)

Auto-detect the stack from the repo (lockfiles / manifests) and run that row.
Install the tool if it's missing and I've okayed it; otherwise note it was
skipped.

| Stack | Format | Lint / type | Test | CVE scan |
|---|---|---|---|---|
| **Python** | `ruff format` | `ruff check` + `mypy` | `pytest` | `pip-audit` |
| **Go** | `gofmt -w` | `go vet` + `golangci-lint run` + `gosec ./...` | `go test ./...` | `govulncheck ./...` |
| **Rust** | `cargo fmt` | `cargo clippy -- -D warnings` | `cargo test` | `cargo audit` |
| **Node / TS** | `prettier -w` | `eslint .` + `tsc --noEmit` | `vitest run` (or `jest`) | `npm audit` |

Shell scripts in the repo → `shellcheck`. Dockerfiles/IaC → `hadolint` / `trivy
config`. Secret scan (`gitleaks`) applies to every stack.

---

## Commit & PR hygiene

- Commits atomic + buildable, focused per change, short "why" in the body.
- **Never commit:** build artifacts, `node_modules/` / `target/` / `dist/` /
  `__pycache__/`, virtualenvs, `.env` files with real credentials, license keys,
  large binaries. Keep `.gitignore` honest.
- Tests pass locally before every push.
- Audit gate over the full branch diff before the PR.

---

## CLI-specific conventions

- **One job, done well.** A subcommand or flag earns its place; don't add
  options nobody asked for.
- **Exit codes are an API:** `0` success, non-zero on failure, and keep them
  stable — scripts depend on them. Document any code beyond `0/1`.
- **stdout is data, stderr is chatter.** Machine-readable output (or the thing
  the user piped for) goes to stdout; logs, progress, and errors go to stderr.
- **Respect pipes and redirection.** Don't assume a TTY; detect it before using
  color or interactive prompts. Honor `NO_COLOR`. Handle `SIGPIPE`/`SIGINT`
  cleanly (no ugly traceback on Ctrl-C or `| head`).
- **`--help` and `--version` always work**, even with bad config. Errors are
  short, plain, and actionable — say what to do next, not just what broke.
- **Config precedence, most-wins-last:** built-in defaults → config file →
  environment variables → command-line flags.
- **Read from stdin** when it makes sense (support `-` as "stdin"), so the tool
  composes in a pipeline.
- **No secrets in argv or logs** — process args are visible to other users via
  `ps`; take secrets from a file, env var, or prompt.
- **Reproducible builds / pinned dependencies** (lockfile committed), so the
  binary someone builds tomorrow matches today's.

---

## End-to-end tests (thin top layer only)

Unit + seam tests are the base of the pyramid. On top, keep **3–5 critical
happy-path flows** that drive the actual built binary: `--help` renders, the one
or two signature commands produce the expected stdout/exit code, a bad flag
fails with the right message. Run E2E **before a release**, not on every commit —
it must not slow the inner TDD loop. No `sleep`-based waits, no network, seeded
deterministic input.

---

## Conflict resolution

If anything here conflicts with a more specific project doc (`ARCHITECTURE.md`,
an ADR), the more specific doc wins. Otherwise this file is the source of truth.
