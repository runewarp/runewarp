# Agents

- Read `README.md` and the files in `docs/` before changing behavior. In particular `docs/architecture.md`, `docs/protocol.md` and `docs/security.md`.
- Keep documentation up to date with implementation. If behavior or design changes, update the relevant docs in the same change.
- All documents (except for roadmap) should be evergreen and represent the current state of implementation, not planned state (unless otherwise mentioned).
- Prioritize privacy, speed, security, ease of use, and simple designs.
- Benchmark before adding complexity for performance. Prefer fewer allocations and proven wins.
- Never use `unsafe` Rust here. Avoid `unwrap` unless failure is impossible by construction.
- Prefer popular, well-maintained crates. Check current versions before adding dependencies, and do not add a dependency for something trivial.
- If a prompt is ambiguous and the default is not obvious, ask the user with clear options.
- Keep commit messages concise when asked to commit. Commit messages should mark related issues as "Closes #123" where relevant.
- All code must be formatted and linted with Clippy.
- Run relevant tests after changes. Run the full suite before any commit.
- Keep comments and doc-comments useful, detailed where needed, and not excessive.
- Always use TDD during implementation.
- When release workflows, changelog discipline, or maintainer release expectations change, update `docs/release-guide.md` in the same change.
- Keep shell scripts simple with consistent plain-text section headers and polished manual-run output.
- Any user facing changes should be added to the "Unreleased" section of `CHANGELOG.md` during implementation strictly following "Keep a Changelog" format.

## Agent skills

### Issue tracker

Issues are tracked in this repo's GitHub Issues via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the canonical triage labels `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

This repo uses a single-context layout rooted at `CONTEXT.md` and `docs/adr/`. See `docs/agents/domain.md`.
