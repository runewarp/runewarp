# AGENTS.md

- Read `README.md` and the files in `docs/` before changing behavior.
- Keep documentation up to date with implementation. If behavior or design changes, update the relevant docs in the same change.
- Never push commits for the maintainer.
- Public traffic is TLS passthrough only. Do not terminate customer TLS on public hostnames.
- Server config is the routing authority. Clients do not register hostnames with the server.
- Prioritize privacy, speed, security, ease of use, and simple designs.
- Benchmark before adding complexity for performance. Prefer fewer allocations and proven wins.
- Never use `unsafe` Rust here. Avoid `unwrap` unless failure is impossible by construction.
- Prefer popular, well-maintained crates. Check current versions before adding dependencies, and do not add a dependency for something trivial.
- If a prompt is ambiguous and the default is not obvious, ask the user with clear options.
- Keep commit messages concise when asked to commit.
- All code must be formatted and linted with Clippy.
- Run relevant tests after changes. Run the full suite before any commit.
- Keep comments and doc-comments useful, detailed where needed, and not excessive.
- Always use TDD during implementation.
