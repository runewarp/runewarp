# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

This repo is configured as a **single-context** repo.

- **`CONTEXT.md`** at the repo root for the project's domain language.
- **`docs/adr/`** at the repo root for architectural decisions relevant to the area being changed.
- Do not look for `CONTEXT-MAP.md` or per-context `src/<context>/docs/adr/` directories unless this repo is later reconfigured as multi-context.

If these files or directories do not exist yet, proceed silently. Don't flag their absence or suggest creating them upfront; producer skills can create them lazily when terms or decisions are actually resolved.

## File structure

Single-context repo:

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-event-sourced-orders.md
│   └── 0002-postgres-for-write-model.md
└── src/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, or a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use, or there's a real gap to capture later.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding it.

> _Contradicts ADR-0007 — but worth reopening because..._
