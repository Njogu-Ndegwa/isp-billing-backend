# Claude Code Instructions

All project conventions, architecture notes, and reliability guardrails for this
repository live in **AGENTS.md** — the single source of truth shared across every
coding agent (Claude Code, Codex, Cursor). Always read and follow it.

In particular, before writing code that touches the database and also performs any
network/router I/O, follow the **Database Session Discipline** section in AGENTS.md
— it is the most common cause of production outages in this app.

AGENTS.md is imported below so it is always in context:

@AGENTS.md
