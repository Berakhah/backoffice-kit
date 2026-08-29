# bok-core

Model gateway, data-boundary enforcement, and provenance primitives for the BackOffice Kit.

This is a **0.0.1 minimal slice**: `bok_core.boundary.sensitivity` and `bok_core.provenance`
(`Source`, `Claim`) only. The full surface (gateway, redact, egress, findings, obs) lands as
consumers need it — see `docs/INTERFACE-CONTRACT.md` for the authoritative interface and
`.superpowers/sdd/2026-08-27-bok-core-week0/progress.md` for what is deliberately deferred.

## Install

```bash
uv sync --all-groups
```

## Develop

```bash
uv run ruff check .
uv run mypy src
uv run pytest
```

## Licence

Apache-2.0. See `LICENSE` and `CONTRIBUTING.md`.
