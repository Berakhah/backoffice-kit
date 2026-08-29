# BackOffice Kit

The shared substrate: two publishable packages plus the copier template that scaffolds the other four repos.
Week 0 · No accent of its own — it defines all four · Licence: Apache-2.0 (patent grant matters for security tooling)

**What it is:** `bok-core` (PyPI) — model gateway, quota governor, data-boundary enforcement, redaction, typed findings, provenance primitives, structured logging. `bok-ui` (npm) — design tokens, React component library, the provenance rail, chart primitives. `template/` — a copier template producing a repo that passes CI on first push with zero edits.

## Source of truth

- `../Starting_Documents/00-SHARED-FOUNDATION.md` — this repo **is** that document. Read it in full; it is the spec.
- The four consumer briefs (`01`–`04`) describe what will be built on top. Read them for the interface requirements they impose, not for their own scope.
- `docs/superpowers/specs/2026-08-27-backoffice-kit-design.md` — the approved design. It **amends `00` in several recorded places**; §1 is the decisions ledger and every amendment is argued there rather than assumed.
- `docs/INTERFACE-CONTRACT.md` **v0.2** — the authoritative symbol surface. If a symbol is not in it, it does not exist, and the task needing it is blocked on an amendment there, not on a local workaround.

The brief wins over anything summarised here, **except where the design records an amendment to it** — then the design wins and says why. This file exists so a fresh session cannot violate a hard rule by accident; where it and the design disagree, the design is newer.

> **Revision R1 (29 Aug 2026)** audited both implementation plans against all of the above. Five
> controls were untestable-as-written or absent, and the plans were corrected in place. If you are
> re-deriving any rule below from `00` alone, read the `R1:` notes in the plans first — several of
> them exist because the obvious reading of `00` produced a test that could not fail.

## Workflow

superpowers, in order: `brainstorming` → `using-git-worktrees` → `writing-plans` → `subagent-driven-development` → `test-driven-development` → `requesting-code-review` → `verification-before-completion`. TDD is RED-GREEN-REFACTOR, no exceptions.

## The constraint everything falls out of

**No local GPU, $0 budget.** All four consumer projects need inference. Free tiers change monthly, delete models without notice, mostly train on inputs, are sometimes non-commercial-only, and are not uniformly available by geography. Every architectural requirement below exists because of that.

## Never (each has a test proving it)

1. **No model name is ever hardcoded.** Selection lives in `models.yaml`, resolved at runtime through a lane abstraction (`extract-vision`, `judge`, `classify-cheap`, `local-fallback`). Code asks for a lane, never a model. (R1)
2. **A dead primary is never discovered mid-run by a 429 or a 404.** Startup capability probe pings every configured model, records what is alive, demotes dead entries down the fallback chain, caches with a TTL, and exposes the result as a provider health strip. (R2)
3. **Every capability has a deterministic implementation that carries the majority of the load;** the model is an escalation path. Rules before classifiers, OCR + layout before vision, DOM heuristics before visual grounding, exact-match graders before LLM judges. **There is no shared ≥70% threshold** — design §7 deletes it, because `00` §2.2 and §7 name two different denominators and the four consumers measure four incommensurable units. What is shared is `bok_core.testing.degraded`: a `blackout()` that patches the socket, and `assert_blackout_complete()`. Each repo declares and tests its own floor, in its own stated unit, and publishes it in `docs/methodology.md`. (R3)
4. **`CLIENT_CONFIDENTIAL` never reaches a free tier — hard fail, `SensitivityViolation`.** Every payload crossing into the gateway carries a `Sensitivity` label: `PUBLIC` and `SYNTHETIC` may go anywhere; `REDACTED` only with an explicit per-project opt-in; `CLIENT_CONFIDENTIAL` routes only to a fully local path, or to a provider marked `trains_on_data: false` **and** `commercial_use: true` **and** with a client-supplied paid key. Enforced in code, not in discipline. **Build this before anything that touches a document.** (R4)
5. **Redaction is verified, not hoped.** Rule-based detection (emails, phones, tax ids, bank/routing numbers, addresses, names via local NER), replacement with **HMAC-keyed** stable surrogates so structure survives, then **a verification pass that RE-RUNS EVERY DETECTOR over the output** and fails loudly if any fires. Untested redaction is worse than none — it manufactures false confidence in the boundary. Three R1 corrections are load-bearing here: verification that re-searches for strings it just replaced is a tautology and cannot fail; an unkeyed `sha256(id)[:8]` surrogate is brute-forceable for the identifier classes that matter; and the result object must never carry the identifiers it removed. The classes that are *not* detected are declared, in `COVERED`/`NOT_COVERED` and in `methodology.md` — an undetected class is a hole, and naming it is what separates a limitation from a lie.
6. **Quota fails closed — which means reserving BEFORE dispatch, not recording after.** Persistent per-provider buckets over **rolling** 60s/24h windows (a calendar-minute bucket permits double the ceiling across a minute boundary), one `BEGIN IMMEDIATE` spanning check-and-increment so two concurrent callers cannot both pass, exponential backoff with **full jitter, capped, and honouring `Retry-After`**, a priority-lane queue, and a hard daily ceiling. Quota consumed is displayed as a first-class metric — in a $0 build, quota *is* the cost column. (R5)
7. **Every model call is recorded:** prompt hash, model actually used, provider, latency, tokens, quota consumed, timestamp, response fingerprint, sensitivity label, lane. This ledger is what makes Ground Truth possible at all and what makes the other three products' provenance claims true rather than aspirational. (R7)
8. **No secrets in a repo, ever, including test fixtures.** `gitleaks` pre-commit and in CI.
9. **No AGPL dependency adopted silently.** MIT / Apache-2.0 / BSD / OFL only for anything vendored or redistributed. Flag any AGPL candidate explicitly and name the permissive alternative.
10. **`docker compose up` on a fresh machine with no manual steps beyond copying `.env.example`.**

## The `Claim` primitive — the thesis in code

Every number that reaches a user is a `Claim`, never a bare float.

```python
class Claim(BaseModel, Generic[T]):
    value: T
    source: Source              # file+line, URL+retrieved_at, model call id, or human
    method: Method              # DETERMINISTIC | MODEL | HUMAN | DERIVED
    confidence: float | None    # None for DETERMINISTIC; calibrated for MODEL
    observed_at: datetime
    parents: list[Claim] = []   # for DERIVED
    caveat: str | None = None   # scope limitation, in the source's own terms
```

Enforced by a validator on `Claim` itself, not by a helper a caller can route around:
- A `DERIVED` claim's confidence never exceeds the minimum of its parents'.
- A `MODEL` claim with `confidence is None` cannot render as a fact — the UI shows it as unverified.
- **`DERIVED` inherits unverified-ness.** `renders_as_fact()` is False if *any* ancestor is an uncalibrated `MODEL` claim. Without this, one `derive()` hop launders a 0.72 model guess into a fact — and R1 found exactly that in the worked example `00` §10.4 makes a definition-of-done item.
- `DETERMINISTIC` implies `confidence is None`. `Claim[Decimal]` serialises as a **string**, at every layer including the rail payload the UI consumes.
- `caveat` propagates to children. If a parent says "sample size 51", the child says it too — over branching chains at depth ≥ 5, not just linear ones.

`parents` is annotated `list[Claim]`, **bare**: a self-referencing parametrised field (`list[Claim[object]]`) raises `AttributeError: __pydantic_fields__` at `Claim[Decimal]` on pydantic 2.13. Verified, not inferred.

This makes "state your scope" structural rather than a habit anyone has to remember.

## Module layout

```
bok_core/
  gateway/     lanes.py  probe.py  router.py  governor.py  cache.py  ledger.py
  boundary/    sensitivity.py  redact.py  policy.py
  provenance/  claim.py  chain.py  render.py
  findings/    severity.py  finding.py  sarif.py
  obs/         logging.py  metrics.py
```

Route through a self-hosted **LiteLLM** proxy (MIT) or an equivalent thin adapter — one OpenAI-shaped interface, fallback chains, per-key budgets. Do **not** adopt a hosted gateway with a free tier of its own; that adds a second thing that can silently change.

Response cache is content-addressed — **provider + model + lane + normalised prompt + canonical params + response-schema fingerprint** — SQLite-backed (WAL), explicit TTL, LRU-bounded, with an invalidate command taking a pattern. Drop the provider and you erase `ground-truth` B8; drop the params and a temperature change is a hit; drop the schema and a reply validated against schema A is returned for schema B. On free tiers, cache hit rate is the difference between a demo that runs and one that 429s in front of a client. (R6)

**Order of operations in `router.call` is a security property, not a style choice.** Trust check → blackout check → **`policy.check()`** → `governor.reserve()` → dispatch under a timeout → backoff on 429 → validate the response against its schema → `ledger.record()` (**including cache hits**) → metrics. R1 found the boundary check sitting *below* the cache lookup, so a `CLIENT_CONFIDENTIAL` payload with a warm entry was served with no enforcement at all.

## `bok-ui` — design system

**Direction: editorial instrument.** A well-set audit report crossed with the density of a control panel. **Light mode is primary** — a deliberate inversion, because these deliverables get printed and emailed, and a dark-first product reads as a developer toy to a controller.

**Reject three looks explicitly** — they are what generated design converges on and every buyer here has seen all of them: warm-cream + serif + terracotta; near-black + single acid accent; broadsheet with hairlines and zero radius. If a screen could drop into any of the four products unchanged and still look right, it is too generic.

Tokens in OKLCH via Tailwind v4 `@theme`. Neutral ramp is a **warm graphite** — not blue-grey, not pure grey — paper `oklch(0.985 0.004 85)`, ink `oklch(0.22 0.012 85)`, twelve steps. One accent per product from a shared chroma: agent-perimeter amber `oklch(0.72 0.16 68)`, ledger-sense green `oklch(0.58 0.11 158)`, selector-drift indigo `oklch(0.55 0.14 268)`, ground-truth slate-blue `oklch(0.52 0.10 232)`.

**Severity and provenance state are never encoded in colour alone** — each carries a glyph and a text label. Two target markets are literally regulated for accessibility.

**Every semantic and accent colour exists twice, and the halves are not interchangeable.** The base token is fill, field and badge ground, held to 3:1; the `-ink` sibling is text, glyphs, meaning-bearing borders and **the focus ring**, held to 4.5:1. Setting `color:` or `outline:` from a base token is the mistake this split exists to prevent — it is how the focus ring shipped at 2.46:1 through an R1 pass that was looking straight at it. `agent-perimeter` amber is the sharpest case: `00` §8 fixes the value, it measures 2.46:1 on paper and falls outside sRGB, so it is a fill and nothing else (design §8.5). Ratios are measured through the real OKLCH → WCAG transform by `scripts/check-contrast.mjs`, never approximated as `L³`, and the gate runs before axe because axe only sees what a story renders.

Type, all OFL and **self-hosted** (no Google Fonts CDN call — a privacy and offline-demo liability): Newsreader for display/report headings, Geist Sans for UI, IBM Plex Mono for data and code. **Tabular numerals everywhere a number appears** — a column of figures that shifts as it updates is the fastest way to look amateur to a controller.

4px spacing base. Radius 6px controls / 2px data cells / 0 table rules. Three densities (`comfortable / compact / dense`), persisted per user, default `compact`.

### The provenance rail — the signature element

Any figure rendered through `<Claim>` carries a 1px dotted underline in the provenance state colour. Activating it (click, or `Cmd+.` while focused) opens a 380px right-hand panel rendering the claim's chain top to bottom as a vertical ledger: value, method glyph, source with a working link or file-and-line reference, confidence with its calibration basis, timestamp, and any inherited caveat verbatim. Parents nest. Rail slides in over 180ms, chain items stagger at 30ms, all disabled under `prefers-reduced-motion`.

It is not decoration — it is the demo. Click a number and the buyer watches the evidence unfold, after which every competitor's unsourced percentage looks like what it is.

### Components

`Claim`, `ProvenanceRail`, `SeverityBadge`, `FindingsTable` (virtualised, column-resizable, keyboard-navigable, CSV/JSON export), `EvidencePane`, `ConfidenceMeter` (greys out when uncalibrated), `QuotaStrip`, `RunTimeline`, `DiffView`, `EmptyState`, `ErrorState`, `Skeleton`. Charts via Recharts wrapped in shadcn chart primitives — no gradient fills, no 3D, nothing that would not survive being printed in greyscale.

### Quality floor, not negotiable

WCAG 2.2 AA verified by `axe-core` in CI. Full keyboard operation including a `cmdk` palette. Visible focus rings. Every screen has designed empty, loading (skeleton, never a spinner), error, and partial-failure states. Responsive to 375px. `prefers-reduced-motion` respected. **A print stylesheet for every report view.**

## The template

Copier, not a GitHub template repo — specifically because `copier update` re-applies template changes to already-scaffolded repos and a template repo cannot. Scaffolds: CI (lint, typecheck, test, coverage, axe, licence audit), release via semantic-release with trusted publishing, `.pre-commit-config.yaml` (ruff, mypy, gitleaks, prettier, eslint), `docker-compose.yml` (app + postgres + litellm + prometheus under an `obs` profile), multi-stage non-root Dockerfile, mkdocs-material docs to GitHub Pages, Apache-2.0, SECURITY.md, CONTRIBUTING.md, README with a scope statement in the first 200 words.

**`docs/methodology.md` is a required artifact in all four repos** — what was counted, who counted it, sample size, collection period, known limitations, for every number the product publishes. It is the cheapest competitive moat available.

## Stack

Python 3.12+, `uv`, `ruff`, `mypy --strict` on all of `bok-core`. TypeScript strict, no `any` without a justifying comment. `pytest` + `hypothesis` for property tests on anything doing arithmetic on money or parsing untrusted input. Coverage floor **85%** on `bok-core` — a test that asserts nothing is a lie with a green tick.

## Testing bar

Unit (no network, no model) · contract tests with recorded cassettes per provider, plus a nightly live smoke test allowed to fail CI but required to open an issue — that is how you learn a free model was deleted before a client does · degraded mode **per repo, in its own declared unit** (no shared threshold) plus the shared `assert_blackout_complete()` · boundary (`CLIENT_CONFIDENTIAL` raises on every free-tier route **including a warm cache**; redaction verification catches a **missed** detection, not a planted one) · golden-file diffs for reports and SARIF · Playwright E2E including keyboard-only paths · **axe in a real browser** — `vitest-axe` under jsdom silently skips `color-contrast`, so a jsdom-only sweep cannot evidence the WCAG claim · zero serious/critical.

**The meta-rule R1 exists to enforce: a test that does not fail when you break the thing is not evidence.** Before marking any control green, break it and watch the test go red. Five of them did not.

## Definition of done

Brief section 10, seven items — including a copier run that produces a repo passing CI on first push with zero edits, a Storybook on GitHub Pages showing every component in light, dark and all three densities with axe passing, and a worked provenance example with three levels of derivation and an inherited caveat.

## Before planning

**`00` §12's seven open decisions are answered.** Design §1.1 records all seven with their reasoning
— publish (not vendor); four independent CLIs (no `bok-cli`); week 0 ships and tests the **empty**
provider inventory; compose-only, no third-party data processor; `backoffice-kit` public from commit
one and the consumers public at first release; Apache-2.0 everywhere plus DCO; 35–40 h/week. **Do not
re-ask them.** If you want to reopen one, argue against the recorded reasoning in §1.1 rather than
treating it as unanswered.

What is genuinely still open, and is data entry rather than a decision: **`providers.yaml` is empty
and due before week 4.** The twelve-field checklist is `docs/providers.md`. One question decides
`ledger-sense` on its own — does any free-tier, vision-capable provider state *in writing* that it
does not train on inputs? *No* is a perfectly good answer, and the design already accommodates it
with no code change.
