# BackOffice Kit — Design

**Status:** approved (brainstorming, 27 August 2026)
**Scope:** week 0 — `bok-core` v0.1 + `template/`. `bok-ui` v0.1 deferred to week 3 (§2.3).
**Licence:** Apache-2.0 · **Repo visibility:** public from commit one (§1.4) · **No accent** — this repo defines all four.
**Sources of truth:** `../Starting_Documents/00-SHARED-FOUNDATION.md`, and the four approved consumer designs. Where this document and `00` disagree, the disagreement is recorded in §1 as a decision.

This repo **is** `00`. Sections 4, 5, 6 and 10 of that document are its spec. This design amends
`00` in six places, each recorded and argued rather than assumed.

---

## 1. Decisions ledger

### 1.1 `00` §12 — all seven, resolved

| # | Decision | Answer |
|---|---|---|
| Q1 | Publish or vendor? | **Publish.** `bok-core` → PyPI, `bok-ui` → npm, trusted publishing (OIDC). A release step exists and the plan accounts for it. |
| Q2 | Unified `bok` CLI vs four independent | **Four independent. No `bok-cli` package.** Reasons in §1.3 — the recorded downstream reason was unsound and is replaced. Copier asks *"does this repo ship a console entrypoint?"*, defaulting to **no**; only `agent-perimeter` answers yes. Docs unify at a landing page; binaries do not. |
| Q3 | Provider inventory | **Week 0 ships and tests the EMPTY inventory.** Every lane resolves to its deterministic fallback with zero eligible providers, and that is the first tested state. The nine-provider sweep is dated data entry due **before week 4** (`ledger-sense`, week 5, is the first blocked consumer). Checklist in §10. |
| Q4 | Supabase vs compose-only | **Compose-only, no third-party data processor.** Generalisable rule: *any plane that can hold `CLIENT_CONFIDENTIAL` is compose-only; Supabase is permitted only on `SYNTHETIC`/`PUBLIC` planes.* Template scaffolds two profiles (`CLIENT`/`DEMO`) **plus a `pg_dump` sidecar and a restore test that runs in CI.** |
| Q5 | Public from commit one vs at release | **Consumers: public at first release** (wk 4/12/20/26). **`backoffice-kit`: public from commit one** — its PyPI/npm release is week 0–1 regardless, and a `Claim` primitive has nothing scoopable. Resolves the 2–2 conflict across the four approved designs; see §1.4. |
| Q6 | Apache-2.0 vs AGPL for the scanner | **Apache-2.0 everywhere, plus DCO.** The substrate's licence is forced independently of the scanner's (§1.5). The relicensing reserve closes at the first external contribution, and the DCO says so honestly rather than pretending otherwise. |
| Q7 | Capacity | **35–40 h/week, full time.** Week 0 is ~38h of `bok-core` + template; `bok-ui` is ~20h and moves to week 3. |

### 1.2 The two challenges

| # | Challenge | Resolution |
|---|---|---|
| A | The 70% degraded-mode floor | **Not testable as stated. `bok-core` ships the harness; each repo asserts its own floor.** §7. `00` §2.2 and §7 use two different denominators for the same test. Deleted as a shared constant. |
| B | `bok-ui` week-0 scope | **Tokens land whole; components land lazily.** Nine of thirteen ship in v0.1; charts, `QuotaStrip`, `RunTimeline`, `DiffView`, two `EvidencePane` adapters and the `dense` mode defer to the phase that first demands them. §8. |

### 1.3 Why four independent CLIs — the recorded reason replaced

`agent-perimeter`'s spec justifies the decision as *"a command registry in `bok-core` would invert
the dependency direction."* That is a strawman: a unified CLI would be a fifth package depending
on all four, with `bok-core` a library underneath. Nothing inverts. The decision stands on three
other grounds:

1. **Dependency weight.** A security engineer installing `agent-perimeter` would transitively pull
   construction accounting rules, Playwright browser binaries, DuckDB and Prefect. B5 sellability
   dies on this alone.
2. **There is no unified CLI to build.** Per the four approved designs, only `agent-perimeter` ships
   a real CLI, because CI is its distribution channel. `ledger-sense`'s buyer entrypoint is the web
   UI, `selector-drift`'s is the Prefect scheduler, `ground-truth`'s is a published static site. A
   `bok` command would front one CLI and three `python -m` dev entrypoints — a platform veneer over
   something `ground-truth` §4 explicitly forbids being a platform.
3. **The one real cross-product flow does not want a CLI.** `ground-truth` consumes `ledger-sense`'s
   golden set and returns calibration curves; `selector-drift` emits `Finding`s through the shared
   SARIF emitter. All of it composes at the **data** layer. Nothing shells out.

### 1.4 Q5 — resolving the 2–2 conflict

`agent-perimeter` and `selector-drift` answered *public at first release*; `ledger-sense` and
`ground-truth` answered *public from commit one*. The conflict is real and resolves as follows.

**`ground-truth`'s argument is stronger than `selector-drift`'s rebuttal recognised.** The rebuttal
was *"flipping public preserves full git history, so timestamps stay verifiable."* True but
insufficient: commit timestamps are author-controlled (`GIT_COMMITTER_DATE` is settable, history is
rewritable), so a sceptic auditing a repo that was private during the labelling period cannot
distinguish a genuine history from a fabricated one. For a project whose known weakness is
single-annotator ground truth (`04` B1), *"trust me, the timestamps are real"* is the move this
programme exists to reject.

**The fix is a hash commitment, not repo visibility.** `ground-truth` already builds a
hash-publication mechanism for its private split (`04` B5). Pointing it at `docs/rubric.md` — an
OpenTimestamps commitment, free, no account, one command, the `.ots` file committed alongside — is
*stronger* evidence than a public repo. A public repo proves a push date; OTS proves the **content**
existed at that date, which is what the claim actually needs.

**`ledger-sense`'s own reason argues against its own answer.** It said public *costs* nothing, not
that public is *required*, while its risk register demands no client data or partner-identifying
detail is ever committed. A leaked commit in a private repo is recoverable; in a public one it is
indexed forever. Public-at-release is strictly safer for the repo holding client financial documents.

**Carry-back:** `ground-truth`'s spec adds the OTS commitment on the rubric; `ledger-sense`'s
`00` §12 Q5 row is amended to *public at first release*.

### 1.5 Why Apache-2.0 is forced here regardless of the scanner

`bok-core` and `bok-ui` are libraries four separate repos import. AGPL on a library makes every
consumer AGPL. An AGPL `agent-perimeter` would therefore be an AGPL product built on an Apache
substrate — and the strongest argument for AGPL (protecting a hosted version) is already dead,
because hosted is an explicit v1 non-goal there. Separately, `ledger-sense` ships CI that fails the
build on AGPL dependencies; shipping an AGPL product behind an AGPL deny-list is a contradiction to
explain in every sales call. The patent grant matters for security tooling.

**DCO over CLA.** A CLA preserves the relicensing option at the cost of measurably suppressing
drive-by contributions to a young project. The DCO is honest: the reserve closes at the first
external contribution, and that is stated in `CONTRIBUTING.md` rather than discovered later.

---

## 2. What week 0 ships

### 2.1 Artifacts

| Artifact | Registry | Week |
|---|---|---|
| `bok-core` v0.1.0 | PyPI, trusted publishing | 0 |
| `template/` (copier) | this repo | 0 |
| `bok-ui` v0.1.0 | npm, trusted publishing | **3** (§2.3) |

### 2.2 Build order — non-negotiable

```
1. boundary/sensitivity.py      Sensitivity · SensitivityViolation · Labelled[T] · Trust
2. provenance/  claim.py · chain.py · render.py
3. boundary/    policy.py · redact.py · fingerprint.py · egress.py
4. gateway/     lanes · probe · router · governor · cache · ledger
5. findings/    severity · finding · sarif
6. obs/         logging · metrics
7. template/    CI · compose · release · docs scaffolding
8. examples/    worked provenance chain
9. release      PyPI trusted publishing
```

**All nine steps are week 0.** `bok-ui` appears nowhere in this list — it is a separate week-3
sequence (§8), with its own build order: tokens and a11y contract → print sheet → `Claim` +
`ProvenanceRail` → the remaining seven components → Storybook.

`boundary/sensitivity.py` is task one of the whole programme. B2 states that at 2am in week 11 a real
client invoice gets pasted into a test script and the code has to stop it — so the type that does the
stopping exists before anything it could guard.

`provenance/claim.py` precedes the rest of `boundary/` for one reason: `policy.py`'s capability
matrix stores `Claim`s, not bools (§4.4). Nothing in `provenance/` depends on `boundary/`, so there
is no cycle. **The boundary's enforcing type still lands before the gateway, which is what the
constraint requires.**

### 2.3 Why `bok-ui` moves to week 3

Honest estimate at 35–40 h/week:

| Component | Hours |
|---|---|
| `boundary/` + `provenance/` | ~10 |
| `gateway/` (probe, router, governor, cache, ledger) | ~12 |
| `findings/` + `obs/` | ~4 |
| template, CI, trusted publishing | ~8 |
| `examples/` + docs | ~4 |
| **`bok-core` + template subtotal** | **~38** |
| `bok-ui`: tokens + 9 components + Storybook + axe | ~20 |
| **Total if week 0 ships everything** | **~58** |

`00` B5 says the 26-week timeline assumes a rate reality will not honour, and instructs that calendar
assumptions be corrected rather than silently slipped. This is that correction.

**The split is free, not a compromise.** `agent-perimeter` does not touch `bok-ui` until **week 4**;
weeks 1–3 are entirely Python, and its print-critical screen 6 is built in week 3 as server-rendered
HTML through `report/html.py`, deliberately independent of Next.js and of `bok-ui`. So `bok-ui`'s
real deadline is end of week 3. Weeks 1–3 are unblocked on schedule either way.

**Amends `00` §10.1 and §10.3** — both name `bok-ui` and its Storybook as week-0 done criteria.

---

## 3. The boundary

### 3.1 The correction

`00` §4 models the boundary as **one axis** (`Sensitivity`) checked at **one point** (gateway entry).
That satisfies none of the four consumers completely, and the gap is where each would grow its own
workaround.

### 3.2 Three orthogonal axes

| Axis | Question it answers | Type | Demanded by |
|---|---|---|---|
| `Sensitivity` | Who may **receive** this payload? | `PUBLIC \| SYNTHETIC \| REDACTED \| CLIENT_CONFIDENTIAL` | `00` R4; `ledger-sense`, `selector-drift` |
| `commercial` | Is this call a **licence breach**? | `CallContext(commercial: bool)` | `ground-truth` §11.5 |
| `Trust` | Is this content **hostile**? | `TRUSTED \| UNTRUSTED` | `agent-perimeter` §8.4, B6 |

The second and third are not implied by the first. A `SYNTHETIC` payload sent for billable triage
work to a `commercial_use: false` provider is a breach with no confidentiality issue whatsoever
(`00` B3). A `PUBLIC` MCP tool description is attacker-authored: public *and* hostile.

**`trust=UNTRUSTED` structurally forces `response_schema` and `tools_disabled` at the router** — a
refusal to dispatch without them, not a default and not a prompt instruction. `agent-perimeter` §8.4
states the requirement exactly: *"otherwise B6's mitigation is a prompt, and a prompt is not a
security boundary."*

### 3.3 Two enforcement points

```
bok_core/boundary/
  sensitivity.py   Sensitivity · SensitivityViolation · Labelled[T] · Trust
  policy.py        ProviderCapability matrix (Claim-backed) · eligibility predicates
  redact.py        detect -> stable surrogate -> verify
  fingerprint.py   SecretFingerprint (non-retaining constructor)
  egress.py        guard_write() -- the second enforcement point
```

**Point 1 — gateway entry.** `policy.check(labelled, context, provider)` raises or returns.

**Point 2 — storage and egress.** `egress.guard_write(path, payload, plane)`. One guard function.
Refuses `CLIENT_CONFIDENTIAL` to a plane not declared `CLIENT`; refuses any payload whose redaction
verification did not pass.

`selector-drift`'s entire boundary requirement is at the write path — capture, redact, verify, store,
and quarantine the run if verification fails, because *"un-redacted evidence is never written to be
cleaned up later; there is no later."* `agent-perimeter`'s is *"no raw secret is ever persisted,
logged or emitted."* Neither is a gateway concern. Without `egress.py` both grow bespoke guards and
the boundary stops being shared.

### 3.4 `Labelled[T]` wraps bytes and file handles

Not only prompts (`ledger-sense` §4.1.4). The label attaches where a file is **opened**; if it
attaches at gateway entry, the leak has already happened upstream.

### 3.5 `fingerprint.py`

`SecretFingerprint(sha256, entropy, prefix, last4, location)` — the constructor accepts the raw
value and **structurally** guarantees it is never retained: no attribute holds it, `__repr__` and
`__str__` cannot expose it, and it is unreachable after construction. `redact.py` redacts; nothing
in `00` §4 fingerprints. `agent-perimeter` needs it for its constraint 3 (never validate a discovered
secret); `ledger-sense` needs the identical primitive.

### 3.6 Redaction

Per `00` §4.2, unchanged in substance: rule-based detection (emails, phones, tax ids, bank/routing
numbers, addresses, names via local NER) → stable surrogates preserving structure → **a verification
pass that re-scans the output and fails loudly if any original identifier string survives.**

Addition: verification failure returns a typed result the caller must handle, never a bool that can
be ignored. `egress.guard_write` refuses anything whose verification did not pass, which makes
"forgot to check the return value" unrepresentable at the write path.

---

## 4. Provenance

### 4.1 `Claim`

```python
class Claim(BaseModel, Generic[T]):
    value: T
    source: Source                    # 7-variant discriminated union
    method: Method                    # DETERMINISTIC | MODEL | HUMAN | DERIVED
    derivation: Derivation | None     # SCHEMA | DESCRIPTION | PROBE | ARTIFACT
    confidence: float | None
    calibration: Calibration | None   # {state, basis, curve_id, n}
    observed_at: datetime
    parents: list[Claim] = []
    caveat: str | None = None
```

Two fields beyond `00` §4.1:

**`derivation`** (`agent-perimeter` §8.1). A capability edge inferred from a JSON schema, from a
description, from a live probe, or from a static artifact is `DETERMINISTIC` in all four cases with
materially different trustworthiness. B9 requires edges to render differently by derivation; without
this field the distinction lives in product code and diverges across repos.

**`calibration`** (`agent-perimeter` §8.5, `ledger-sense` §4.1.5, `00` B10). An object
`{state, basis, curve_id, n}`, never a float. *"Calibrated on synthetic corpus only"* must render
differently from *"calibrated on 400 real labelled fields"*, and `ConfidenceMeter` cannot make that
distinction from a number.

### 4.2 `Source` variants

| Variant | Fields | Consumer |
|---|---|---|
| `FileSource` | `path, line` | `agent-perimeter` — config and repo findings |
| `DocumentSource` | `path, page, bbox` | `ledger-sense` — boxes the field on the document |
| `UrlSource` | `url, retrieved_at` | `agent-perimeter` registry/census; policy terms citations |
| `ModelSource` | `ledger_call_id` | all four — **a foreign key into `gateway/ledger.py`** |
| `HumanSource` | `who, at` | `ledger-sense` review accept; `selector-drift` promote decision |
| `RuleSource` | `authority, citation, confirmed_by, confirmed_at` | `ledger-sense` — `rules/registry.py` refuses registration without it |
| `DomSource` | `snapshot_id, selector, rung` | `selector-drift` heal evidence; `03` B5 replay |

`FileSource` and `DocumentSource` stay **separate types**, not one type with optional `page`/`bbox`.
Merged, "no bbox because this is source code" is indistinguishable from "no bbox because extraction
failed" — and the second must be visible.

### 4.3 Invariants, all tested

1. A `DERIVED` claim's confidence never exceeds the minimum of its parents'.
2. A `MODEL` claim with `confidence is None` cannot render as a fact.
3. **`DETERMINISTIC` implies `confidence is None`.** `selector-drift` §3.5 depends on this: every
   extracted value is deterministic, therefore uncalibrated, therefore honestly rendered.
4. `caveat` propagates to children, verbatim.
5. **`Claim[Decimal]` serialises `value` as a string, never a float** (`ledger-sense` §4.1.2).
   `model_dump_json` is where the no-floats rule dies quietly.
6. **Invariants 1 and 4 hold at depth ≥ 5**, verified with `hypothesis` over generated chains.
   `00` §10.4 asks the worked example for three levels; real chains are deeper. `ground-truth` runs
   item verdict → field accuracy → calibration curve → threshold → triage recommendation, and the
   caveat *"n=180, private split"* must survive to the last hop. `ledger-sense` runs field → line
   total → G702 summary → validation verdict.

### 4.4 Policy claims are `Claim`s

`ProviderCapability.trains_on_data` is `Claim[bool]` with `method=HUMAN`, a `HumanSource` for who
checked, and a `UrlSource` parent carrying the terms URL, the retrieval date and the quoted
sentence. A refusal then **cites its own evidence**:

```
SensitivityViolation: REDACTED refused to provider 'X'.
  trains_on_data = True
  basis: https://... retrieved 2026-09-02
  quote: "..."
```

This is the substrate's thesis applied to itself. It costs nothing — the primitive exists — and it is
the answer when a client's counsel asks how the check was performed.

---

## 5. Gateway

```
gateway/
  lanes.py     Lane = capability predicate; resolve() derives the eligible set from policy
  probe.py     startup capability probe, TTL cache, health-strip payload
  router.py    fallback chain; enforced response_schema + tools_disabled; failover switch
  governor.py  token buckets (RPM/TPM/RPD); backoff with full jitter; daily ceiling; remaining()
  cache.py     content-addressed, SQLite, TTL, invalidate; per-call disable
  ledger.py    queryable table, stable call_id
```

Six requirements beyond `00` §4.

**G1 — a lane is a capability predicate, never a provider list.**

```yaml
lanes:
  judge:
    requires: {structured_output: true, tools_deniable: true}
    max_sensitivity: PUBLIC
    fallback: local-fallback
```

The eligible provider set is **derived** from the inventory. A different-than-expected inventory
answer edits one data row and the lane re-resolves; no code changes. This is the property that makes
§10's unknown answers survivable.

**G2 — zero eligible providers is a tested first-class state.** `lanes.resolve()` with an empty
eligible set returns the deterministic fallback handle, and the health strip reports *which
requirement no provider satisfied*. `ledger-sense` already banks on this outcome: if no free vision
tier states in writing that it does not train on inputs, its model lane is `SYNTHETIC`-only
permanently and *"the design accommodates it with no change."* **`models.yaml` fails validation if
any lane lacks a deterministic fallback.**

**G3 — `ledger.py` is a queryable table, not structured logs.** `ground-truth`'s
`outputs.ledger_call_id` is a **foreign key into it**. Columns: `call_id` (stable), `model_id`,
`provider`, `lane`, `sensitivity`, `prompt_hash`, `response_fingerprint`, `latency_ms`, `tokens`,
`quota_consumed`, `observed_at`. Exposed as a documented table plus a read API. Without this, B6
fingerprint tracking and B8 provider attribution are both impossible, and `ground-truth`'s regression
module has no substrate.

**G4 — `router.call(..., cache=DISABLED)`.** Inverts R6. A cache hit returns an identical response
for replicates 2–5, fabricating zero variance and destroying `ground-truth` B7's entire measurement.

**G5 — `router.call(..., failover=DISABLED)`.** *Identified in this session; in no prior document.*
**`ground-truth` inverts the lane abstraction.** For the other three, a lane means "give me anything
satisfying this requirement." For `ground-truth`, model identity **is the variable under study** — a
slot pins one model. A silent failover would attribute model A's output to model B and corrupt the
entire benchmark, invisibly.

**G6 — `governor.remaining(provider) -> Quota` is a public query.** `ground-truth`'s scheduler asks
before dispatching each sweep batch; a 9,000-call sweep that 429s partway produces a biased partial
result, which is worse than no result.

---

## 6. Findings and observability

`findings/` — shared severity ladder, typed `Finding` (Pydantic v2), SARIF 2.1.0 emitter.

**The emitter treats `logicalLocations`, `partialFingerprints` and `properties` as first-class**, not
only file-and-line (`agent-perimeter` §8.3, B7). SARIF was designed for static analysis of source
files; a runtime finding about a live MCP server has no natural `physicalLocation`. Validated against
the 2.1.0 schema in CI.

A non-obvious second consumer: `selector-drift` emits **data-quality violations** (row counts, null
rates, schema drift, distribution shift) as `Finding`s on the shared ladder through the same emitter.
So neither the ladder nor the emitter may assume a scanner's vocabulary.

`obs/` — `structlog` JSON with correlation ids; `prometheus-client` metrics scraped by the compose
`obs` profile. **Quota consumed is a first-class metric** — in a $0 build, quota is the cost column.

---

## 7. Degraded mode — what `bok-core` owns

### 7.1 Why the 70% floor is not testable as stated

**The document contradicts itself about what it measures.** `00` §2.2 R3: *"at least 70% of each
product's **findings** still generate."* `00` §7: *"≥70% of the **finding classes**."* Those are
different denominators; `CLAUDE.md` restates the first. One is wrong and nothing indicates which.

**The four have four incommensurable units.** `agent-perimeter` counts check classes (28/29 = 96.6%
against its own 90% floor). `ledger-sense`'s is a binary end-to-end assertion — deterministic
extraction and validation of digital PDFs completes — with no percentage anywhere. `selector-drift`
counts **mutation** classes healed by rungs 1–4. `ground-truth` is vacuous: phase 2 needs no
providers by construction, so it scores 100% and measures nothing. A shared threshold over four
different denominators means four different things and compares none of them.

**Class-count is gameable in the wrong direction.** Splitting one deterministic check into three
improves the ratio with no new capability; shipping a valuable model escalation makes it worse. A
metric improved by not shipping features is a bad metric.

**Class-count is not what a buyer cares about.** "What fraction of check types still run" and "what
fraction of findings on a real target still appear" can differ by an order of magnitude either way.

### 7.2 What ships instead

`bok_core.testing.degraded` provides:

1. **A blackout fixture.** Makes every lane raise `ProvidersUnavailable`. The genuinely shared and
   genuinely hard part: a complete blackout must defeat the response cache, the probe TTL cache, the
   fallback chain, and any `local-fallback` lane that is not actually deterministic.
2. **`assert_blackout_complete()`** — no code path reaches a provider under blackout. **This is the
   valuable shared test.** Identical in all four, boundary-adjacent, and it protects B2 and B4. The
   percentage is decoration by comparison.
3. **A capability-census helper.** Each repo declares its inventory in its own unit with
   `model_dependent: bool`; the helper computes the ratio and emits it into `docs/methodology.md` in
   a uniform shape. **It reports. It never asserts a threshold.**

Each repo asserts its own floor, in its own unit, with the unit named in the assertion message:

| Repo | Floor | Unit |
|---|---|---|
| `agent-perimeter` | ≥90% | check classes |
| `ledger-sense` | binary | deterministic extraction + validation of digital PDFs completes end to end |
| `selector-drift` | majority | mutation classes healed by rungs 1–4 |
| `ground-truth` | **zero** | phase 2 makes no gateway calls at all — an AST assertion, strictly stronger than any percentage |

**Amends `00` §7 and §10.5.** "≥70%" is deleted as a shared constant and replaced with: *every repo
declares a degraded-mode floor in its own stated unit, publishes it in `docs/methodology.md`, and
tests it.*

---

## 8. `bok-ui` v0.1 — week 3

### 8.1 What lands whole, and why

`bok-ui` publishes to npm, which creates a decisive asymmetry: **adding a component later is a minor
version bump; changing a token later is a breaking visual change across four repos.** Tokens whole,
components lazy.

**Whole in v0.1:**

- **Token layer.** OKLCH warm-graphite ramp (paper `oklch(0.985 0.004 85)`, ink
  `oklch(0.22 0.012 85)`, twelve steps); four product accents; `critical/high/medium/low/info` and
  `verified/modelled/unverified` semantic scales; Newsreader / Geist Sans / IBM Plex Mono,
  self-hosted, tabular numerals wherever a number appears; 4px base; radius 6/2/0; **the density
  mechanism** as a custom-property scale, shipping `comfortable` and `compact`.
- **A11y contract.** Visible focus rings; **glyph + text label on every semantic colour** — two
  target markets are regulated for accessibility; `prefers-reduced-motion` honoured throughout.
- **Print stylesheet as standalone CSS.** Its first consumer is `agent-perimeter`'s
  `report/html.py` — server-rendered Python HTML that never imports React. A print sheet existing
  only as React component styles would have no consumer in weeks 1–4.
- **`Claim` + `ProvenanceRail`.** `00` §1 requires the rail identical in all four; landing it
  per-product guarantees divergence, and it constrains `Claim`'s serialisation shape in `bok-core`.

**Nine components:** `Claim`, `ProvenanceRail`, `SeverityBadge`, `FindingsTable`,
`EvidencePane` (text/code adapter only), `ConfidenceMeter`, `EmptyState`, `ErrorState`, `Skeleton`.

### 8.2 Deferred, each to the phase that first demands it

| Deferred | First real consumer |
|---|---|
| **All chart primitives** (Recharts + shadcn wrappers) | **Week 13** — `selector-drift` distribution plots. `agent-perimeter`'s capability graph is force-directed, not a chart. **Weeks 1–4 chart nothing at all.** The largest single deferral |
| `QuotaStrip` | Week 5 — `agent-perimeter`'s model lane is escalation-only; the strip would have almost nothing to display |
| `RunTimeline` | Week 13 — `agent-perimeter`'s live scan groups by phase, not by time |
| `DiffView` | Week 13 — drift is an `agent-perimeter` v2 surface, stubbed in v1 |
| `EvidencePane` DOM adapter | Week 13 |
| `EvidencePane` document-image + bbox adapter | Week 5 |
| `dense` density mode | Week 5 — nothing in weeks 1–4 exercises it; the **mechanism** ships in v0.1 |

The deferral schedule is published in the repo with the phase and the consumer named. **Amends
`00` §10.3**: the Storybook covers the v0.1 component list.

### 8.3 Component contracts `00` §5.4 does not describe

Behaviours extracted from the four approved designs that the shared foundation's component list does
not capture:

| Contract | Consumers |
|---|---|
| **`EmptyState` takes a scope object and renders a denominator.** `agent-perimeter`: *"No findings for the checks that ran"* + skipped count and why. `selector-drift`: *"Nothing quarantined"* + the count that passed. `ground-truth`: what has **not** been measured, never implying zero. Same rule three times, so it is an API, not copy guidance | AP · SD · GT |
| **`EvidencePane` takes a content adapter.** §5.4 names code, DOM and document — but they are three different coordinate systems: character offsets, node paths, page+bbox. The adapter interface is designed in v0.1; only the first adapter ships | AP · SD · LS |
| **`ConfidenceMeter` takes a `Calibration` object**, never a float | LS §4.1.5 |
| **A roving-tabindex list-navigation primitive, separate from the table.** `ledger-sense`'s review queue is a *queue* — `J`/`K`/`Enter`/`E`/`R`, fifty exceptions cleared without a mouse. Not a `FindingsTable`. The shared part is the keyboard primitive | LS |
| **`DiffView` is word-level, not line-level** — three consumers, same requirement, unstated in §5.4 | AP drift · LS bank-detail change · SD DOM diff |

Two further behaviours are **deferred with their component but recorded now** so they are not
rediscovered in week 21:

- **Interval rendering with an overlap verdict.** `ground-truth` §7.1: a confidence interval rendered
  *as an interval*, and where two overlap the interface states in words *"not distinguishable at this
  sample size."* `ground-truth` calls this single behaviour "the entire brand." Nothing in `00` §5.4
  covers it. Lands with the chart primitives in week 13.
- **Alerts state their test.** `ground-truth` §13.2 (the test used and the p-value or interval, never
  a bare red arrow) and `selector-drift` §8.5 (the threshold **and why that threshold**, never a bare
  red badge). A shared `Threshold`/`Alert` contract, deferred with charts.

### 8.4 Quality floor

WCAG 2.2 AA via `axe-core` in CI, zero serious or critical. Full keyboard operation including a
`cmdk` palette. Designed empty, loading (skeleton, never a spinner), error and partial-failure states.
Responsive to 375px. Storybook on GitHub Pages showing every v0.1 component in light, dark and both
shipped densities, with axe passing.

---

## 9. The template

Copier, not a GitHub template repo — `copier update` re-applies template changes to already-scaffolded
repos and a template repo cannot.

**Scaffolds:**

- `.github/workflows/ci.yml` — lint (`ruff`), typecheck (`mypy --strict`), test, coverage, axe,
  **licence audit**.
- `.github/workflows/release.yml` — semantic-release, trusted publishing.
- `.pre-commit-config.yaml` — ruff, mypy, `gitleaks`, prettier, eslint.
- `docker-compose.yml` — **two profiles**: `CLIENT` (app + compose-only postgres + litellm, no
  third-party processor ever) and `DEMO` (synthetic data only, hostable anywhere), plus `prometheus`
  under an `obs` profile. Plus a **`pg_dump` sidecar and a restore test that runs in CI** — an
  untested backup is the same species of lie as untested redaction, and compose-only means the
  operator is the solo author (B5, B7).
- `Dockerfile` — multi-stage, non-root, distroless-ish final.
- `docs/` — mkdocs-material to GitHub Pages; **`methodology.md` with its four forced questions**;
  `security.md`.
- `LICENSE` Apache-2.0, `SECURITY.md`, `CONTRIBUTING.md` **with the DCO**, `README.md` with a scope
  statement in the first 200 words.

**Two copier questions that fall out of §1:**

1. *"Does this repo ship a console entrypoint?"* — default **no**. Only `agent-perimeter` answers yes;
   the other three get `python -m <module>` and no `[project.scripts]`.
2. *"Does this repo hold `CLIENT_CONFIDENTIAL` data?"* — selects whether the `CLIENT` compose profile
   and the backup sidecar are scaffolded.

**The licence audit checks the native and system layer, not only Python metadata.** `ledger-sense`
established this: a metadata-only scan waves through exactly the AGPL cases that matter (PyMuPDF, and
Ghostscript-shaped system dependencies). The job lands before any dependency is installed — its value
is preventing adoption, not documenting it.

---

## 10. Provider inventory

### 10.1 The record — 12 fields per provider

Providers: **Google AI Studio, Groq, Cerebras, OpenRouter (`:free`), Mistral, Cloudflare Workers AI,
SambaNova, GitHub Models, NVIDIA NIM.** Record **Cohere trial as excluded, with its citation** — an
exclusion nobody can check is not an exclusion (`00` B3).

| # | Field | Where the answer lives | Trap |
|---|---|---|---|
| 1 | `reachable_from_location` | A real API call **from the machine that will run this**; record status + timestamp | B1: geofences are silent and marketing pages never mention them |
| 2 | `card_required` | The signup flow, by completing it | A free tier behind a card is a different product |
| 3 | `trains_on_data` | **The exact sentence, quoted verbatim, + URL + retrieval date** | Free and paid tiers differ. The free-tier clause frequently lives in a *separate* "additional terms" / "unpaid services" document, not the main ToS. **The field that ends the business if wrong** |
| 4 | `commercial_use` | Quoted sentence + URL + date, **on the free tier specifically** | Independent of sensitivity — `ground-truth` §11.5 |
| 5 | `limits` `{rpm,tpm,rpd}` | **The live console for the key-owning project**, screenshotted and dated | Google explicitly declines to publish a stable universal quota; the docs page is not the answer |
| 6 | `structured_output` | A real call returning schema-conformant output, **plus a call with an adversarial prompt that fails to break the schema** | `agent-perimeter` B6 — decisive for the judge lane at any quota |
| 7 | `tools_deniable` | Can a call be made with tools structurally absent? | A provider with server-side tools is disqualified from the judge lane |
| 8 | `vision` | Free tier specifically | `ledger-sense`'s decisive question |
| 9 | `fingerprint_exposed` | Does the response carry model-version / system-fingerprint metadata? | `ground-truth` B6 — often absent on free tiers, and it must **say so** rather than imply it can pin a version it cannot |
| 10 | `live_model_ids` | Current free catalogue, snapshot + date | The field that rots — cf. the 31 May 2026 catalogue collapse |
| 11 | `terms_url` + `terms_retrieved_at` | — | — |
| 12 | **`terms_sha256`** | Hash of the terms page at retrieval | Lets the nightly job detect a **silent terms change** — B4's shape applied to legal terms rather than model availability |

Recorded in `providers.yaml` (versioned, in-repo) and rendered into `docs/methodology.md`. Fields 3
and 4 are stored as `Claim`s per §4.4.

### 10.2 Surviving an unexpected answer

Seven properties, of which G1 and G2 (§5) are the load-bearing pair:

1. Lanes are capability predicates; the eligible set derives from the inventory (G1).
2. `models.yaml` fails validation if any lane lacks a deterministic fallback.
3. **Zero eligible providers is a tested first-class state** (G2).
4. Capability claims carry their evidence and refusals cite it (§4.4).
5. **Fail closed on unknown.** `trains_on_data: null` behaves as `true`; an unverified provider is
   ineligible above `PUBLIC`/`SYNTHETIC`.
6. **Staleness nags.** Entries carry `verified_at`; past threshold the health strip warns and
   `REDACTED` routing blocks. `00` §11 says "re-verify on the day you build" — which only happens if
   something nags.
7. **Terms-drift detection.** The nightly job that live-smoke-tests providers also diffs
   `terms_sha256` and opens an issue on change.

**Week 0 ships and tests the empty inventory**, so the gateway's first exercised state is the worst
one. A disappointing inventory result in week 4 is then a data change, never a code change.

---

## 11. Testing and definition of done

### 11.1 `00` §10, seven items, mapped

| # | DoD item | Where it is proven | Amended? |
|---|---|---|---|
| 1 | `bok-core` on PyPI, `bok-ui` on npm, trusted publishing | `release.yml`; a real v0.1.0 of each | **Yes** — `bok-ui`'s deadline moves to week 3 (§2.3) |
| 2 | `copier copy` produces a repo passing CI on first push, zero edits | A CI job that scaffolds into a temp dir and runs the generated CI | no |
| 3 | Storybook on Pages, every component × light/dark × densities, axe passing | Storybook deploy job + axe | **Yes** — v0.1 component list, both shipped densities, published deferral schedule (§8.2) |
| 4 | Worked provenance example: a number, three derivation levels, one inherited caveat, rendered | **Splits across two weeks.** Week 0: `examples/` builds the chain and a test asserts the three levels and the inherited caveat. Week 3: the same chain rendered through `<ProvenanceRail>` in Storybook | **Yes** — the "rendered" half follows `bok-ui` to week 3 (§2.3) |
| 5 | `test_degraded_mode_still_produces_findings` with every provider disabled | **Replaced** by `assert_blackout_complete()` + census helper in `bok-core`; each repo asserts its own floor | **Yes** — §7 |
| 6 | Boundary test proving `CLIENT_CONFIDENTIAL` cannot reach a free tier | `tests/boundary/` — every free-tier route, plus the egress path | **Extended** — egress is a second enforcement point (§3.3) |
| 7 | `docs/methodology.md` template with its four forced questions | `template/docs/methodology.md.jinja` | no |

### 11.2 Test classes

- **Unit** — no network, no model. `pytest`; `hypothesis` for the `Claim` chain invariants and any
  arithmetic.
- **Boundary** — `CLIENT_CONFIDENTIAL` raises on every free-tier route; `commercial=True` refuses a
  `commercial_use: false` provider; `trust=UNTRUSTED` cannot dispatch without an enforced schema and
  tool denial; redaction verification catches a deliberately planted identifier; `guard_write`
  refuses `CLIENT_CONFIDENTIAL` to a non-`CLIENT` plane; `SecretFingerprint` never retains, reprs or
  logs the raw value.
- **Gateway inversions** — `test_benchmark_execution_bypasses_cache`,
  `test_benchmark_slot_does_not_failover`,
  `test_lane_with_zero_eligible_providers_resolves_to_fallback`,
  `test_models_yaml_rejects_lane_without_fallback`, `test_unverified_provider_refuses_redacted`.
- **Provenance** — the six invariants of §4.3, chain depth parametric to ≥5.
- **Contract** — recorded cassettes per provider; a nightly live smoke test allowed to fail CI but
  required to open an issue; plus the `terms_sha256` diff.
- **Golden file** — SARIF against the 2.1.0 schema, with `logicalLocations` and `partialFingerprints`
  present.
- **Template** — scaffold-and-run-CI; restore test against the `pg_dump` sidecar.
- **Accessibility** — `axe-core`, zero serious/critical (week 3, with `bok-ui`).

Coverage floor **85%** on `bok-core`. A test that asserts nothing is a lie with a green tick.

---

## 12. Risks

| Risk | Mitigation |
|---|---|
| **Week 0 overruns and weeks 1–4 start late.** The programme's critical path runs through it | `bok-ui` already split out (§2.3). Further descope levers, in order: `gateway/probe.py` TTL caching reduced to the simplest form; `obs/metrics.py` deferred to week 3. **`boundary/` and `provenance/` are not descopable** — they are the reason this repo exists |
| **The gateway is built for an inventory that does not exist yet** | Deliberate. G2 makes the empty case the first tested state, so the inventory becomes data entry against a proven interface (§10.2) |
| **`bok-ui` in week 3 collides with `agent-perimeter` weeks 1–3** | Those weeks are Python-only, but week 3 already carries `report/html.py`, `eval/` and the graph. If week 3 is tight, `bok-ui` v0.1 slips into week 4 alongside the UI work that consumes it — acceptable, because `agent-perimeter`'s own descope lever already reduces week 4 to the report view plus the capability graph |
| **An interface requirement is discovered in week 9 that this contract missed** | `docs/INTERFACE-CONTRACT.md` is versioned and additive. `bok-core` is on PyPI, so an addition is a minor bump, not a vendored-source migration. `ground-truth` already carries a `_bok_shim.py` fallback pattern any repo can copy |
| **Publishing to PyPI/npm in week 0 makes early mistakes permanent** | Version `0.x` explicitly. Public-from-commit-one on this repo means `gitleaks` and the CLIENT-DATA-NEVER policy are load-bearing from commit one, not eventually |

---

## 13. Carry-back to the other four sessions

Amendments this design makes to already-approved consumer specs:

1. **`ledger-sense` `00` §12 Q5** — *public from commit one* becomes *public at first release* (§1.4).
2. **`ground-truth`** — adds an OpenTimestamps commitment on `docs/rubric.md` at authoring time,
   replacing repo visibility as the evidence for rubric-precedes-labelling (§1.4).
3. **All four** — the degraded-mode floor is declared per repo in its own unit and published in
   `docs/methodology.md`; the shared `≥70%` assertion no longer exists (§7).
4. **`ground-truth`** — `router.call(failover=DISABLED)` is available and **required** for benchmark
   execution; `test_benchmark_slot_does_not_failover` belongs in its plan (§5, G5).
5. **All four** — `boundary.egress.guard_write` exists; `selector-drift`'s evidence write path and
   `agent-perimeter`'s secret-persistence guard route through it rather than through bespoke code
   (§3.3).

The full interface surface is `docs/INTERFACE-CONTRACT.md`.
