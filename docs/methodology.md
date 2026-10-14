# Methodology

How `bok-core` makes the claims it makes, and where those claims stop.

## Redaction coverage (`bok_core.boundary.redact`)

`00` §4.2 names six identifier classes the redactor must handle. Coverage is a **declared
list**: an undetected class is a hole in the data boundary, and naming it is the difference
between a limitation and a lie. The source of truth is the pair of tuples `COVERED` and
`NOT_COVERED` in `src/bok_core/boundary/redact.py`; `tests/boundary/test_redact.py` asserts
that every kind named there is also named here.

| `00` §4.2 class | Status | Detector kind(s) | Shapes recognised (after normalisation, below) |
|---|---|---|---|
| Emails | Covered | `email` | `local@domain.tld`; local part 0–64 chars of `[\w.%+-]`, so a bare `@domain.tld` residue is also redacted |
| Phones | Covered (NANP shape) | `phone` | optional `+CC` (1–3 digits) prefix; `(ddd)` or `ddd`; then `ddd` and `dddd`, each gap independent (`555-010-0100`, `555 010-0100`, `555/010.0100`, `5550100100`) |
| Tax ids | Covered (US shapes only) | `tax_id` | EIN `12-3456789`; SSN/ITIN `123-45-6789` (hyphenated; other layouts are still caught as digit runs) |
| Bank / routing numbers | Covered (partial) | `routing`, `account`, `iban`, `card`, `digit_run` | 9 contiguous digits (`routing`); 8–12 digits (`account`); 13–19 digits (`card`); 20+ digits (`digit_run`) — the last three with an optional gap (below) between any two digits; IBAN, case-insensitive, compact `NL91ABNA0417164300` or spaced in groups of four with single spaces `GB82 WEST 1234 5698 7654 32` (`iban`) |
| Addresses | **NOT covered** | `address` (declared, no detector) | — |
| Person names | **NOT covered** | `person_name` (declared, no detector) | — |

**Every run of 8 or more digits is redacted**, however it is split by the gaps below and
whatever its length: 8–12 (`account`, or `routing`/`phone`/`tax_id` on a tie), 13–19
(`card`), 20+ (`digit_run`).

### Normalisation — which separators are covered

Before detection the text is normalised, and **the redacted output is the normalised
text — all of it, not only the identifiers** (see "Output text" below):

1. Unicode NFKC (full-width digits `０-９` become ASCII digits; compatibility forms fold).
2. Every space separator (category `Zs`: NBSP U+00A0, narrow NBSP U+202F, thin space
   U+2009, en space U+2002, ...) becomes an ASCII space.
3. Every dash (category `Pd`: en dash U+2013, em dash U+2014, non-breaking hyphen U+2011,
   ...) and the minus sign U+2212 becomes an ASCII hyphen.
4. Removed: every format character (category `Cf`: zero-width space, soft hyphen, word
   joiner, bidi marks, ZWJ/ZWNJ, BOM, tag characters, ...); every
   `Default_Ignorable_Code_Point` (hard-coded from Unicode 15.0.0, the version Python
   3.12 implements — includes the combining grapheme joiner U+034F, variation selectors
   U+FE00–FE0F and U+E0100–E01EF, Hangul fillers U+115F/U+1160/U+3164/U+FFA0, Khmer
   U+17B4/17B5, Mongolian U+180B–180F); the braille pattern blank U+2800; and any
   combining mark (`Mn`/`Me`) directly after a digit or a gap character.

After that, the gap the digit detectors (`phone`, `account`, `card`, `digit_run`) accept
**between two digits** is nothing, or a run of **1 to 3** characters from: space, TAB,
CR, LF (and other whitespace), `.`, `-`, `/`. So `4111  1111`, `4111<TAB>1111` (the
innerText of a table row), `4111<LF>1111`, `4111 - 1111` and `4111/1111` are one run. A
gap of 4 or more such characters, or any other character (`,`, `:`, a letter), ends the
run — and a run that ends with fewer than 8 digits is not redacted. IBANs are recognised
compact or with single spaces between groups of four.

### Surrogates and joins

The HMAC input is the **canonical** identifier, so one identifier gets one surrogate
whatever its layout or case: digits only for `phone`, `account`, `routing`, `card`,
`tax_id`, `digit_run` (`555-010-0100` and `(555) 010 0100` match); separator-free upper
case for `iban` (spaced and compact match); lower case for `email` (`ana@x.test` and
`ANA@X.TEST` match). Joins across documents survive that far. They do NOT survive
merging: when identifiers are glued together (or overlap) they are replaced as **one
merged span with one surrogate, which is not the surrogate either identifier gets on its
own**. The label also differs between kinds: the same digits labelled `phone` in one
document and `account` in another get different surrogates.

### Output text

The redacted text is the normalised text. Non-identifier text is therefore changed too:
ligatures (`ﬁ` → `fi`), superscripts (`²` → `2`), full-width letters, compatibility
forms, bidi marks and ZWJ inside emoji sequences are all normalised or removed. **No
offset map from the output back into the original is provided**; a consumer that needs
to align the two must normalise the original with the same rules.

### What "not covered" means operationally

Regex reaches neither addresses nor person names; they need a local NER model (spaCy or
GLiNER), scheduled for week 5 against ledger-sense's real corpus. Until that ships, **a
document containing a person's name or a street address is not `REDACTED` — it remains
`CLIENT_CONFIDENTIAL`**, whatever `redact()` returns. `verified=True` means only "no
*covered* detector fires on the output".

### Known gaps inside the covered classes

- Account numbers shorter than 8 digits are not detected, nor are digit groups separated
  by a gap of 4+ characters or by anything outside the gap set (e.g. `1234,5678`).
- Non-US tax ids and non-NANP phone layouts are not detected as such (8+ digits of them
  are still caught as digit runs).

### Over-redaction (declared, deliberate)

The bias is toward over-redaction. These shapes are redacted although they are usually
not identifiers, and that reduces the usefulness of heal-log evidence:

- any 8+ digits joined by the gap set: dates (`2026-10-14`, `2026/10/14`, `20261014`),
  IP addresses (`192.168.100.200`), version strings, order numbers;
- rows of small numbers and prices in tab-separated or spaced tables (`1<TAB>2<TAB>3 ...`
  with 8+ digits in total, `12.50 13.75 9.99`) become `account`, `card` or `digit_run`;
- any token of 15+ letters/digits starting with two letters and two digits, in either
  case (hex hashes, SKUs), as `iban`; and, after an IBAN-like prefix, up to seven
  space-separated 4-character words of either case plus one final 1–4 character word
  (`AB12 THIS WORD ok` is redacted whole, `ok` included);
- identifiers glued together with no separator are redacted (no fragment of either
  survives — property-tested) but merge into one surrogate under one label.

### How redaction works, and what verification can and cannot catch

1. Every detector runs over the same normalised text. Overlapping matches are merged
   into one span, labelled by its longest constituent match (earlier detector on a tie),
   and each span is replaced whole with an HMAC-SHA256-keyed surrogate
   (`BOK_REDACTION_KEY`, at least 32 bytes, never committed) in a digit-free alphabet.
2. This repeats (at most 4 passes) until no detector matches, because a substitution can
   expose a new match.
3. **Verification** re-runs every detector over the output. If any fires, the result is
   `verified=False`, `failures` names the detector kinds (never the matched text), and
   `RedactionResult.labelled()` raises `RedactionFailed`.

Verification catches an identifier that a covered detector **still recognises** in the
output: one whose substitution was skipped or failed, or one exposed by a neighbouring
substitution. It **cannot** catch an identifier that was mangled into a shape no detector
recognises. When detectors substituted one after another, `phone` took the digit tail of
`NL91ABNA0417164300` and left `NL91ABNA[PHONE:..]`, which verified. That failure mode is
prevented structurally by step 1 (span merging means a character any detector matched is
always redacted), not by verification, and is pinned by property tests: per-kind counts
for separated identifiers, and "no 4-character fragment of any identifier survives" for
separated, adjacent and glued identifiers with Unicode separator noise.

`RedactionResult.text` is excluded from `repr()`/`str()`, because a failed result still
holds the surviving identifier. `model_dump()` includes it: a caller that persists an
unverified result's text must treat it as `CLIENT_CONFIDENTIAL` and route it through
egress like the original document.
