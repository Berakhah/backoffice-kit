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
| Phones | Covered (NANP shape) | `phone` | optional `+CC` (1–3 digits) prefix; `(ddd)` or `ddd`; then `ddd` and `dddd`. Without parentheses the two separators must be the same (`555-010-0100`, `555.010.0100`, `555 010 0100`, `5550100100`) |
| Tax ids | Covered (US shapes only) | `tax_id` | EIN `12-3456789`; SSN/ITIN `123-45-6789` (hyphenated only) |
| Bank / routing numbers | Covered (partial) | `routing`, `account`, `iban`, `card`, `digit_run` | 9 contiguous digits (`routing`); 8–12 contiguous digits (`account`); IBAN, compact `NL91ABNA0417164300` or spaced in groups of four `GB82 WEST 1234 5698 7654 32` (`iban`); 13–19 digits (`card`) and 20+ digits (`digit_run`), each with an optional single separator between any two digits |
| Addresses | **NOT covered** | `address` (declared, no detector) | — |
| Person names | **NOT covered** | `person_name` (declared, no detector) | — |

**Every contiguous run of 8 or more digits is redacted**, whatever its length: 8–12
(`account`, or `routing`/`phone` at 9/10), 13–19 (`card`), 20+ (`digit_run`). Runs longer
than 19 used to be undetected, and a spaced run longer than 19 left a tail; both are now
detected.

### Normalisation — which separators are covered

Before detection the text is normalised, and **the redacted output is the normalised
text**:

1. Unicode NFKC (full-width digits `０-９` become ASCII digits; compatibility forms fold).
2. Every space separator (category `Zs`: NBSP U+00A0, narrow NBSP U+202F, thin space
   U+2009, en space U+2002, ...) becomes an ASCII space.
3. Every dash (category `Pd`: en dash U+2013, em dash U+2014, non-breaking hyphen U+2011,
   ...) and the minus sign U+2212 becomes an ASCII hyphen.
4. Every format character (category `Cf`: zero-width space U+200B, soft hyphen U+00AD,
   word joiner U+2060, ZWJ/ZWNJ, BOM, ...) is removed.

After that, the separators the digit detectors accept **between digits** are exactly one
ASCII space, hyphen or dot. **Tabs, newlines and runs of two or more separators are NOT
separators**: `4111  1111 1111 1111` (double space) or a number split across a line break
is not recognised as one identifier (its 8+-digit pieces still are). IBANs are recognised
compact or with single spaces between groups of four, upper-case only.

Surrogates are computed on the normalised identifier, so `4111<NBSP>1111 ...` and
`4111 1111 ...` get the same surrogate and joins survive.

### What "not covered" means operationally

Regex reaches neither addresses nor person names; they need a local NER model (spaCy or
GLiNER), scheduled for week 5 against ledger-sense's real corpus. Until that ships, **a
document containing a person's name or a street address is not `REDACTED` — it remains
`CLIENT_CONFIDENTIAL`**, whatever `redact()` returns. `verified=True` means only "no
*covered* detector fires on the output".

### Known gaps inside the covered classes

- Account numbers shorter than 8 digits, and spaced/hyphenated account numbers of 8–12
  digits that match no phone or tax-id shape, are not detected.
- Non-US tax ids, unhyphenated SSNs (9 digits are caught as `routing` anyway), non-NANP
  phone layouts and lower-case IBANs are not detected.
- Detection is deliberately over-eager: any 8+ digit run (a date written `20261014`, an
  order number), any upper-case token of 15+ characters starting with two letters and two
  digits, and a row of 13+ single digits separated by spaces are all redacted.
  Over-redaction is the safe direction for a boundary; it can reduce the usefulness of
  heal-log evidence.
- Identifiers glued together with no separator are redacted (no fragment of either
  survives — property-tested), but may be merged into one surrogate under one label.

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
