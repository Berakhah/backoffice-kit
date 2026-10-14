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
| Emails | Covered (ASCII TLD) | `email` | `local@domain.tld`. The local part follows RFC 5322: atext (letters, digits and ``! # $ % & ' * + - / = ? ^ _ ` { | } ~``, plus dots), quoted strings (`"john smith"`), parenthesised comments (`ana(comment)`), and Unicode letters including spacing marks (`Mc`, so Devanagari EAI local parts are covered). It is up to 64 items and may be empty, so a bare `@domain.tld` residue is also redacted. The TLD must be ASCII letters |
| Phones | Covered (NANP shape) | `phone` | optional `+CC` (1–3 digits) prefix; `(ddd)` or `ddd`; then `ddd` and `dddd`, each gap independent (`555-010-0100`, `555 010-0100`, `555/010.0100`, `5550100100`) |
| Tax ids | Covered (US shapes only) | `tax_id` | EIN `12-3456789`; SSN/ITIN `123-45-6789` (hyphenated; other layouts are still caught as digit runs) |
| Bank / routing numbers | Covered (partial) | `routing`, `account`, `iban`, `card`, `digit_run` | 9 contiguous digits (`routing`); 8–12 digits (`account`); 13–19 digits (`card`); 20+ digits (`digit_run`) — the last three with an optional gap (below) between any two digits; IBAN, case-insensitive, compact `NL91ABNA0417164300` or in groups of four with the same gap before every group, the trailing 1–4 character group included (`GB82 WEST 1234 5698 7654 32`, `GB82-WEST-1234-5698-7654-32`, `MT84  MALT  0110  0001  2345  MTLC  AST0  01S`, `GB82WEST 1234 ...`); plus **national display formats** with groups of any width: an optional gap between country code and check digits, then 11–30 letters/digits each optionally preceded by a gap (`IT60 X 05428 11101 000000123456`, `FR76 30006 00001 12345678901 89`, `MT84 MALT 01100 0012345MTLCAST001S`, `GB 82 WEST ...`). When the code and check digits are separated by a gap, the code must be upper case (`iban`) |
| Addresses | **NOT covered** | `address` (declared, no detector) | — |
| Person names | **NOT covered** | `person_name` (declared, no detector) | — |

**Every run of 8 or more digits is redacted**, however it is split by the gaps below and
whatever its length or script: 8–12 (`account`, or `routing`/`phone`/`tax_id` on a tie),
13–19 (`card`), 20+ (`digit_run`).

### Normalisation — structural, applied to ALL text

Before detection the text is normalised, and **the redacted output is the normalised
text — all of it, not only the identifiers** (see "Output text" below):

1. Unicode **NFKD** (compatibility decomposition: full-width and mathematical digits fold
   to ASCII, ligatures split, and every precomposed letter splits into base letter plus
   combining mark).
2. Every decimal digit of **any** script (category `Nd`: Arabic-Indic `٠-٩`, Devanagari
   `०-९`, Thai, Bengali, Adlam, ... — every `Nd` Python 3.12 knows) becomes its ASCII
   digit.
3. **Removed:**
   - every combining mark (`Mn`, `Me`). Because step 1 decomposed first, this removes
     **every diacritic from all text**: `café` becomes `cafe`, `ana@x.tést`
     becomes `ana@x.test`, and Devanagari vowel signs and nukta are dropped;
   - every control character (`Cc`) except TAB, LF, CR, VT and FF: NUL, BS, ESC, DEL, NEL
     and the rest of C0/C1;
   - every format character (`Cf`: zero-width space, soft hyphen, word joiner, bidi marks,
     ZWJ/ZWNJ, BOM, tag characters, ...);
   - every `Default_Ignorable_Code_Point`, hard-coded from Unicode 15.0.0 (the version
     Python 3.12 implements). This includes CGJ U+034F, the variation selectors, the
     Hangul fillers U+115F/U+1160/U+3164/U+FFA0, Khmer U+17B4/17B5 and Mongolian
     U+180B–180F;
   - the braille pattern blank U+2800;
   - lone surrogates (`Cs`, which reach Python from JavaScript strings via JSON and would
     make the output unencodable), private use (`Co`) and unassigned code points (`Cn`,
     as of Unicode 15.0.0).
4. Every space separator (`Zs`) becomes an ASCII space. Every dash (`Pd`) and the minus
   sign U+2212 becomes an ASCII hyphen. **Lookalike separators** are mapped into the gap
   set:
   - slashes U+2044, U+2215, U+29F8 and U+2571 → `/`;
   - full stops and dots U+3002 (U+FF61 decomposes to it), U+06D4, U+2E3C, U+00B7,
     U+2022, U+2027, U+2219 and U+30FB → `.`;
   - dash-likes U+30FC (with U+FF70), U+02D7, U+2043, U+2796, U+23AF and the box-drawing
     horizontals → `-`.

   NFKD already folds U+FF0F, U+FF0E, U+2024 and U+FE52 to ASCII.
5. NFC, which only recomposes what is left (Hangul syllables).

After that, the **gap** the digit detectors (`phone`, `account`, `card`, `digit_run`) and
the IBAN groups accept is nothing, or a run of **1 to 3** characters from: whitespace
(space, TAB, CR, LF, VT, FF), `.`, `-`, `/`. So `4111  1111`, `4111<TAB>1111` (the
innerText of a table row), `4111<LF>1111`, `4111 - 1111` and `4111/1111` each form one
run.

Anything else **ends** a run, including the separators listed under "Declared gaps"
below. A run that ends with fewer than 8 digits is not redacted.

### Surrogates and joins

The HMAC input of a **standalone** identifier is its **canonical** form, so one identifier
gets one surrogate whatever its layout or case. A span is standalone when the detector
match that labels it covers the whole span. The canonical forms are:
- the digits alone for `phone`, `account`, `routing`, `card`, `tax_id` and `digit_run`
  (`555-010-0100` and `(555) 010 0100` match);
- the letters and digits in upper case for `iban` (compact, spaced, dashed and
  lower-case layouts match);
- lower case for `email` (`ana@x.test` and `ANA@X.TEST` match).

A **merged** span is one where identifiers were glued together, or overlapping matches
widened the span beyond its labelling match. Its HMAC input is the kind plus the
**full normalised span text**, never a canonical form that drops parts. Its surrogate
is therefore **not** the surrogate of any identifier inside it. For example,
`4111 1111 1111 1111a@b.cc` does not get the standalone card's surrogate.

Joins break in two other cases as well:
- **Different labels:** the same digits get different surrogates when the label differs
  (`phone` standing alone, `card` when glued to more digits).
- **Different country prefix:** `+1 555 010 0100` and `555-010-0100` canonicalise to
  different digits. This is deferred, not fixed.

### Output text

The redacted text is the normalised text, so text outside the identifiers changes too:
- diacritics are removed from all text;
- control characters other than TAB/LF/CR/VT/FF are removed;
- ligatures are split (`ﬁ` → `fi`) and superscripts flattened (`²` → `2`);
- full-width letters and other compatibility forms are folded;
- digits of every script become ASCII;
- bidi marks and ZWJ inside emoji sequences are removed.

**No offset map from the output back into the original is provided.** A consumer that
needs to align the two must normalise the original with the same rules (`_normalise`).

### What "not covered" means operationally

Regex reaches neither addresses nor person names; they need a local NER model (spaCy or
GLiNER), scheduled for week 5 against ledger-sense's real corpus. Until that ships, **a
document containing a person's name or a street address is not `REDACTED` — it remains
`CLIENT_CONFIDENTIAL`**, whatever `redact()` returns. `verified=True` means only "no
*covered* detector fires on the output".

### Declared gaps (canonical list)

This list is the single source. `docs/INTERFACE-CONTRACT.md` §1.3 carries the identical
list between the same markers, and `tests/boundary/test_redact.py` asserts that the two
are equal.

<!-- declared-gaps:start -->
- Addresses and person names: no detector yet (a local NER model is planned for week 5).
- Digit groups split by `,` `'` `:` `|` `_` `;`, U+066B or U+066C, or by any other character outside the gap set and its mapped lookalikes. Box-drawing verticals and corners, and dingbat slashes and dashes not in `_LOOKALIKE`, are not mapped.
- Gaps of 4 or more gap characters between digit groups.
- Account numbers shorter than 8 digits. Non-US tax ids and non-NANP phone layouts are not detected as such, though their runs of 8+ digits are still caught.
- Emails with an IDN or non-ASCII TLD, emails with comments or quoted strings in the domain part, and local parts of more than 64 items or starting more than 256 characters before the `@`.
- Digit-valued `No` characters without an NFKD digit form: dingbat negative-circled digits (U+2776-U+277F), double-circled digits (U+24F5-U+24FE), Ethiopic (U+1369-U+137C), Kharoshthi (U+10A40-U+10A48), Brahmi (U+11052-U+11065), Rumi (U+10E60-U+10E7E), and similar.
<!-- declared-gaps:end -->

### Over-redaction (declared, deliberate)

The bias is toward over-redaction. The shapes below are redacted even though they are
usually not identifiers, which reduces the usefulness of heal-log evidence:

- **Any 8+ digits joined by the gap set:** dates (`2026-10-14`, `2026/10/14`,
  `20261014`), IP addresses (`192.168.100.200`), version strings, order numbers.
- **Rows of small numbers and prices** in tab-separated or spaced tables become
  `account`, `card` or `digit_run`: `1<TAB>2<TAB>3 ...` once it reaches 8+ digits in
  total, or `12.50 13.75 9.99`.
- **IBAN-shaped tokens and the words after them:** any token of 15+ letters/digits that
  starts with two letters and two digits, in either case (hex hashes, SKUs), is
  redacted as `iban`. After an IBAN-like prefix, the redaction also takes up to seven
  4-character words of either case joined by any gap, plus one final word of 1–4
  characters. So `AB12 THIS WORD ok` is redacted whole, `ok` included. An IBAN can
  absorb a short word (1–4 characters) that follows it in two ways:
  - Its own last group has four characters: `GB82 WEST 1234 5698 7654 3210 and` loses
    `and`.
  - An inner IBAN-shaped match at another 4-alignment ends there. The scan must look for
    overlapping IBAN matches, or IBANs glued together leak. For example
    `GB82WEST12345698765432 now` contains `ST12345698765432 now`.

  In the second case, and whenever an inner match widens the span, the span becomes a
  **merged span** keyed on its full text. So **the IBAN's surrogate in that context is
  not its standalone surrogate**: the join is lost, but nothing leaks and there is no
  false join. Followed by `;`, `,`, `)` or end of text, an IBAN keeps its standalone
  (canonical) surrogate.
- **National-layout IBAN fallback:** after an IBAN-like prefix (two letters, optionally
  a gap when they are upper case, then two digits), the next 30 letters and digits are
  taken. They are counted across gap-separated words of any width, and the 30th may fall
  mid-word. With fewer than 30 available, the run ends at the last word boundary.
  An IBAN-like prefix *inside* the IBAN (`ST12` in `…WEST12…`) starts another such match.
  So prose after an IBAN can lose up to roughly 40 letters/digits, up to the next
  character outside the gap set (`,` `;` `:` ...). Examples:
  - `IN 20 MINUTES WE LEFT` is redacted;
  - `GB82WEST12345698765432 for the invoice now` loses `for the invoice now`;
  - `SC52 BAHL ... USD and more` loses `and more`.

  The span's surrogate is then context-specific: the join is lost, but nothing leaks.
  Lower-case prose such as `on 12 March 2026` is not affected.
- **Glued identifiers:** identifiers glued together with no separator are redacted (no
  fragment of either survives, property-tested), but they merge into one span with one
  surrogate.

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
