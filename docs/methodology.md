# Methodology

How `bok-core` makes the claims it makes, and where those claims stop.

## Redaction coverage (`bok_core.boundary.redact`)

`00` §4.2 names six identifier classes the redactor must handle. Coverage is a **declared
list**: an undetected class is a hole in the data boundary, and naming it is the difference
between a limitation and a lie. The source of truth is the pair of tuples `COVERED` and
`NOT_COVERED` in `src/bok_core/boundary/redact.py`; `tests/boundary/test_redact.py` asserts
that every kind named there is also named here.

| `00` §4.2 class | Status | Detector kind(s) | Shapes recognised |
|---|---|---|---|
| Emails | Covered | `email` | `local@domain.tld` |
| Phones | Covered | `phone` | 10-digit NANP shape, optional `+CC` prefix, optional `(area)`, `-` `.` or space separators |
| Tax ids | Covered (US shapes only) | `tax_id` | EIN `12-3456789`; SSN/ITIN `123-45-6789` (hyphenated only) |
| Bank / routing numbers | Covered (partial) | `routing`, `account`, `iban`, `card` | any standalone 9-digit run (`routing`); any standalone 8-digit run (`account`); IBAN shape; 13–19 digit card numbers with optional single space/hyphen separators (`card`) |
| Addresses | **NOT covered** | `address` (declared, no detector) | — |
| Person names | **NOT covered** | `person_name` (declared, no detector) | — |

### What "not covered" means operationally

Regex reaches neither addresses nor person names; they need a local NER model (spaCy or
GLiNER), scheduled for week 5 against ledger-sense's real corpus. Until that ships, **a
document containing a person's name or a street address is not `REDACTED` — it remains
`CLIENT_CONFIDENTIAL`**, whatever `redact()` returns. `verified=True` means only "no
*covered* detector fires on the output".

### Known gaps inside the covered classes

- Account numbers of any length other than exactly 8 digits are not detected unless they
  happen to match another shape (9 digits -> `routing`, 13–19 -> `card`).
- Non-US tax ids, unhyphenated SSNs, and non-NANP phone formats are not detected.
- Detection is deliberately over-eager on digit runs (a date written `20261014` is redacted
  as an `account`). Over-redaction is the safe direction for a boundary.

### Verification pass

After substitution, every detector is re-run over the output; if any fires, the result is
`verified=False`, `failures` names the detector kinds (never the matched text), and
`RedactionResult.labelled()` raises `RedactionFailed`. Surrogates are HMAC-SHA256 keyed
(`BOK_REDACTION_KEY`, never committed) and rendered in a digit-free alphabet so a correct
redaction can never re-trigger a detector.
