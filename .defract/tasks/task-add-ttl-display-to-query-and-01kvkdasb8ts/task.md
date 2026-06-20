---
defract:
  id: task-add-ttl-display-to-query-and-01kvkdasb8ts
  type: improvement
  status: active
  stage: release
  phase: 0
  total_phases: 1
  priority: normal
  source: backlog
  source_id: bli-add-ttl-display-1
  branch_strategy: worktree
  mode: human-in-the-loop
  created_by: holynakamoto
  assignee: holynakamoto
---

## Story Brief

Promoted from backlog item `bli-add-ttl-display-1`.

- Module: dnsmenace.py

Original paste from the builder:

> Extend the DNS query functions to capture and surface TTL values alongside each answer, adding a TTL column to the table output in `display_results_table` and the propagation command.
> TTL is one of the most useful pieces of data for diagnosing caching issues and stale records, but it is currently stripped when answers are converted to strings — exposing it would make the tool noticeably more useful for its target audience.

# Add TTL display to query and propagation result tables

# Add TTL display to query and propagation result tables

## What We're Building

DNS records carry a Time-To-Live (TTL) value that tells resolvers and clients how long to cache a response. This value is currently discarded when the tool formats answers for display. We are adding TTL capture and display to the two main result tables — the standard query output and the propagation check — so that security researchers and network administrators can see cache lifetimes alongside each answer.

## Expected Outcome

- Running a DNS query shows a TTL column in the results table next to each answer
- Running a propagation check shows a TTL column alongside each DNS provider's response
- TTL values are displayed as whole seconds, matching the raw DNS wire format
- Results with errors show a dash in the TTL column rather than crashing
- The existing JSON and CSV output formats are not changed by this work

## Phase Outcomes

- **Phase 1: Add TTL column to query and propagation tables** — Security researchers and network administrators see the cache lifetime alongside every DNS answer, making it easier to diagnose stale records and caching issues without needing separate tooling.

## Out of Scope

- Adding TTL to JSON or CSV output formats — those formats may be consumed by scripts and a format change requires a separate decision
- TTL-based filtering, sorting, or alerting on results
- Any changes to the live monitoring or watch command
- Capturing TTL for DNS-over-HTTPS or `query_dns_simple` callers — those code paths do not feed the two target tables

## Scope Summary

**Size:** 6 requirements, 7 acceptance criteria, 1 implementation phase
**Key decisions:**
- Store TTL as a single `int | None` on `DNSResult` rather than a parallel list, since all records in a DNS RRset share one TTL
- Modify only `query_dns` (not `query_dns_simple` or `query_doh`) — only `query_dns` feeds the two target tables
**Biggest risk:** dnspython's `Answer.rrset` attribute must be guarded; if the answer has no rrset (unusual but possible in CNAME-chain edge cases), a bare attribute access will raise `AttributeError`.

## Context

`DNSResult` (line 86) stores `answers: list[str]` — TTL is thrown away at line 226 when `str(rdata)` is called for each answer in `query_dns`. The zone-transfer command already displays TTL via `rdataset.ttl` (line 1303), confirming the access pattern is established in this codebase. `display_results_table` (line 455) and the inline propagation table (line 1356) are the two targets. Both already have a response-time column that shows "-" on error, so the TTL column follows the same convention.

## Requirements

### Data Model

- R1: `DNSResult` (line 86) gains a `ttl: int | None` field with a default of `None`. The existing `answers: list[str]` field is unchanged so JSON and CSV serialisation are unaffected.

### DNS Query Function

- R2: `query_dns` (line 205) captures the TTL from the resolved answer's rrset after a successful resolution and stores it in `result.ttl`. The capture uses `answers.rrset.ttl` guarded against an absent or `None` rrset so that an unusual empty rrset does not raise an unhandled exception.
- R3: On any error path in `query_dns` (NXDOMAIN, NoAnswer, Timeout, DNSException), `result.ttl` remains `None`.

### Query Results Table

- R4: `display_results_table` (line 455) adds a "TTL (s)" column between the Response and Time (ms) columns. The column is right-justified. Each row shows the integer TTL value when `result.ttl` is set, or "-" when it is `None`. The zone-transfer table's TTL column (line 1303) is the stylistic precedent.

### Propagation Table

- R5: The propagation command's inline table (line 1356) adds a "TTL (s)" column with the same heading, justification, and "-" fallback, positioned between Response and Time (ms).

### Output Format Preservation

- R6: `display_results_json` (line 489) and `display_results_csv` (line 508) are not modified. If either uses `dataclasses.asdict`, the implementation must explicitly exclude the new `ttl` field to avoid silently adding it to the output.

## Acceptance Criteria

- [ ] `dnsmenace query example.com` produces a table with a "TTL (s)" column showing a positive integer for each successful answer
- [ ] `dnsmenace propagation example.com` produces a table with a "TTL (s)" column showing a positive integer for each resolver that returned a result
- [ ] A query for a non-existent domain (e.g. `dnsmenace query nonexistent.invalid`) shows "-" in the TTL column for every row with no Python traceback
- [ ] `dnsmenace query example.com --output json` produces output with no `ttl` key (format is identical to before this change)
- [ ] `dnsmenace query example.com --output csv` produces output with no `ttl` column (format is identical to before this change)
- [ ] `mypy dnsmenace.py` passes with no new type errors
- [ ] `ruff check dnsmenace.py` passes with no new warnings

## Implementation Phases

### Phase 1: Add TTL column to query and propagation tables
**Scope:** Add a `ttl: int | None` field to `DNSResult`, capture the TTL in `query_dns`, and render a "TTL (s)" column in `display_results_table` and the propagation command's table.
**Files:**
- `dnsmenace.py` — `DNSResult` dataclass (line 91), `query_dns` success path (line 226), `display_results_table` (line 455), propagation inline table (line 1356), and JSON/CSV display functions (lines 489/508) if `dataclasses.asdict` is used
**Verification:**
- Run `dnsmenace query example.com` — confirm "TTL (s)" column is present with a positive integer per row
- Run `dnsmenace propagation example.com` — confirm "TTL (s)" column is present with positive integers
- Run `dnsmenace query nonexistent.invalid` — confirm "-" in TTL column, no traceback
- Run `dnsmenace query example.com --output json` — confirm no `ttl` key in output
- Run `mypy dnsmenace.py` — zero new errors
- Run `ruff check dnsmenace.py` — zero new warnings
**Estimated effort:** Small

## Edge Cases

- **Answer with no rrset**: dnspython's `Answer` object may have `rrset` as `None` when the response is synthesised from a CNAME chain. Guard TTL capture with a `None` check on `answers.rrset`; default `result.ttl` to `None` if absent.
- **Zero TTL records**: a TTL of 0 is valid (uncacheable records such as SOA negatives). Display it as `0`, not "-".
- **DoH and query_dns_simple results**: these functions are not modified and will always produce `DNSResult` objects with `ttl = None`, which display as "-". This is acceptable for this scope.

## Technical Notes

dnspython's `Answer` object (returned by `await resolver.resolve(...)`) exposes the rrset TTL at `answers.rrset.ttl` — an integer of whole seconds. This is the same attribute already used for the zone-transfer display at line 1303 (`rdataset.ttl`), confirming it is stable and idiomatic in this codebase.

The `DNSResult` dataclass uses `dataclasses.field` defaults throughout; `ttl: int | None = None` fits the existing pattern without needing `field(default_factory=...)`.

Before implementing R6: check whether `display_results_json` calls `dataclasses.asdict(result)`. If it does, the `ttl` field will appear in JSON output automatically and must be explicitly dropped before serialisation (e.g. via a dict comprehension excluding `"ttl"`).

### Dependencies

None. All changes are confined to `dnsmenace.py` and the existing dnspython `Answer` object interface.

## Implementation Notes

## Phase 1: Add TTL column to query and propagation tables

**Files modified:** `dnsmenace.py`

**Changes:**

1. `DNSResult` dataclass (line 91) — added `ttl: int | None = None` as a trailing field using the existing `= None` pattern; no `field()` wrapper needed since it is a scalar default.

2. `query_dns` success path — after populating `result.answers`, captures `answers.rrset.ttl` into `result.ttl`, guarded with `if answers.rrset is not None`. Error paths leave `ttl` as `None`.

3. `display_results_table` — added a right-justified "TTL (s)" column (style: magenta) between Response and Time (ms). Each row shows `str(result.ttl)` when set, `"-"` when `None`. Zero-TTL records display as `"0"` correctly.

4. Propagation inline table — same column added in the same position with the same logic.

5. `display_results_json` and `display_results_csv` — not modified; both manually construct output dicts/rows, so the new `ttl` field is never exposed.

**Test results:** 32/32 passed (test_scenarios.py). Zero new ruff warnings, zero new mypy errors.

## Review

## Verdict

**Verdict:** APPROVE
**Files reviewed:** 1 files changed across 1 phases

All 7 acceptance criteria pass. The TTL field is correctly added to DNSResult with a None guard in query_dns, both target tables display the new column between Response and Time (ms), and JSON/CSV output formats are unchanged. No new mypy or ruff issues introduced.

### Automated Checks

| Check | Result | Details |
|-------|--------|---------|
| Ruff lint | PASS | 39 pre-existing warnings, 0 new on changed lines |
| mypy type check | PASS | 29 pre-existing errors, 0 new in changed code |

### Acceptance Criteria (7/7 passed)

- [x] AC-1: `dnsmenace query example.com` produces a table with a "TTL (s)" column showing a positive integer for each successful answer — PASS: Ran `python3 dnsmenace.py dnsmenace query -c US -d example.com -l 2` — TTL column present showing 300 for dns.google row, "-" for timed-out row
- [x] AC-2: `dnsmenace propagation example.com` produces a table with a "TTL (s)" column showing a positive integer for each resolver that returned a result — PASS: Ran `python3 dnsmenace.py dnsmenace propagation example.com` — TTL column present showing 200-300 range for all 7 successful resolvers, "-" for timed-out Alternate DNS row
- [x] AC-3: A query for a non-existent domain (e.g. `dnsmenace query nonexistent.invalid`) shows "-" in the TTL column for every row with no Python traceback — PASS: Ran `python3 dnsmenace.py dnsmenace query -c US -d nonexistent.invalid -l 2` — both rows show "-" in TTL column (NXDOMAIN and Timeout), no traceback
- [x] AC-4: `dnsmenace query example.com --output json` produces output with no `ttl` key (format is identical to before this change) — PASS: Ran `python3 dnsmenace.py dnsmenace query -c US -d example.com -l 2 --output json` — keys are nameserver, query, record_type, answers, error, response_time_ms; no ttl key present
- [x] AC-5: `dnsmenace query example.com --output csv` produces output with no `ttl` column (format is identical to before this change) — PASS: Ran `python3 dnsmenace.py dnsmenace query -c US -d example.com -l 2 --output csv` — header row is nameserver_ip,nameserver_name,record_type,answers,error,response_time_ms; no ttl column
- [x] AC-6: `mypy dnsmenace.py` passes with no new type errors — PASS: mypy reports 29 errors, all pre-existing (lines 1985, 1990, 2067, 2068 and others far from changed lines 94, 229-230, 471, 480, 1372, 1384); no errors on new code
- [x] AC-7: `ruff check dnsmenace.py` passes with no new warnings — PASS: ruff reports 39 errors, none on changed lines (94, 229-230, 471, 480, 1372, 1384); grep for new line numbers returned empty

### Code Quality (Refactor Review)

No code quality issues found in changed files.

### Security Assessment (Security Review)

No security issues found in changed files.

### Decisions Made During Implementation

- TTL stored as a single `int | None` field on `DNSResult` rather than a parallel list — all records in a DNS RRset share one TTL value
- Only `query_dns` modified (not `query_dns_simple` or `query_doh`) — only `query_dns` feeds the two target tables
- JSON and CSV outputs manually construct output dicts/rows without `dataclasses.asdict`, so the new ttl field is never exposed in those formats

## Required Changes

None.

## Release

## Release Notes

### What was built
- Added `ttl: int | None = None` field to the `DNSResult` dataclass so DNS record cache lifetimes are captured alongside each answer
- Extended `query_dns` to read `answers.rrset.ttl` on the success path, guarded with a `None` check to handle edge-case empty rrsets
- Added a right-justified "TTL (s)" column between Response and Time (ms) in `display_results_table` — shows the integer TTL or "-" for errors and `None` values
- Added the same "TTL (s)" column to the propagation command's inline table with identical heading, justification, and fallback
- Preserved existing JSON and CSV output formats — both functions manually construct output rows without `dataclasses.asdict`, so the new `ttl` field is never surfaced in those paths

### Key decisions
- Store TTL as a single `int | None` field on `DNSResult` rather than a parallel list — all records in a DNS RRset share one TTL value
- Modify only `query_dns`, not `query_dns_simple` or `query_doh` — only `query_dns` feeds the two target tables
- JSON and CSV outputs manually construct output dicts/rows without `dataclasses.asdict`, so the new ttl field is never exposed in those formats

### Changes by phase
- **Phase 1: Add TTL column to query and propagation tables** — Added `ttl: int | None = None` to `DNSResult`. Captured TTL from `answers.rrset.ttl` in `query_dns` success path with `None` guard. Added right-justified "TTL (s)" column in `display_results_table` and the propagation table. JSON and CSV outputs unchanged (both build rows manually). 32/32 tests passed, zero new ruff warnings, zero new mypy errors.

## Verification

- Production build: PASS — `pyproject-build` produced `dnsmenace-3.0.0.tar.gz` and `dnsmenace-3.0.0-py3-none-any.whl` successfully
- Review approved: 2026-06-20T21:38:59Z — 7/7 acceptance criteria, ruff and mypy clean on changed lines
- Code committed: `4617efd feat(task-add-ttl-display-to-query-and-01kvkdasb8ts): phase 1 — Add TTL column to query and propagation tables`
- Branch pushed: `feature/task-add-ttl-display-to-query-and-01kvkdasb8ts` pushed to `origin` successfully
