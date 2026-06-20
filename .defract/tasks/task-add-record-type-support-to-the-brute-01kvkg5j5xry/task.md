---
defract:
  id: task-add-record-type-support-to-the-brute-01kvkg5j5xry
  type: improvement
  status: active
  stage: release
  phase: 0
  total_phases: 1
  priority: normal
  source: backlog
  source_id: bli-add-record-type-3
  branch_strategy: worktree
  mode: human-in-the-loop
  created_by: holynakamoto
  assignee: holynakamoto
---


## Story Brief

Promoted from backlog item `bli-add-record-type-3`.

- Module: dnsmenace.py

Original paste from the builder:

> Add a `--type` / `-t` option to the `brute` command (mirroring other commands) so users can enumerate subdomains by record type beyond A — for example MX or CNAME — and update the results table to show the queried type.
> The current hardcoded A-only lookup misses mail servers, CDN CNAMEs, and other common subdomain patterns that only resolve under other record types, limiting the usefulness of the enumeration for thorough recon.

# Add record type support to the brute subdomain command

# Add record type support to the brute subdomain command

## What We're Building

The `brute` subdomain enumeration command currently queries only A records, which misses mail servers, CDN aliases, and other subdomain patterns that only resolve under different record types. We are adding a `--type` option so users can enumerate subdomains using any DNS record type — for example MX or CNAME — and see the queried type reflected in the results table.

## Expected Outcome

- Users can pass `--type MX` (or `-t MX`) to the `brute` command to enumerate subdomains using a specific record type
- The results table shows the queried record type alongside each discovered subdomain
- When no type is specified, the command defaults to A records, preserving existing behavior
- The option mirrors the `--type` convention already used on other commands in the tool

## Phase Outcomes

- **Phase 1: Add `--type` option to brute enumeration** — Users can specify any DNS record type when bruteforcing subdomains. The results table reflects the queried type, and all output formats (table, JSON, CSV) include the record type in their output.

## Out of Scope

- Querying multiple record types in a single `brute` invocation (parallel multi-type enumeration is a separate enhancement)
- Adding `--type` support to commands other than `brute`
- Changes to the subdomain wordlist or any other enumeration logic beyond the record type lookup

## Scope Summary

**Size:** 6 requirements, 6 acceptance criteria, 1 implementation phase
**Key decisions:**
- Single `RecordType` parameter (not list) — multi-type is explicitly out of scope
- Column header "IP Address(es)" renamed to "Records" to be type-agnostic
- `record_type` captured as a closure variable by `check_one` — no refactor of the inline DNS logic needed
**Biggest risk:** MX and CNAME answers are formatted differently from A records (e.g., MX includes priority); the existing `str(rdata)` serialisation via dnspython should handle this but needs verification.

## Context

The `brute` command (`dnsmenace.py:1634–1810`) performs subdomain enumeration using a batch async loop. Its inner `check_one` closure hardcodes `"A"` in two places: the DoH path (`query_doh(provider, fqdn, RecordType.A)` at line ~1747) and the standard resolver path (`resolver.resolve(fqdn, "A")` at line ~1756). All other major commands — `query` (line 589), `compare` (line 709), `propagation` (line 1338), and `doh` (line 1533) — already expose `--type` / `-t` via `Annotated[RecordType, typer.Option(...)]` with a default of `RecordType.A`. The `RecordType` enum is already defined and covers all standard DNS record types. The results table currently has two columns: Subdomain and IP Address(es); JSON and CSV outputs use `addresses` as the key name.

## Requirements

### CLI Parameter

- R1: The `brute` command accepts a `--type` / `-t` option that takes a `RecordType` value, defaulting to `RecordType.A`. The declaration follows the `Annotated[RecordType, typer.Option("--type", "-t", help="DNS record type to query")]` pattern used by `compare` and `propagation`.

### DNS Query Logic

- R2: The `check_one` closure captures `record_type` from the outer `brute` scope and uses it instead of the hardcoded `RecordType.A` (DoH path) and `"A"` (resolver path) literals.
- R3: Both query paths — DoH (`query_doh`) and standard resolver (`resolver.resolve`) — use the parameterised record type.

### Display

- R4: The results table column header "IP Address(es)" is renamed to "Records" to be type-agnostic.
- R5: The results table title includes the queried record type (e.g., `Discovered Subdomains for example.com (MX)`).

### Output Formats

- R6: JSON output includes a `"type"` field alongside `"subdomain"` and `"addresses"` containing the record type string (e.g., `"MX"`). CSV output includes a `"type"` column.

## Acceptance Criteria

- [ ] Running `dnsmenace brute example.com --type MX` (or `-t MX`) executes without error and queries MX records for each subdomain candidate.
- [ ] Running `dnsmenace brute example.com` with no `--type` queries A records, preserving existing behavior.
- [ ] The results table title contains the record type string (e.g., "MX") when `--type MX` is used.
- [ ] The results table column formerly labelled "IP Address(es)" is now labelled "Records".
- [ ] JSON output includes `"type": "MX"` (or whichever type was queried) on each result object.
- [ ] CSV output includes a `"type"` column.

## Implementation Phases

### Phase 1: Add --type option to the brute command
**Scope:** Add the `record_type` parameter to the `brute` function signature, thread it through the `check_one` closure, and update all output paths (table, JSON, CSV) to reflect the queried type.
**Files:**
- `dnsmenace.py` — modify the `brute` function (lines 1634–1810): add parameter, update `check_one` closure, rename table column, update table title, update JSON and CSV output schemas
**Verification:**
- `dnsmenace brute <real-domain> --type MX` runs without error and queries MX records
- `dnsmenace brute <real-domain>` still defaults to A records
- Table title includes the record type string
- Table column header reads "Records" not "IP Address(es)"
- `dnsmenace brute <real-domain> --output json` output includes `"type"` field on each result
- `dnsmenace brute <real-domain> --output csv` output includes `"type"` column
- `ruff check dnsmenace.py` passes
- `mypy dnsmenace.py` passes
**Estimated effort:** Small

## Edge Cases

- MX records include a priority integer in their `str()` representation (e.g., `"10 mail.example.com"`): dnspython's `str(rdata)` handles this — no special-casing needed.
- CNAME records return a target domain name, not an IP address: the column rename to "Records" already accommodates this.
- No subdomains resolve for the queried type: the existing "No subdomains discovered" message handles this — no change needed.
- An invalid record type string is passed via `--type`: Typer and the `RecordType` enum reject it before the command runs, consistent with other commands.

## Technical Notes

`check_one` is a closure defined inside `run_brute`, which is itself defined inside `brute`. The new `record_type` parameter on `brute` is accessible to `check_one` via closure without any change to `check_one`'s own signature. Use `record_type` (the enum value) when calling `query_doh`, and `record_type.value` (the string) when calling `resolver.resolve` — matching the pattern in `query_dns_simple` (`dnsmenace.py:243`).

The `query_dns_simple` helper at line 243 already accepts `record_type: str`. The `brute` command does not use it (it inlines the resolver logic); no refactor of that approach is needed — just parameterise the existing inline code.

## Implementation Notes

## Phase 1: Add --type option to the brute command

**Files changed:** `dnsmenace.py`

**Changes made:**

1. Added `record_type: Annotated[RecordType, typer.Option("--type", "-t", help="DNS record type to query")] = RecordType.A` parameter to the `brute` function (between the `country` and `output` parameters), matching the pattern used by `compare` and `propagation` commands.

2. Updated `check_one` closure to use `record_type` (enum value) for the DoH path (`query_doh`) and `record_type.value` (string) for the resolver path (`resolver.resolve`), replacing the two hardcoded literals `RecordType.A` and `"A"`.

3. Renamed table column from `"IP Address(es)"` to `"Records"` — type-agnostic label that works for MX, CNAME, A, and all other record types.

4. Updated table title to `f"Discovered Subdomains for {domain} ({record_type.value})"` — shows queried type in parentheses.

5. Updated JSON output: `{"subdomain": fqdn, "addresses": ips, "type": record_type.value}` — adds `"type"` field alongside existing fields.

6. Updated CSV header row to `["subdomain", "addresses", "type"]` and each data row to include `record_type.value` as the third column.

**No deviations from plan.** All 32 pre-existing tests pass; no new ruff or mypy issues introduced.

## Review

## Verdict

**Verdict:** APPROVE
**Files reviewed:** 1 files changed across 1 phases

All six acceptance criteria are satisfied: `--type`/`-t` is wired up, both query paths use the parameterised type, the table title and column are updated, and JSON/CSV carry the `type` field. 32/32 tests pass; no new ruff or mypy errors introduced.

### Automated Checks

| Check | Result | Details |
|-------|--------|---------|
| Pytest (32 scenarios) | PASS | 32/32 passed in 103s |
| Ruff lint | FAIL | 39 errors — all pre-existing (identical count on master branch); zero new errors from this task's changes |
| Mypy type check | FAIL | 29 errors — all pre-existing (identical count on master branch); zero new errors from this task's changes |

### Acceptance Criteria (6/6 passed)

- [x] AC-1: Running `dnsmenace brute example.com --type MX` (or `-t MX`) executes without error and queries MX records for each subdomain candidate. — PASS: dnsmenace.py:1661-1667 declares `typer.Option("--type", "-t")` with `RecordType` type. DoH path at line 1754 passes `record_type` to `query_doh`; resolver path at line 1763 passes `record_type.value` to `resolver.resolve`. Closure captures `record_type` from brute scope correctly.
- [x] AC-2: Running `dnsmenace brute example.com` with no `--type` queries A records, preserving existing behavior. — PASS: dnsmenace.py:1667 sets `= RecordType.A` as the default. test_S30 runs `brute google.com --doh` (no `--type`) and passes, confirming default A behavior is preserved.
- [x] AC-3: The results table title contains the record type string (e.g., "MX") when `--type MX` is used. — PASS: dnsmenace.py:1792 sets table title to `f"Discovered Subdomains for {domain} ({record_type.value})"`. When `--type MX`, `record_type.value` is `"MX"`, producing `"Discovered Subdomains for example.com (MX)"`.
- [x] AC-4: The results table column formerly labelled "IP Address(es)" is now labelled "Records". — PASS: dnsmenace.py:1799 calls `table.add_column("Records", style="green")`. The old label `"IP Address(es)"` is gone from the diff.
- [x] AC-5: JSON output includes `"type": "MX"` (or whichever type was queried) on each result object. — PASS: dnsmenace.py:1806-1809 builds each entry as `{"subdomain": fqdn, "addresses": ips, "type": record_type.value}`. The `"type"` key is present alongside `"subdomain"` and `"addresses"`.
- [x] AC-6: CSV output includes a `"type"` column. — PASS: dnsmenace.py:1814 writes header `["subdomain", "addresses", "type"]`. dnsmenace.py:1816 writes each row as `[fqdn, "|".join(ips), record_type.value]`, adding the type value as the third column.

### Code Quality (Refactor Review)

No code quality issues found in changed files.

### Security Assessment (Security Review)

No security issues found in changed files.

### Decisions Made During Implementation

- Use singular RecordType parameter (not list) for brute --type option — multi-type enumeration is explicitly out of scope.
- Rename table column to "Records" and include record type in table title — type-agnostic label that works for MX (priority+hostname), CNAME (domain), A (IP), and all other record types.
- record_type captured as closure variable by check_one — no refactor of inline DNS logic needed, matching existing pattern.

## Required Changes

None.

