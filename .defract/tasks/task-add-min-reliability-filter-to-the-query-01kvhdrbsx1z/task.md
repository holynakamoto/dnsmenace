---
defract:
  id: task-add-min-reliability-filter-to-the-query-01kvhdrbsx1z
  type: improvement
  status: active
  stage: implementation
  phase: 0
  total_phases: 1
  priority: normal
  source: backlog
  source_id: bli-add-min-reliability-2
  branch_strategy: worktree
  mode: human-in-the-loop
  created_by: holynakamoto
  assignee: holynakamoto
---


## Story Brief

Promoted from backlog item `bli-add-min-reliability-2`.

- Module: dnsmenace.py
- Labels: starter

Original paste from the builder:

> Wire the `reliability` field already returned by `fetch_nameservers` into the `query` command by adding a `--min-reliability` option (e.g. `--min-reliability 0.8`) that filters out low-quality servers before queries run.
> The reliability score is fetched from public-dns.info but never used, so queries against unreliable servers silently time out and inflate failure counts — filtering them upfront would reduce noise and speed up results.

# Add --min-reliability filter to the query command

# Add --min-reliability filter to the query command

## What We're Building

The `query` command gains an optional `--min-reliability` flag (e.g. `--min-reliability 0.8`) that pre-filters the DNS server list before any queries run. Servers below the threshold are dropped from the pool, so only servers that public-dns.info considers reliable are queried. The reliability score is already returned by the nameserver fetch step but has never been used — this wires it in.

## Expected Outcome

- Running `query` without `--min-reliability` behaves exactly as today — no disruption to existing workflows.
- Passing `--min-reliability 0.8` limits the server pool to servers with a reliability score at or above the specified value.
- Query runs finish faster and report fewer failures because low-quality servers that silently time out are excluded upfront.
- When the filter reduces the server pool to zero, the user sees a clear message explaining why no queries ran rather than a confusing empty result.

## Phase Outcomes

- **Phase 1: Wire reliability filtering into the query command** — Users querying DNS servers from a given country can now pass `--min-reliability` to skip unreliable servers before any queries run, reducing timeout noise and returning cleaner results faster.

## Out of Scope

- Applying reliability filtering to commands other than `query` (e.g. `geo-diff`, `propagation`, `watch`) — each command can be addressed separately if wanted.
- Persisting a default reliability threshold in a config file or environment variable — the flag must be passed explicitly each run.
- Changing how reliability scores are fetched, computed, or cached — the existing fetch logic is untouched.

## Scope Summary

**Size:** 4 requirements, 5 acceptance criteria, 1 implementation phase
**Key decisions:**
- Filter is applied after `fetch_nameservers` returns, not inside it — the fetch signature and `--limit` semantics are unchanged.
- The threshold comparison is inclusive (`>=`), so `--min-reliability 1.0` passes servers scored exactly 1.0.
- The zero-pool error message names the threshold and the number of servers checked so the user knows how to adjust.
**Biggest risk:** `--limit` caps how many servers are fetched before reliability filtering runs — users may get very few results if their limit is low and the threshold is high. Worth noting in help text.

## Context

`NameServer` already carries a `reliability: float` field (populated from the `reliability` key in each public-dns.info record at `dnsmenace.py:191`). The `query` command fetches nameservers via `fetch_nameservers` (lines 634-638), checks for an empty list (line 640), then passes the full list to `run_dns_queries` (line 648) with no filtering in between. The filtering logic belongs in that gap. No other commands are in scope.

## Requirements

### CLI option

- R1: The `query` command accepts an optional `--min-reliability` option taking a `float` in `[0.0, 1.0]`. When omitted, no filtering is applied and behaviour is identical to today.
- R2: The option must carry a help string that mentions the 0–1 range, the effect on the server pool, and the interaction with `--limit` (i.e. filtering applies after `--limit` caps the fetch).

### Filtering logic

- R3: After `fetch_nameservers` returns and before `run_dns_queries` is called, nameservers with `reliability < min_reliability` are excluded from the pool. The comparison is inclusive at the threshold (servers scoring exactly at the threshold are kept).
- R4: When the filtered pool is empty, the command prints a user-facing message that names the threshold and the count of servers that were checked, then exits with a non-zero code. (`dnsmenace.py:640-642` shows the existing empty-list pattern to follow.)

## Acceptance Criteria

- [ ] `dnsmenace query -c US -d example.com` (no flag) produces identical output to today — confirmed by manual run and diff against baseline.
- [ ] `dnsmenace query -c US -d example.com --min-reliability 0.9` only queries nameservers whose `reliability` field is 0.9 or higher; verified by inserting a `console.print` of the filtered list during a local run (removed before commit) or checking that reported server IPs correspond to high-reliability entries in the public-dns.info JSON response.
- [ ] `dnsmenace query -c US -d example.com --min-reliability 1.1` (impossible threshold) prints a message containing the threshold value and server count, exits cleanly with code 1.
- [ ] `ruff check dnsmenace.py` reports zero errors.
- [ ] `mypy dnsmenace.py` reports zero errors in strict mode.

## Implementation Phases

### Phase 1: Wire reliability filtering into the query command
**Scope:** Add `--min-reliability` as an optional `float` parameter to the `query` function with a `None` default (meaning no filtering). After `fetch_nameservers` returns its list, filter it when the option is set, and add an informative exit path when the filtered pool is empty.
**Files:**
- `dnsmenace.py` — add `min_reliability: Annotated[float | None, typer.Option(...)] = None` parameter to `query`, insert filtering block between the `fetch_nameservers` call (line 638) and the empty-list check (line 640), update the empty-list check to distinguish between "no servers found for this country" and "all servers filtered out by reliability threshold".
**Verification:**
- `ruff check dnsmenace.py` passes with zero issues.
- `mypy dnsmenace.py` passes in strict mode.
- Manual run: `dnsmenace query -c US -d example.com` matches pre-change behaviour.
- Manual run: `dnsmenace query -c DE -d example.com --min-reliability 0.9` runs without error and the summary line shows a server count equal to or less than the unfiltered count.
- Manual run with impossible threshold (e.g. `--min-reliability 1.1`): prints the threshold and checked-server count, exits with code 1.
**Estimated effort:** Small

## Edge Cases

- **All fetched servers are unreliable**: filtered pool is empty — show threshold + checked-count message and exit 1.
- **`--min-reliability 0.0`**: passes all servers (equivalent to no flag); no special handling needed.
- **`--min-reliability 1.0`**: servers scored exactly 1.0 pass (inclusive); servers scored 0.999… do not.
- **`--limit` interaction**: `--limit` caps the fetch before filtering — the user may need to raise `--limit` to find enough high-reliability servers. The help text should note this.
- **Machine-readable output (`--output json` or `--output csv`) with zero results after filtering**: exit code 1 and a message to stderr, no partial JSON/CSV output.

## Technical Notes

Follow the existing `Annotated[..., typer.Option(...)]` parameter style used throughout the `query` function. The `min` validator on `--limit` shows how to apply range constraints via Typer — add `min=0.0, max=1.0` on `--min-reliability` to let Typer validate the range and surface a clean error automatically.

The filtering block should sit between the `fetch_nameservers` call (line 638) and the existing empty-list guard (line 640). Reuse the existing `console.print(...) / raise typer.Exit(1)` pattern for the zero-pool error path.

The `reliability` field is already a `float` on `NameServer` (line 82), so the comparison `ns.reliability >= min_reliability` is type-safe with no casting needed.

## Implementation Notes

## Phase 1: Wire reliability filtering into the query command

**Files changed:** `dnsmenace.py`

**What was built:**

1. Added `min_reliability: Annotated[float | None, typer.Option("--min-reliability", min=0.0, max=1.0, ...)] = None` parameter to the `query` command. Typer enforces the 0.0–1.0 range automatically and returns a clean error for out-of-range values.

2. Added filtering block between the `fetch_nameservers` call and the "Found N nameservers" display line. When `min_reliability` is set, nameservers with `reliability < min_reliability` are dropped. If the filtered pool is empty, a message naming the threshold and the count of servers checked is printed and the command exits with code 1.

**Deviations from plan:** None. The help text notes the `--limit`-first interaction as specified. The threshold comparison is inclusive (`>=`) per the scope decision.

**Pre-existing lint/type issues:** ruff reports 39 and mypy reports 29 pre-existing errors. Zero new errors were introduced by this change (all errors fall outside lines 603–670).

## Review

## Verdict

**Verdict:** REQUEST CHANGES
**Files reviewed:** 1 files changed across 1 phases

The filtering logic at dnsmenace.py:658-666 is correct. Three ACs fail: AC-3's test uses 1.1 which Typer intercepts as out-of-range (exit 2, no server count) before the custom R4 message fires; AC-4 and AC-5 report 39+29 pre-existing errors — none in the changed range.

### Automated Checks

| Check | Result | Details |
|-------|--------|---------|
| Python syntax | PASS | dnsmenace.py compiles cleanly with no syntax errors |
| CLI help output | PASS | --min-reliability appears with FLOAT RANGE [0.0<=x<=1.0] and correct help text describing the 0-1 range and --limit interaction |
| Ruff lint | FAIL | 39 errors — all confirmed pre-existing (master baseline has same errors at line numbers 25 lines lower before insertion); 0 new errors in changed range dnsmenace.py:606-666 |
| Mypy strict | FAIL | 29 errors — all confirmed pre-existing (master baseline carries same errors at shifted line numbers); 0 new errors in changed range dnsmenace.py:606-666 |

### Acceptance Criteria (2/5 passed)

- [x] AC-1: `dnsmenace query -c US -d example.com` (no flag) produces identical output to today — confirmed by manual run and diff against baseline. — PASS: dnsmenace.py:658 — filtering block is guarded by `if min_reliability is not None`; when the flag is omitted, this block is skipped entirely and the code path from fetch_nameservers through run_dns_queries is unchanged
- [x] AC-2: `dnsmenace query -c US -d example.com --min-reliability 0.9` only queries nameservers whose `reliability` field is 0.9 or higher; verified by inserting a `console.print` of the filtered list during a local run (removed before commit) or checking that reported server IPs correspond to high-reliability entries in the public-dns.info JSON response. — PASS: dnsmenace.py:660 — `nameservers = [ns for ns in nameservers if ns.reliability >= min_reliability]`; inclusive `>=` comparison is correct per scope decision; NameServer.reliability is already a float (dnsmenace.py:82), so the comparison is type-safe
- [ ] AC-3: `dnsmenace query -c US -d example.com --min-reliability 1.1` (impossible threshold) prints a message containing the threshold value and server count, exits cleanly with code 1. — FAIL: Typer test runner: invoking query with --min-reliability 1.1 exits with code 2 and message 'Invalid value for --min-reliability: 1.1 is not in the range 0.0<=x<=1.0' — no server count appears. The custom R4 empty-pool message at dnsmenace.py:661-666 only fires for within-range thresholds that still produce an empty pool; Typer's range validator intercepts 1.1 before the command body runs.
- [ ] AC-4: `ruff check dnsmenace.py` reports zero errors. — FAIL: ruff check dnsmenace.py: 39 errors. Baseline comparison confirms all errors are pre-existing: master carries the same errors at lower line numbers (e.g. master:622 = branch:636 after 25-line insertion). Zero new errors in changed range 606-666.
- [ ] AC-5: `mypy dnsmenace.py` reports zero errors in strict mode. — FAIL: mypy dnsmenace.py: 29 errors, all at lines 1876-2187 — entirely outside the changed range 606-666. Baseline comparison confirms these existed in master. Zero new errors introduced.

### Code Quality (Refactor Review)

No code quality issues found in changed files.

### Security Assessment (Security Review)

No security issues found in changed files.

### Decisions Made During Implementation

- Filter applied post-fetch, not inside fetch_nameservers — preserves shared function signature and keeps --limit semantics unchanged across all callers
- Threshold comparison is inclusive (>=) — --min-reliability 0.8 means 'at least 0.8'; exclusive would silently drop servers scored exactly at the stated threshold
- Typer min=0.0, max=1.0 range validation — rejects out-of-range values (like 1.1) at the CLI layer before the command body runs, producing Typer's standard range error (exit 2) rather than the custom empty-pool message

## Headline Findings

- **critical** — AC-3's test scenario uses --min-reliability 1.1 which Typer rejects as out-of-range (exit 2, no server count) before the custom R4 empty-pool message can fire; the requirement's intended behavior is implemented but its acceptance test is miscalibrated. See `### Acceptance Criteria`.
- **recommended** — 39 ruff and 29 mypy pre-existing errors block AC-4 and AC-5; none were introduced by this change, but a dedicated cleanup task would prevent them from failing future reviews. See `### Automated Checks`.

## Required Changes

**Blocking**

- dnsmenace.py: verify the R4 empty-pool path with a live run using a within-range threshold that filters all servers (e.g. --min-reliability 1.0) — confirm exit code 1 and message naming threshold + server count; update AC-3 to document both behaviors: Typer rejects out-of-range 1.1 (exit 2), within-range high threshold produces the custom message (exit 1)

**Recommended**

- dnsmenace.py: create a follow-up backlog item to address the 39 ruff and 29 mypy pre-existing errors so AC-4 and AC-5 can pass; optionally relabel them 'zero new errors introduced' until cleanup is done


