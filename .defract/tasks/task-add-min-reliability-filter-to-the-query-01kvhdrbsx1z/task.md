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
