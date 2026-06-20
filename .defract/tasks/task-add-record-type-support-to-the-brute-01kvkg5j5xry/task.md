---
defract:
  id: task-add-record-type-support-to-the-brute-01kvkg5j5xry
  type: improvement
  status: active
  stage: scope
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

## What We're Building

The `brute` subdomain enumeration command currently queries only A records, which misses mail servers, CDN aliases, and other subdomain patterns that only resolve under different record types. We are adding a `--type` option so users can enumerate subdomains using any DNS record type — for example MX or CNAME — and see the queried type reflected in the results table.

## Expected Outcome

- Users can pass `--type MX` (or `-t MX`) to the `brute` command to enumerate subdomains using a specific record type
- The results table shows the queried record type alongside each discovered subdomain
- When no type is specified, the command defaults to A records, preserving existing behavior
- The option mirrors the `--type` convention already used on other commands in the tool

## Out of Scope

- Querying multiple record types in a single `brute` invocation (parallel multi-type enumeration is a separate enhancement)
- Adding `--type` support to commands other than `brute`
- Changes to the subdomain wordlist or any other enumeration logic beyond the record type lookup
