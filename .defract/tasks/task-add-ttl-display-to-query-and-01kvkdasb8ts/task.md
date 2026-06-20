---
defract:
  id: task-add-ttl-display-to-query-and-01kvkdasb8ts
  type: improvement
  status: active
  stage: scope
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

## What We're Building

DNS records carry a Time-To-Live (TTL) value that tells resolvers and clients how long to cache a response. This value is currently discarded when the tool formats answers for display. We are adding TTL capture and display to the two main result tables — the standard query output and the propagation check — so that security researchers and network administrators can see cache lifetimes alongside each answer.

## Expected Outcome

- Running a DNS query shows a TTL column in the results table next to each answer
- Running a propagation check shows a TTL column alongside each DNS provider's response
- TTL values are displayed as whole seconds, matching the raw DNS wire format
- Results with errors show a dash in the TTL column rather than crashing
- The existing JSON and CSV output formats are not changed by this work

## Out of Scope

- Adding TTL to JSON or CSV output formats — those formats may be consumed by scripts and a format change requires a separate decision
- TTL-based filtering, sorting, or alerting on results
- Any changes to the live monitoring or watch command
