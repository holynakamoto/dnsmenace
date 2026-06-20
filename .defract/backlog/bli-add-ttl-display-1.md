---
id: bli-add-ttl-display-1
rawText: ''
title: Add TTL display to query and propagation result tables
type: improvement
module: dnsmenace.py
labels: []
groomingStatus: completed
createdAt: 2026-06-19T19:08:39Z
groomedAt: 2026-06-19T19:08:39Z
promotedTaskId: task-add-ttl-display-to-query-and-01kvkdasb8ts
---

Extend the DNS query functions to capture and surface TTL values alongside each answer, adding a TTL column to the table output in `display_results_table` and the propagation command.
TTL is one of the most useful pieces of data for diagnosing caching issues and stale records, but it is currently stripped when answers are converted to strings — exposing it would make the tool noticeably more useful for its target audience.
