---
id: bli-add-min-reliability-2
rawText: ''
title: Add --min-reliability filter to the query command
type: improvement
module: dnsmenace.py
labels:
- starter
groomingStatus: completed
createdAt: 2026-06-19T19:08:39Z
groomedAt: 2026-06-19T19:08:39Z
promotedTaskId: task-add-min-reliability-filter-to-the-query-01kvhdrbsx1z
---

Wire the `reliability` field already returned by `fetch_nameservers` into the `query` command by adding a `--min-reliability` option (e.g. `--min-reliability 0.8`) that filters out low-quality servers before queries run.
The reliability score is fetched from public-dns.info but never used, so queries against unreliable servers silently time out and inflate failure counts — filtering them upfront would reduce noise and speed up results.
