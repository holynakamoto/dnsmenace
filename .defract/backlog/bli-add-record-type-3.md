---
id: bli-add-record-type-3
rawText: ''
title: Add record type support to the brute subdomain command
type: improvement
module: dnsmenace.py
labels: []
groomingStatus: completed
createdAt: 2026-06-19T19:08:39Z
groomedAt: 2026-06-19T19:08:39Z
---

Add a `--type` / `-t` option to the `brute` command (mirroring other commands) so users can enumerate subdomains by record type beyond A — for example MX or CNAME — and update the results table to show the queried type.
The current hardcoded A-only lookup misses mail servers, CDN CNAMEs, and other common subdomain patterns that only resolve under other record types, limiting the usefulness of the enumeration for thorough recon.
