# Design System

## Overview

DNSMenace is a Python CLI tool with no web frontend, CSS, or browser-based styling. The visual design is entirely driven by the [Rich](https://github.com/Textualize/rich) terminal UI library (v13+), used via [Typer](https://typer.tiangolo.com/) with `rich_markup_mode="rich"`. All color, layout, and component conventions are Rich terminal markup — not CSS or design tokens in the traditional sense.

## Colors

### Semantic Color Roles

| Role | Rich Color | Usage |
|------|-----------|-------|
| Primary accent | `cyan` | Nameserver names, country names, DoH progress, section headers |
| Header | `bold magenta` | Table column headers |
| Record type | `yellow` | DNS record type column, warning states |
| Success / response | `green` | DNS response data, found counts, consistent results |
| Timing / info | `blue` | Latency/timing column, info status icons |
| Error | `red` | Network errors, invalid input, failed queries, vulnerability alerts |
| De-emphasized | `dim` | IP addresses, secondary metadata, footers, details |
| Neutral | `white` | General field values |

### Status Color Map

| Status | Color | Icon |
|--------|-------|------|
| pass | `green` | ✓ |
| warn | `yellow` | ! |
| fail | `red` | ✗ |
| info | `blue` | ℹ |

### Panel Border Colors

| Context | Border Style |
|---------|-------------|
| Success / consistent result | `green` |
| Warning / discrepancy detected | `yellow` |
| Security vulnerability | `red` |

## Components

### Organization

All UI components are defined inline in `dnsmenace.py` using Rich primitives. There is no separate component library or directory.

### Component Count

Single-file application — all rendering logic is in `dnsmenace.py`.

### Key Components Used

- **Table** (`box.ROUNDED`) — primary data display for DNS results, reverse DNS, propagation checks
- **Table** (`box.SIMPLE`) — secondary info tables, similarity matrix, field/value pairs
- **Panel** — result summary callouts (success, warning, vulnerability alerts)
- **Progress** — async query progress with `SpinnerColumn`, `BarColumn`, `TextColumn`, `TaskProgressColumn`
- **Live** — real-time result streaming during concurrent queries
- **Tree** — hierarchical data display
- **Columns** — multi-column layout
- **Text** — inline styled text objects for mixed-style table cells

## Conventions

### Styling Approach

- Framework: Rich terminal markup (`[color]...[/color]`, `[bold]...[/bold]`)
- File pattern: single-file, all rendering inline in `dnsmenace.py`
- Naming: Rich markup tags (not CSS class names)
- No CSS, no SCSS, no Tailwind, no CSS-in-JS, no design tokens file

### Banner

The ASCII art banner uses `[bold cyan]` markup. Subtitle uses `[dim]`.

### Table Style

All primary tables use `box.ROUNDED` with `header_style="bold magenta"`. Info/detail tables use `box.SIMPLE` with `show_header=False` where appropriate.

### Accessibility

- Rich respects `NO_COLOR` environment variable and terminal color support detection automatically
- No reduced-motion or focus style handling (terminal context, not browser)
- Error states always include descriptive text alongside color indicators
