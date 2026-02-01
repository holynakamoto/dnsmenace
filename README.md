# DNSMenace

```
    ____  _   _______ __  ___
   / __ \/ | / / ___//  |/  /__  ____  ____ _________
  / / / /  |/ /\__ \/ /|_/ / _ \/ __ \/ __ `/ ___/ _ \
 / /_/ / /|  /___/ / /  / /  __/ / / / /_/ / /__/  __/
/_____/_/ |_//____/_/  /_/\___/_/ /_/\__,_/\___/\___/
```

**Query DNS servers from any country in the world.**

A powerful CLI tool for security researchers, network administrators, and anyone interested in exploring global DNS infrastructure. Query nameservers by country, compare responses across different regions, and export results in multiple formats.

## Features

- **Global DNS Queries**: Query DNS servers from 200+ countries using two-letter country codes
- **Multiple Record Types**: Support for A, AAAA, MX, TXT, NS, CNAME, SOA, and PTR records
- **Async Performance**: Concurrent queries with progress bars for fast results
- **Beautiful Output**: Rich terminal UI with colored tables and formatted output
- **Export Formats**: Output results as tables, JSON, or CSV
- **Server Discovery**: Browse available DNS servers by country with reliability scores

## Installation

### Using pip

```bash
pip install .
```

### Using uv (recommended)

```bash
uv pip install .
```

### Development install

```bash
# Clone the repo
git clone https://github.com/holynakamoto/dnsmenace.git
cd dnsmenace

# Install with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```bash
# Query US DNS servers for google.com
dnsmenace query -c US -d google.com

# Query German servers for A and MX records
dnsmenace query -c DE -d example.com -t A -t MX

# Export results as JSON
dnsmenace query -c JP -d cloudflare.com -o json

# List all available country codes
dnsmenace countries-list

# Search for a specific country
dnsmenace countries-list --search germany

# Look up a country code
dnsmenace lookup "United States"

# List DNS servers in a country
dnsmenace servers JP --limit 10
```

## Commands

### `query`

Query DNS servers from a specific country.

```bash
dnsmenace query [OPTIONS]

Options:
  -c, --country TEXT     Two-letter country code (e.g., US, DE, JP) [required]
  -d, --domain TEXT      Domain name to query (FQDN) [required]
  -t, --type TYPE        DNS record type (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR)
                         Can be specified multiple times [default: A]
  -l, --limit INTEGER    Maximum number of nameservers to query [default: 5]
  -o, --output FORMAT    Output format: table, json, csv [default: table]
```

**Examples:**

```bash
# Basic query
dnsmenace query -c US -d google.com

# Multiple record types
dnsmenace query -c DE -d example.com -t A -t AAAA -t MX

# Query more servers and export as JSON
dnsmenace query -c JP -d cloudflare.com -l 10 -o json

# Export as CSV for analysis
dnsmenace query -c GB -d bbc.com -o csv > results.csv
```

### `countries-list`

List all available country codes.

```bash
dnsmenace countries-list [OPTIONS]

Options:
  -s, --search TEXT    Search for a country by name
```

**Examples:**

```bash
# List all countries
dnsmenace countries-list

# Search for countries
dnsmenace countries-list --search japan
dnsmenace countries-list -s united
```

### `lookup`

Look up a country code by name.

```bash
dnsmenace lookup COUNTRY_NAME
```

**Examples:**

```bash
dnsmenace lookup Germany
dnsmenace lookup "United States"
dnsmenace lookup japan
```

### `servers`

List available DNS servers for a country.

```bash
dnsmenace servers COUNTRY [OPTIONS]

Options:
  -l, --limit INTEGER    Maximum number of servers to show [default: 20]
```

**Examples:**

```bash
dnsmenace servers US
dnsmenace servers JP --limit 10
dnsmenace servers DE -l 50
```

## Use Cases

### Security Research

Compare DNS responses across different countries to detect DNS-based censorship or geo-blocking:

```bash
# Check if a domain resolves differently in different countries
dnsmenace query -c CN -d google.com -o json > china.json
dnsmenace query -c US -d google.com -o json > usa.json
```

### Network Debugging

Verify DNS propagation across global nameservers:

```bash
# Check DNS propagation for your domain
dnsmenace query -c US -d yourdomain.com -t A -l 10
dnsmenace query -c EU -d yourdomain.com -t A -l 10
```

### Email Configuration

Verify MX records from different locations:

```bash
dnsmenace query -c US -d example.com -t MX -t TXT
```

## Requirements

- Python 3.11+
- Dependencies (automatically installed):
  - typer
  - rich
  - dnspython
  - httpx
  - iso3166
  - pydantic

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linting
ruff check .

# Run type checking
mypy dnsmenace.py

# Run tests
pytest
```

## License

MIT License

## Credits

DNS server data provided by [public-dns.info](https://public-dns.info).
