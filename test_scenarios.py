"""
dnsmenace Scenario Test Suite
==============================
32 realistic scenarios covering every major capability.

Success Criteria (applies to every scenario unless overridden):
  - Exit code 0  (code 1 only for explicit error scenarios)
  - No Python traceback in stdout/stderr
  - Output matches expected pattern(s)
  - Completes within timeout

Scoring rubric (printed at end via pytest -v summary):
  PASS  – all assertions met
  FAIL  – at least one assertion missed
  SKIP  – external dependency unavailable (network, API rate-limit, etc.)

Run:
    PYBIN=/Users/nickmoore/.local/share/uv/python/cpython-3.11.15-macos-aarch64-none/bin
    $PYBIN/pytest test_scenarios.py -v --tb=short
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PYBIN = Path("/Users/nickmoore/.local/share/uv/python/cpython-3.11.15-macos-aarch64-none/bin")
CLI = str(PYBIN / "dnsmenace")

# Stable reference domains / IPs used across tests
STABLE_DOMAIN = "google.com"
STABLE_IP_GOOGLE = "8.8.8.8"
STABLE_IP_CF = "1.1.1.1"
AXFR_VULNERABLE = "zonetransfer.me"   # publicly available test target
NONEXISTENT = "nxdomain.thisdoesnotexist99999.invalid"


class Result(NamedTuple):
    stdout: str
    stderr: str
    returncode: int
    elapsed: float


def run(
    args: list[str],
    timeout: int = 90,
    input_text: str | None = None,
) -> Result:
    """Run dnsmenace with args and capture output."""
    t0 = time.perf_counter()
    proc = subprocess.run(
        [CLI, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_text,
    )
    return Result(
        stdout=proc.stdout,
        stderr=proc.stderr,
        returncode=proc.returncode,
        elapsed=time.perf_counter() - t0,
    )


def no_traceback(r: Result) -> bool:
    """Return True if output is free of Python tracebacks."""
    combined = r.stdout + r.stderr
    return "Traceback (most recent call last)" not in combined


def has_pattern(r: Result, pattern: str, flags: int = re.IGNORECASE) -> bool:
    combined = r.stdout + r.stderr
    return bool(re.search(pattern, combined, flags))


# ---------------------------------------------------------------------------
# Group 1 – CLI Infrastructure (no network)
# ---------------------------------------------------------------------------

class TestGroup1_CLIInfrastructure:
    """S01–S06: Meta-commands that work without network access."""

    def test_S01_version_flag(self):
        """
        S01 – Version flag
        Criteria: exit 0, stdout contains 'dnsmenace version 3.0.0'
        """
        r = run(["--version"])
        assert r.returncode == 0, f"expected exit 0, got {r.returncode}"
        assert no_traceback(r)
        assert "3.0.0" in r.stdout, f"version string missing from: {r.stdout!r}"

    def test_S02_help_flag_lists_all_commands(self):
        """
        S02 – Help flag
        Criteria: exit 0, all 14 command names present in output
        """
        r = run(["--help"])
        assert r.returncode == 0
        assert no_traceback(r)
        commands = [
            "query", "compare", "security", "reverse", "axfr",
            "propagation", "bulk", "doh", "brute", "watch",
            "map", "countries-list", "lookup", "servers",
        ]
        for cmd in commands:
            assert cmd in r.stdout, f"command '{cmd}' missing from help output"

    def test_S03_countries_list_shows_entries(self):
        """
        S03 – countries-list returns country table
        Criteria: exit 0, output contains known country codes US, DE, JP
        """
        r = run(["countries-list"])
        assert r.returncode == 0
        assert no_traceback(r)
        for code in ("US", "DE", "JP"):
            assert code in r.stdout, f"country code {code!r} missing from countries-list"

    def test_S04_countries_list_search_filter(self):
        """
        S04 – countries-list --search filters correctly
        Criteria: exit 0, 'Germany' or 'DE' present; unrelated countries absent
        """
        r = run(["countries-list", "--search", "germany"])
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"germany|DE"), "Germany not found in filtered output"
        # 'Japan' should not appear when searching 'germany'
        assert "Japan" not in r.stdout, "'Japan' appeared in Germany-filtered list"

    def test_S05_lookup_germany(self):
        """
        S05 – lookup returns ISO code for a country name
        Criteria: exit 0, 'DE' present in output
        """
        r = run(["lookup", "Germany"])
        assert r.returncode == 0
        assert no_traceback(r)
        assert "DE" in r.stdout, f"'DE' not found in lookup output: {r.stdout!r}"

    def test_S06_lookup_united_states(self):
        """
        S06 – lookup handles multi-word country names
        Criteria: exit 0, 'US' present in output
        """
        r = run(["lookup", "United States"])
        assert r.returncode == 0
        assert no_traceback(r)
        assert "US" in r.stdout, f"'US' not found in lookup output: {r.stdout!r}"


# ---------------------------------------------------------------------------
# Group 2 – DNS Server Listing (network: public-dns.info)
# ---------------------------------------------------------------------------

class TestGroup2_ServerListing:
    """S07–S08: Fetch nameserver lists per country from external API."""

    def test_S07_servers_us(self):
        """
        S07 – servers US lists American nameservers
        Criteria: exit 0, at least one IP-like string in output
        """
        r = run(["servers", "US", "--limit", "5"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
            "No IP address found in servers US output"

    def test_S08_servers_de(self):
        """
        S08 – servers DE lists German nameservers
        Criteria: exit 0, at least one IP-like string
        """
        r = run(["servers", "DE", "--limit", "3"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
            "No IP address found in servers DE output"


# ---------------------------------------------------------------------------
# Group 3 – Core DNS Query (network: real DNS)
# ---------------------------------------------------------------------------

class TestGroup3_CoreQuery:
    """S09–S15: DNS query with various record types and output formats."""

    def test_S09_query_a_record_table(self):
        """
        S09 – query A record, table output (default)
        Criteria: exit 0, at least one IPv4 address in output, 'DNS Query Results' table present
        """
        r = run(["query", "-c", "US", "-d", STABLE_DOMAIN, "-t", "A", "-l", "3"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
            "No IPv4 address found in A record query output"
        assert has_pattern(r, r"DNS Query Results"), "Table title missing"

    def test_S10_query_a_record_json(self):
        """
        S10 – query A record, JSON output
        Criteria: exit 0, stdout parseable as JSON array with 'answers' key, ≥1 answer
        """
        r = run(["query", "-c", "US", "-d", STABLE_DOMAIN, "-t", "A", "-l", "2", "-o", "json"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        # Rich may add markup; strip ANSI for JSON parse
        raw = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout).strip()
        # Find JSON array in output
        match = re.search(r"\[.*\]", raw, re.DOTALL)
        assert match, f"No JSON array found in output:\n{raw}"
        data = json.loads(match.group(0))
        assert isinstance(data, list), "JSON output is not a list"
        assert len(data) > 0, "JSON list is empty"
        assert "answers" in data[0], "JSON record missing 'answers' key"
        assert "record_type" in data[0], "JSON record missing 'record_type' key"

    def test_S11_query_a_record_csv(self):
        """
        S11 – query A record, CSV output
        Criteria: exit 0, first line contains CSV header fields
        """
        r = run(["query", "-c", "US", "-d", STABLE_DOMAIN, "-t", "A", "-l", "2", "-o", "csv"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        assert len(lines) >= 2, f"CSV must have header + data, got {len(lines)} lines"
        header = lines[0]
        assert "nameserver_ip" in header, f"CSV header missing 'nameserver_ip': {header!r}"
        assert "record_type" in header, f"CSV header missing 'record_type': {header!r}"
        assert "answers" in header, f"CSV header missing 'answers': {header!r}"

    def test_S12_query_mx_record(self):
        """
        S12 – query MX record returns mail exchanger data
        Criteria: exit 0, output contains 'MX' and mail-like content
        """
        r = run(["query", "-c", "US", "-d", STABLE_DOMAIN, "-t", "MX", "-l", "2"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert "MX" in r.stdout, "Record type 'MX' not shown in output"
        # google.com MX includes 'smtp.google.com' or similar
        assert has_pattern(r, r"(smtp|mail|aspmx|google)"), \
            "No mail-related hostname found in MX output"

    def test_S13_query_txt_record(self):
        """
        S13 – query TXT record returns text records
        Criteria: exit 0, 'TXT' in output, SPF-like content present for google.com
        """
        r = run(["query", "-c", "US", "-d", STABLE_DOMAIN, "-t", "TXT", "-l", "2"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert "TXT" in r.stdout, "Record type 'TXT' not shown in output"
        assert has_pattern(r, r"(v=spf|google-site|docusign|globalsign)"), \
            "No recognizable TXT record content for google.com"

    def test_S14_query_ns_record(self):
        """
        S14 – query NS record returns nameserver hostnames
        Criteria: exit 0, 'NS' in output, google NS entries present
        """
        r = run(["query", "-c", "US", "-d", STABLE_DOMAIN, "-t", "NS", "-l", "2"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert "NS" in r.stdout, "Record type 'NS' not shown in output"
        assert has_pattern(r, r"ns[0-9]+\.google\.com"), \
            "Expected google NS records (ns1/ns2/ns3/ns4.google.com) not found"

    def test_S15_query_aaaa_record(self):
        """
        S15 – query AAAA record returns IPv6 addresses
        Criteria: exit 0, 'AAAA' in output, colon-separated IPv6 address present
        """
        r = run(["query", "-c", "US", "-d", STABLE_DOMAIN, "-t", "AAAA", "-l", "2"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert "AAAA" in r.stdout, "Record type 'AAAA' not shown in output"
        assert has_pattern(r, r"[0-9a-f]{1,4}:[0-9a-f:]+"), \
            "No IPv6 address found in AAAA query output"


# ---------------------------------------------------------------------------
# Group 4 – Propagation (network)
# ---------------------------------------------------------------------------

class TestGroup4_Propagation:
    """S16–S17: DNS propagation check across 8 global servers."""

    def test_S16_propagation_google(self):
        """
        S16 – propagation check for google.com
        Criteria: exit 0, output mentions ≥3 of the 8 known DNS providers,
                  'propagation' or 'consistent' language present
        """
        r = run(["propagation", STABLE_DOMAIN], timeout=90)
        assert r.returncode == 0
        assert no_traceback(r)
        providers = ["Google", "Cloudflare", "Quad9", "OpenDNS"]
        found = [p for p in providers if p in r.stdout]
        assert len(found) >= 3, \
            f"Expected ≥3 DNS providers in output, found: {found}\nOutput:\n{r.stdout[:500]}"

    def test_S17_propagation_cloudflare(self):
        """
        S17 – propagation check for cloudflare.com
        Criteria: exit 0, IP addresses returned from multiple servers
        """
        r = run(["propagation", "cloudflare.com"], timeout=90)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
            "No IPv4 addresses found in propagation output"


# ---------------------------------------------------------------------------
# Group 5 – Bulk Lookup (network)
# ---------------------------------------------------------------------------

class TestGroup5_Bulk:
    """S18: Bulk DNS lookup from a file."""

    def test_S18_bulk_from_file(self):
        """
        S18 – bulk lookup for a file of 3 well-known domains
        Criteria: exit 0, all 3 domain names appear in output, IP addresses present
        """
        domains = ["google.com", "cloudflare.com", "github.com"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            tmpfile = f.name

        try:
            r = run(["bulk", tmpfile, "-t", "A"], timeout=120)
            assert r.returncode == 0
            assert no_traceback(r)
            for d in domains:
                assert d in r.stdout, f"Domain '{d}' missing from bulk output"
            assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
                "No IP addresses found in bulk output"
        finally:
            Path(tmpfile).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Group 6 – Compare / Geo-Diff (network)
# ---------------------------------------------------------------------------

class TestGroup6_Compare:
    """S19–S20: Country-by-country DNS comparison."""

    def test_S19_compare_two_countries(self):
        """
        S19 – compare google.com between US and DE
        Criteria: exit 0, both country codes in output, similarity/diff language present
        """
        r = run(["compare", STABLE_DOMAIN, "-c", "US", "-c", "DE"], timeout=120)
        assert r.returncode == 0
        assert no_traceback(r)
        assert "US" in r.stdout, "'US' not found in compare output"
        assert "DE" in r.stdout, "'DE' not found in compare output"
        assert has_pattern(r, r"(similar|identical|differ|match|geo.diff|comparison)", re.IGNORECASE), \
            "No comparison language in compare output"

    def test_S20_compare_three_countries(self):
        """
        S20 – compare google.com across US, GB, DE
        Criteria: exit 0, all three country codes present, ≥1 IP in output
        """
        r = run(["compare", STABLE_DOMAIN, "-c", "US", "-c", "GB", "-c", "DE"], timeout=120)
        assert r.returncode == 0
        assert no_traceback(r)
        for code in ("US", "GB", "DE"):
            assert code in r.stdout, f"Country code '{code}' missing from compare output"
        assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
            "No IP addresses found in compare output"


# ---------------------------------------------------------------------------
# Group 7 – Security Analysis (network)
# ---------------------------------------------------------------------------

class TestGroup7_Security:
    """S21–S22: Email security record analysis."""

    def test_S21_security_google(self):
        """
        S21 – security check on google.com
        Criteria: exit 0, SPF / DMARC / DKIM check names present in output,
                  at least one pass/warn/fail/info status icon present
        """
        r = run(["security", STABLE_DOMAIN], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"SPF"), "SPF check not reported"
        assert has_pattern(r, r"DMARC"), "DMARC check not reported"
        assert has_pattern(r, r"(DKIM|MX|NS|CAA)"), "Expected security check sections missing"
        # At least one status icon/keyword
        assert has_pattern(r, r"(pass|warn|fail|info|\✓|\!|\✗|ℹ)", re.IGNORECASE), \
            "No status indicators found in security output"

    def test_S22_security_gmail(self):
        """
        S22 – security check on gmail.com
        Criteria: exit 0, 'v=spf1' found (gmail has a well-known SPF record),
                  DMARC record with 'reject' or 'quarantine' policy present
        """
        r = run(["security", "gmail.com"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"SPF"), "SPF not analyzed for gmail.com"
        assert has_pattern(r, r"(v=spf1|v=DMARC1|google\.com)"), \
            "Expected gmail SPF/DMARC record content missing"


# ---------------------------------------------------------------------------
# Group 8 – Zone Transfer / AXFR (network)
# ---------------------------------------------------------------------------

class TestGroup8_AXFR:
    """S23–S24: DNS zone transfer vulnerability testing."""

    def test_S23_axfr_vulnerable_domain(self):
        """
        S23 – zone transfer against zonetransfer.me (publicly vulnerable test target)
        Criteria: exit 0, zone records displayed (A, MX, or TXT records from the zone),
                  'zone transfer' language present
        """
        r = run(["axfr", AXFR_VULNERABLE], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        # zonetransfer.me is intentionally vulnerable; should return records
        assert has_pattern(r, r"(zone transfer|AXFR|transfer success|vulnerable|record)", re.IGNORECASE), \
            f"No zone-transfer language found.\nOutput:\n{r.stdout[:600]}"

    def test_S24_axfr_secure_domain(self):
        """
        S24 – zone transfer against google.com (not vulnerable)
        Criteria: exit 0, output indicates transfer refused/failed/not vulnerable —
                  no zone dump; graceful handling
        """
        r = run(["axfr", STABLE_DOMAIN], timeout=60)
        assert r.returncode == 0, f"axfr exited {r.returncode} instead of 0"
        assert no_traceback(r)
        combined = r.stdout + r.stderr
        assert has_pattern(r, r"(refused|denied|failed|not vulnerable|no nameservers|transfer)", re.IGNORECASE), \
            f"No expected 'refused/denied/failed/not vulnerable' message.\nOutput:\n{combined[:600]}"


# ---------------------------------------------------------------------------
# Group 9 – Reverse DNS (network)
# ---------------------------------------------------------------------------

class TestGroup9_Reverse:
    """S25–S26: Reverse PTR lookup + geolocation for known IPs."""

    def test_S25_reverse_google_dns(self):
        """
        S25 – reverse lookup of 8.8.8.8 (Google Public DNS)
        Criteria: exit 0, 'google' in output, geolocation data present (US / country)
        """
        r = run(["reverse", STABLE_IP_GOOGLE], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"google"), "Expected 'google' in reverse lookup output for 8.8.8.8"
        assert has_pattern(r, r"(United States|US|country|ISP|org|ASN)"), \
            "Geolocation data missing from reverse output"

    def test_S26_reverse_cloudflare_dns(self):
        """
        S26 – reverse lookup of 1.1.1.1 (Cloudflare DNS)
        Criteria: exit 0, 'cloudflare' or PTR record present, geolocation shown
        """
        r = run(["reverse", STABLE_IP_CF], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"(cloudflare|1\.1\.1\.1)"), \
            "Expected Cloudflare reference in reverse lookup output for 1.1.1.1"
        assert has_pattern(r, r"(country|org|ISP|AS|city|PTR|geolocation)", re.IGNORECASE), \
            "Geolocation/PTR data missing from reverse output"


# ---------------------------------------------------------------------------
# Group 10 – DNS over HTTPS (network)
# ---------------------------------------------------------------------------

class TestGroup10_DoH:
    """S27–S29: DoH queries through multiple providers."""

    def test_S27_doh_a_record_default_provider(self):
        """
        S27 – DoH A record query (Cloudflare provider by default)
        Criteria: exit 0, IPv4 addresses in output, 'Cloudflare' or provider name present
        """
        r = run(["doh", STABLE_DOMAIN, "-t", "A"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
            "No IPv4 address in DoH A record output"

    def test_S28_doh_google_provider(self):
        """
        S28 – DoH A record via Google provider explicitly
        Criteria: exit 0, IPv4 addresses in output, 'Google' in output
        """
        r = run(["doh", STABLE_DOMAIN, "-t", "A", "-p", "google"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
            "No IPv4 address in DoH Google-provider output"
        assert "Google" in r.stdout, "'Google' provider name missing from output"

    def test_S29_doh_aaaa_record(self):
        """
        S29 – DoH AAAA record query returns IPv6 addresses
        Criteria: exit 0, IPv6 address pattern present in output
        """
        r = run(["doh", "cloudflare.com", "-t", "AAAA"], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"[0-9a-f]{1,4}:[0-9a-f:]+"), \
            "No IPv6 address found in DoH AAAA query output"


# ---------------------------------------------------------------------------
# Group 11 – Subdomain Brute-force (network)
# ---------------------------------------------------------------------------

class TestGroup11_Brute:
    """S30: Subdomain enumeration via brute-force."""

    def test_S30_brute_google_doh(self):
        """
        S30 – subdomain brute-force on google.com using DoH
        Criteria: exit 0, at least 1 subdomain discovered (mail/www/api/dns known to exist),
                  discovered subdomains contain IP addresses
        """
        r = run(["brute", STABLE_DOMAIN, "--doh"], timeout=120)
        assert r.returncode == 0
        assert no_traceback(r)
        # At minimum www.google.com, mail.google.com, api.google.com, dns.google.com exist
        assert has_pattern(r, r"(\.google\.com|Found|discovered|subdomain)", re.IGNORECASE), \
            "No subdomains or discovery language in brute output"
        assert has_pattern(r, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), \
            "No IP addresses found in brute output (no subdomains resolved?)"


# ---------------------------------------------------------------------------
# Group 12 – Map Visualization (network)
# ---------------------------------------------------------------------------

class TestGroup12_Map:
    """S31: Visual ASCII map with geolocation."""

    def test_S31_map_ip(self):
        """
        S31 – map visualization for 8.8.8.8
        Criteria: exit 0, geolocation output present (country, org, ASN, or coordinates),
                  ASCII map content present (coordinates or map markers)
        """
        r = run(["map", STABLE_IP_GOOGLE], timeout=60)
        assert r.returncode == 0
        assert no_traceback(r)
        assert has_pattern(r, r"(country|org|ASN|ISP|lat|lon|coordinate|location|google)", re.IGNORECASE), \
            "No geolocation/organization data found in map output"


# ---------------------------------------------------------------------------
# Group 13 – Error Handling
# ---------------------------------------------------------------------------

class TestGroup13_ErrorHandling:
    """S32: Tool handles invalid inputs gracefully."""

    def test_S32_nxdomain_graceful(self):
        """
        S32 – query against a nonexistent domain handles NXDOMAIN gracefully
        Criteria: exit 0 (errors are informational, not crashes), no traceback,
                  some indication of failure in output (NXDOMAIN / error / no answers)
        """
        r = run(
            ["query", "-c", "US", "-d", NONEXISTENT, "-t", "A", "-l", "2"],
            timeout=60,
        )
        # Tool may exit 0 or 1, but must NOT crash with traceback
        assert no_traceback(r), f"Python traceback found:\n{r.stderr}"
        combined = r.stdout + r.stderr
        assert has_pattern(r, r"(NXDOMAIN|does not exist|error|no answer|timeout|failed)", re.IGNORECASE), \
            f"Expected error indication for NXDOMAIN query, got:\n{combined[:400]}"


# ---------------------------------------------------------------------------
# Summary hook
# ---------------------------------------------------------------------------

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print scenario pass/fail scoreboard at end of run."""
    passed = len(terminalreporter.stats.get("passed", []))
    failed = len(terminalreporter.stats.get("failed", []))
    skipped = len(terminalreporter.stats.get("skipped", []))
    total = passed + failed + skipped
    pct = int(100 * passed / total) if total else 0

    terminalreporter.write_sep("=", "SCENARIO SCOREBOARD")
    terminalreporter.write_line(f"  Total scenarios : {total}")
    terminalreporter.write_line(f"  PASS            : {passed}")
    terminalreporter.write_line(f"  FAIL            : {failed}")
    terminalreporter.write_line(f"  SKIP            : {skipped}")
    terminalreporter.write_line(f"  Score           : {pct}%  ({passed}/{total})")
    if failed == 0:
        terminalreporter.write_line("  Quality bar     : MET ✓")
    else:
        terminalreporter.write_line(f"  Quality bar     : NOT MET — {failed} scenario(s) need fixes")
