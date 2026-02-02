#!/usr/bin/env python3
"""
dnsmenace - Global DNS Query Tool

Query DNS servers from any country in the world. Perfect for security research,
network debugging, and understanding global DNS infrastructure.
"""

from __future__ import annotations

import asyncio
import base64
import csv
import json
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from io import StringIO
from pathlib import Path
from typing import Annotated

import dns.asyncresolver
import dns.resolver
import dns.query
import dns.zone
import dns.rdatatype
import dns.message
import dns.name
import dns.rdata
import dns.exception
import httpx
from iso3166 import countries
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
import typer

# Initialize Rich console and Typer app
console = Console()
app = typer.Typer(
    name="dnsmenace",
    help="Query DNS servers from any country in the world",
    add_completion=False,
    rich_markup_mode="rich",
)


class RecordType(str, Enum):
    """DNS record types supported by dnsmenace."""
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    CNAME = "CNAME"
    SOA = "SOA"
    PTR = "PTR"


class OutputFormat(str, Enum):
    """Output formats for DNS query results."""
    TABLE = "table"
    JSON = "json"
    CSV = "csv"


@dataclass
class NameServer:
    """Represents a DNS nameserver."""
    ip: str
    name: str = ""
    country: str = ""
    reliability: float = 0.0


@dataclass
class DNSResult:
    """Represents a DNS query result."""
    nameserver: NameServer
    query: str
    record_type: str
    answers: list[str] = field(default_factory=list)
    error: str | None = None
    response_time_ms: float = 0.0


@dataclass
class SecurityCheck:
    """Represents a security check result."""
    check_name: str
    status: str  # "pass", "warn", "fail", "info"
    message: str
    details: list[str] = field(default_factory=list)


# Well-known public DNS servers for global checks
GLOBAL_DNS_SERVERS = [
    NameServer(ip="8.8.8.8", name="Google", country="US"),
    NameServer(ip="1.1.1.1", name="Cloudflare", country="US"),
    NameServer(ip="9.9.9.9", name="Quad9", country="CH"),
    NameServer(ip="208.67.222.222", name="OpenDNS", country="US"),
    NameServer(ip="8.26.56.26", name="Comodo", country="US"),
    NameServer(ip="185.228.168.9", name="CleanBrowsing", country="US"),
    NameServer(ip="76.76.19.19", name="Alternate DNS", country="US"),
    NameServer(ip="94.140.14.14", name="AdGuard", country="CY"),
]


@dataclass
class DoHProvider:
    """DNS over HTTPS provider configuration."""
    name: str
    url: str
    country: str


# DNS over HTTPS providers for privacy mode
DOH_PROVIDERS = [
    DoHProvider(name="Cloudflare", url="https://cloudflare-dns.com/dns-query", country="US"),
    DoHProvider(name="Google", url="https://dns.google/dns-query", country="US"),
    DoHProvider(name="Quad9", url="https://dns.quad9.net/dns-query", country="CH"),
    DoHProvider(name="AdGuard", url="https://dns.adguard.com/dns-query", country="CY"),
    DoHProvider(name="NextDNS", url="https://dns.nextdns.io/dns-query", country="US"),
    DoHProvider(name="CleanBrowsing", url="https://doh.cleanbrowsing.org/doh/security-filter", country="US"),
]

# Common subdomains for bruteforce enumeration
SUBDOMAIN_WORDLIST = [
    # Development & Staging
    "dev", "develop", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "demo", "sandbox", "preview", "beta", "alpha", "canary",
    # Web & API
    "www", "www2", "www3", "web", "webapp", "app", "api", "api2", "api-v2",
    "rest", "graphql", "gateway", "backend", "frontend", "static", "assets",
    # Mail & Communication
    "mail", "mail2", "email", "smtp", "pop", "pop3", "imap", "webmail",
    "exchange", "mx", "mx1", "mx2", "newsletter",
    # Infrastructure
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "vpn", "vpn2",
    "proxy", "gateway", "firewall", "router", "lb", "loadbalancer",
    # Storage & Data
    "ftp", "sftp", "files", "storage", "backup", "backups", "data",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "cdn", "media", "images", "img", "video", "download", "downloads",
    # Monitoring & Admin
    "admin", "administrator", "panel", "dashboard", "portal", "console",
    "monitor", "monitoring", "status", "health", "metrics", "grafana",
    "kibana", "logs", "logging", "sentry", "jenkins", "ci", "cd",
    # Cloud & Services
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker",
    "registry", "git", "gitlab", "github", "bitbucket", "repo",
    # Authentication & Security
    "auth", "login", "sso", "oauth", "ldap", "id", "identity", "secure",
    # Internal
    "internal", "intranet", "private", "corp", "corporate", "office",
    "remote", "connect", "client", "clients", "customer", "customers",
    # Misc
    "blog", "shop", "store", "pay", "payment", "billing", "support",
    "help", "docs", "documentation", "wiki", "forum", "community",
    "news", "events", "careers", "jobs", "about", "info", "contact",
    # Numbered variants
    "server1", "server2", "host1", "host2", "node1", "node2", "web1", "web2",
]


async def fetch_nameservers(country_code: str, limit: int = 10) -> list[NameServer]:
    """Fetch nameservers for a given country from public-dns.info API."""
    url = f"https://public-dns.info/nameserver/{country_code.lower()}.json"

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            nameservers = []
            for item in data[:limit]:
                ns = NameServer(
                    ip=item.get("ip", ""),
                    name=item.get("name", ""),
                    country=item.get("country_id", country_code.upper()),
                    reliability=float(item.get("reliability", 0)),
                )
                if ns.ip:
                    nameservers.append(ns)

            return nameservers
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Error fetching nameservers: HTTP {e.response.status_code}[/red]")
            raise typer.Exit(1)
        except httpx.RequestError as e:
            console.print(f"[red]Network error: {e}[/red]")
            raise typer.Exit(1)


async def query_dns(
    nameserver: NameServer,
    fqdn: str,
    record_type: RecordType,
) -> DNSResult:
    """Query a specific nameserver for DNS records."""
    import time

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [nameserver.ip]
    resolver.lifetime = 5.0  # 5 second timeout

    start_time = time.perf_counter()
    result = DNSResult(
        nameserver=nameserver,
        query=fqdn,
        record_type=record_type.value,
    )

    try:
        answers = await resolver.resolve(fqdn, record_type.value)
        result.answers = [str(rdata) for rdata in answers]
        result.response_time_ms = (time.perf_counter() - start_time) * 1000
    except dns.resolver.NXDOMAIN:
        result.error = "Domain does not exist"
    except dns.resolver.NoAnswer:
        result.error = "No answer for this record type"
    except dns.resolver.Timeout:
        result.error = "Query timed out"
    except dns.exception.DNSException as e:
        result.error = str(e)

    return result


async def query_dns_simple(
    nameserver_ip: str,
    fqdn: str,
    record_type: str,
) -> tuple[list[str], str | None]:
    """Simple DNS query returning answers and error."""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [nameserver_ip]
    resolver.lifetime = 5.0

    try:
        answers = await resolver.resolve(fqdn, record_type)
        return [str(rdata) for rdata in answers], None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "No answer"
    except dns.resolver.Timeout:
        return [], "Timeout"
    except dns.exception.DNSException as e:
        return [], str(e)


async def query_doh(
    provider: DoHProvider,
    fqdn: str,
    record_type: RecordType,
) -> DNSResult:
    """Query DNS over HTTPS provider."""
    start_time = time.perf_counter()
    result = DNSResult(
        nameserver=NameServer(ip=provider.url, name=provider.name, country=provider.country),
        query=fqdn,
        record_type=record_type.value,
    )

    # Map record types to DNS wire format type codes
    type_map = {
        "A": 1, "AAAA": 28, "MX": 15, "TXT": 16,
        "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    }
    qtype = type_map.get(record_type.value, 1)

    try:
        # Build DNS query message
        query_msg = dns.message.make_query(fqdn, qtype)
        wire_query = query_msg.to_wire()

        # Base64url encode for GET request (RFC 8484)
        b64_query = base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode("ascii")

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                provider.url,
                params={"dns": b64_query},
                headers={
                    "Accept": "application/dns-message",
                },
            )
            response.raise_for_status()

            # Parse DNS response
            response_msg = dns.message.from_wire(response.content)
            answers = []

            for rrset in response_msg.answer:
                for rdata in rrset:
                    answers.append(str(rdata))

            result.answers = answers
            result.response_time_ms = (time.perf_counter() - start_time) * 1000

    except httpx.HTTPStatusError as e:
        result.error = f"HTTP {e.response.status_code}"
    except httpx.RequestError as e:
        result.error = f"Network error: {type(e).__name__}"
    except dns.exception.DNSException as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"Error: {type(e).__name__}"

    return result


async def run_doh_queries(
    providers: list[DoHProvider],
    fqdn: str,
    record_types: list[RecordType],
) -> list[DNSResult]:
    """Run DoH queries against multiple providers concurrently."""
    tasks = []

    for provider in providers:
        for rtype in record_types:
            tasks.append(query_doh(provider, fqdn, rtype))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Querying DoH providers...",
            total=len(tasks),
        )

        results = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            progress.advance(task)

    return results


async def bruteforce_subdomains(
    domain: str,
    wordlist: list[str],
    nameserver_ip: str | None = None,
    use_doh: bool = False,
) -> list[tuple[str, list[str]]]:
    """Bruteforce common subdomains for a domain."""
    found = []

    async def check_subdomain(subdomain: str) -> tuple[str, list[str]] | None:
        fqdn = f"{subdomain}.{domain}"
        if use_doh:
            provider = DOH_PROVIDERS[0]  # Use Cloudflare by default
            result = await query_doh(provider, fqdn, RecordType.A)
            if result.answers:
                return (fqdn, result.answers)
        else:
            resolver = dns.asyncresolver.Resolver()
            if nameserver_ip:
                resolver.nameservers = [nameserver_ip]
            resolver.lifetime = 3.0

            try:
                answers = await resolver.resolve(fqdn, "A")
                return (fqdn, [str(r) for r in answers])
            except dns.exception.DNSException:
                pass

        return None

    # Run checks in batches to avoid overwhelming the resolver
    batch_size = 20
    for i in range(0, len(wordlist), batch_size):
        batch = wordlist[i:i + batch_size]
        tasks = [check_subdomain(sub) for sub in batch]
        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                found.append(result)

    return found


async def get_ip_geolocation(ip: str) -> dict | None:
    """Get geolocation info for an IP address."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data
        except Exception:
            pass
    return None


async def run_dns_queries(
    nameservers: list[NameServer],
    fqdn: str,
    record_types: list[RecordType],
) -> list[DNSResult]:
    """Run DNS queries against multiple nameservers concurrently."""
    tasks = []

    for ns in nameservers:
        for rtype in record_types:
            tasks.append(query_dns(ns, fqdn, rtype))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Querying DNS servers...",
            total=len(tasks),
        )

        results = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            progress.advance(task)

    return results


def display_results_table(results: list[DNSResult]) -> None:
    """Display DNS results in a rich table format."""
    table = Table(
        title="DNS Query Results",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
    )

    table.add_column("Nameserver", style="cyan", no_wrap=True)
    table.add_column("IP", style="dim")
    table.add_column("Type", style="yellow")
    table.add_column("Response", style="green")
    table.add_column("Time (ms)", justify="right", style="blue")

    for result in results:
        if result.error:
            response = Text(result.error, style="red")
        else:
            response = Text("\n".join(result.answers) if result.answers else "No data")

        time_str = f"{result.response_time_ms:.1f}" if not result.error else "-"

        table.add_row(
            result.nameserver.name or "Unknown",
            result.nameserver.ip,
            result.record_type,
            response,
            time_str,
        )

    console.print(table)


def display_results_json(results: list[DNSResult]) -> None:
    """Display DNS results in JSON format."""
    output = []
    for result in results:
        output.append({
            "nameserver": {
                "ip": result.nameserver.ip,
                "name": result.nameserver.name,
                "country": result.nameserver.country,
            },
            "query": result.query,
            "record_type": result.record_type,
            "answers": result.answers,
            "error": result.error,
            "response_time_ms": round(result.response_time_ms, 2),
        })
    console.print_json(json.dumps(output, indent=2))


def display_results_csv(results: list[DNSResult]) -> None:
    """Display DNS results in CSV format."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["nameserver_ip", "nameserver_name", "record_type", "answers", "error", "response_time_ms"])

    for result in results:
        writer.writerow([
            result.nameserver.ip,
            result.nameserver.name,
            result.record_type,
            "|".join(result.answers),
            result.error or "",
            f"{result.response_time_ms:.2f}",
        ])

    console.print(output.getvalue())


def print_banner() -> None:
    """Print the dnsmenace banner."""
    banner = """
[bold cyan]    ____  _   _______ __  ___
   / __ \\/ | / / ___//  |/  /__  ____  ____ _________
  / / / /  |/ /\\__ \\/ /|_/ / _ \\/ __ \\/ __ `/ ___/ _ \\
 / /_/ / /|  /___/ / /  / /  __/ / / / /_/ / /__/  __/
/_____/_/ |_//____/_/  /_/\\___/_/ /_/\\__,_/\\___/\\___/[/bold cyan]

[dim]Global DNS Query Tool v3.0.0 - Security Research Edition[/dim]
"""
    console.print(banner)


def display_security_check(check: SecurityCheck) -> None:
    """Display a single security check result."""
    status_colors = {
        "pass": "green",
        "warn": "yellow",
        "fail": "red",
        "info": "blue",
    }
    status_icons = {
        "pass": "[green]✓[/green]",
        "warn": "[yellow]![/yellow]",
        "fail": "[red]✗[/red]",
        "info": "[blue]ℹ[/blue]",
    }

    color = status_colors.get(check.status, "white")
    icon = status_icons.get(check.status, "•")

    console.print(f"\n{icon} [bold]{check.check_name}[/bold]")
    console.print(f"  [{color}]{check.message}[/{color}]")

    for detail in check.details:
        console.print(f"    [dim]• {detail}[/dim]")


@app.command()
def query(
    country: Annotated[
        str,
        typer.Option(
            "--country", "-c",
            help="Two-letter country code (e.g., US, DE, JP)",
        ),
    ],
    domain: Annotated[
        str,
        typer.Option(
            "--domain", "-d",
            help="Domain name to query (FQDN)",
            prompt="Enter domain to query",
        ),
    ],
    record_types: Annotated[
        list[RecordType],
        typer.Option(
            "--type", "-t",
            help="DNS record type(s) to query",
        ),
    ] = [RecordType.A],
    limit: Annotated[
        int,
        typer.Option(
            "--limit", "-l",
            help="Maximum number of nameservers to query",
            min=1,
            max=50,
        ),
    ] = 5,
    output: Annotated[
        OutputFormat,
        typer.Option(
            "--output", "-o",
            help="Output format",
        ),
    ] = OutputFormat.TABLE,
) -> None:
    """
    Query DNS servers from a specific country.

    Example:
        dnsmenace query -c DE -d google.com -t A -t AAAA
    """
    print_banner()

    # Validate country code
    try:
        country_info = countries.get(country.upper())
        console.print(f"\n[bold]Querying DNS servers from:[/bold] {country_info.name} ({country.upper()})")
    except KeyError:
        console.print(f"[red]Invalid country code: {country}[/red]")
        console.print("Use 'dnsmenace countries-list' to see available codes.")
        raise typer.Exit(1)

    console.print(f"[bold]Domain:[/bold] {domain}")
    console.print(f"[bold]Record types:[/bold] {', '.join(rt.value for rt in record_types)}")
    console.print()

    # Fetch nameservers
    with console.status("[bold green]Fetching nameservers..."):
        nameservers = asyncio.run(fetch_nameservers(country, limit))

    if not nameservers:
        console.print("[red]No nameservers found for this country.[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Found {len(nameservers)} nameservers[/green]\n")

    # Run DNS queries
    results = asyncio.run(run_dns_queries(nameservers, domain, record_types))

    # Display results
    console.print()
    if output == OutputFormat.TABLE:
        display_results_table(results)
    elif output == OutputFormat.JSON:
        display_results_json(results)
    elif output == OutputFormat.CSV:
        display_results_csv(results)

    # Summary
    successful = sum(1 for r in results if not r.error)
    console.print(f"\n[dim]Completed: {successful}/{len(results)} queries successful[/dim]")


@app.command()
def compare(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name to compare across countries"),
    ],
    countries_list: Annotated[
        list[str],
        typer.Option(
            "--countries", "-c",
            help="Country codes to compare (can specify multiple)",
        ),
    ] = ["US", "DE", "JP", "AU", "BR"],
    record_type: Annotated[
        RecordType,
        typer.Option(
            "--type", "-t",
            help="DNS record type to query",
        ),
    ] = RecordType.A,
    use_doh: Annotated[
        bool,
        typer.Option(
            "--doh",
            help="Use DNS over HTTPS (bypasses local filtering)",
        ),
    ] = False,
) -> None:
    """
    Compare DNS responses across multiple countries (Geo-Diff mode).

    Detects DNS-based censorship, geo-blocking, CDN routing, or DNS poisoning
    by querying the same domain from servers in different countries and
    highlighting any discrepancies.

    Example:
        dnsmenace compare google.com -c US -c CN -c RU -c IR
        dnsmenace compare example.com --countries US DE JP --doh
    """
    print_banner()

    console.print(f"\n[bold cyan]Geo-Censorship Detection Mode[/bold cyan]")
    console.print(f"[bold]Domain:[/bold] {domain}")
    console.print(f"[bold]Record type:[/bold] {record_type.value}")
    console.print(f"[bold]Countries:[/bold] {', '.join(countries_list)}")
    if use_doh:
        console.print("[bold]Mode:[/bold] DNS over HTTPS (encrypted)")
    console.print()

    async def compare_countries():
        results_by_country: dict[str, tuple[list[str], float]] = {}
        errors_by_country: dict[str, str] = {}

        async def query_country(country_code: str):
            code = country_code.upper()
            try:
                countries.get(code)
            except KeyError:
                return code, None, "Invalid country code"

            if use_doh:
                # Use DoH providers based on country approximation
                provider = DOH_PROVIDERS[0]  # Default to Cloudflare
                result = await query_doh(provider, domain, record_type)
                if result.error:
                    return code, None, result.error
                return code, (sorted(result.answers), result.response_time_ms), None
            else:
                nameservers = await fetch_nameservers(country_code, limit=3)
                if nameservers:
                    for ns in nameservers:
                        start = time.perf_counter()
                        answers, error = await query_dns_simple(ns.ip, domain, record_type.value)
                        elapsed = (time.perf_counter() - start) * 1000
                        if not error:
                            return code, (sorted(answers), elapsed), None
                    return code, None, "All nameservers failed"
                return code, None, "No nameservers found"

        # Query all countries in parallel
        tasks = [query_country(c) for c in countries_list]
        query_results = await asyncio.gather(*tasks)

        for code, data, error in query_results:
            if error:
                errors_by_country[code] = error
            elif data:
                results_by_country[code] = data

        return results_by_country, errors_by_country

    with console.status("[bold green]Querying DNS servers across countries..."):
        results, errors = asyncio.run(compare_countries())

    # Find unique responses and group countries
    response_groups: dict[str, list[str]] = {}
    for code, (answers, _) in results.items():
        key = "|".join(answers) if answers else "<empty>"
        if key not in response_groups:
            response_groups[key] = []
        response_groups[key].append(code)

    # Determine majority response
    most_common_key = max(response_groups.items(), key=lambda x: len(x[1]))[0] if response_groups else ""

    # Build comparison table
    table = Table(
        title="🌍 DNS Response Comparison",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
    )

    table.add_column("Country", style="cyan", no_wrap=True)
    table.add_column("Response", style="green")
    table.add_column("Latency", justify="right", style="blue", width=10)
    table.add_column("Status", justify="center", width=18)

    for country_code in countries_list:
        code = country_code.upper()
        try:
            country_name = countries.get(code).name
        except KeyError:
            continue

        if code in results:
            answers, latency = results[code]
            response = "\n".join(answers) if answers else "<empty>"
            resp_key = "|".join(answers) if answers else "<empty>"

            if resp_key == most_common_key:
                status = Text("✓ Majority", style="green")
            else:
                status = Text("⚠ DIFFERS", style="bold yellow")

            latency_text = f"{latency:.0f}ms"
        elif code in errors:
            response = Text(errors[code], style="red")
            status = Text("✗ Error", style="red")
            latency_text = "-"
        else:
            response = Text("No data", style="dim")
            status = Text("- N/A", style="dim")
            latency_text = "-"

        table.add_row(f"{country_name} ({code})", response, latency_text, status)

    console.print(table)

    # Detailed diff analysis
    unique_count = len(response_groups)

    if unique_count == 1 and results:
        console.print(Panel(
            "[bold green]✓ CONSISTENT[/bold green]\n\n"
            "All countries return identical DNS responses.\n"
            "No evidence of geo-blocking or DNS manipulation detected.",
            border_style="green",
            title="Analysis Result",
        ))
    elif unique_count > 1:
        # Build diff visualization
        diff_content = []
        diff_content.append("[bold yellow]⚠ DISCREPANCY DETECTED[/bold yellow]\n")
        diff_content.append(f"Found [bold]{unique_count}[/bold] different DNS responses:\n")

        group_num = 1
        for resp_key, group_countries in sorted(response_groups.items(), key=lambda x: -len(x[1])):
            is_majority = resp_key == most_common_key
            marker = "[green]●[/green]" if is_majority else "[yellow]○[/yellow]"
            label = " (majority)" if is_majority else ""

            responses = resp_key.split("|") if resp_key != "<empty>" else ["<no response>"]
            countries_str = ", ".join(group_countries)

            diff_content.append(f"\n{marker} [bold]Group {group_num}{label}:[/bold] {countries_str}")
            for resp in responses:
                diff_content.append(f"   → {resp}")
            group_num += 1

        diff_content.append("\n\n[dim]Possible causes: CDN geo-routing, DNS-based load balancing,")
        diff_content.append("regional censorship, or DNS poisoning.[/dim]")

        console.print(Panel(
            "\n".join(diff_content),
            border_style="yellow",
            title="🔍 Diff Analysis",
        ))

        # Show similarity matrix if more than 2 countries
        if len(results) > 2:
            console.print("\n[bold]Similarity Matrix:[/bold]")

            matrix_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
            matrix_table.add_column("", style="cyan")

            country_codes = list(results.keys())
            for code in country_codes:
                matrix_table.add_column(code, justify="center", width=4)

            for code1 in country_codes:
                row = [code1]
                for code2 in country_codes:
                    if code1 == code2:
                        row.append("[dim]—[/dim]")
                    else:
                        answers1 = set(results[code1][0])
                        answers2 = set(results[code2][0])
                        if answers1 == answers2:
                            row.append("[green]✓[/green]")
                        elif answers1 & answers2:
                            row.append("[yellow]~[/yellow]")
                        else:
                            row.append("[red]✗[/red]")
                matrix_table.add_row(*row)

            console.print(matrix_table)
            console.print("[dim]✓ = identical, ~ = partial match, ✗ = different[/dim]")

    # Summary statistics
    if results:
        avg_latency = sum(lat for _, lat in results.values()) / len(results)
        console.print(f"\n[dim]Average latency: {avg_latency:.0f}ms | "
                      f"Successful queries: {len(results)}/{len(countries_list)}[/dim]")


@app.command()
def security(
    domain: Annotated[
        str,
        typer.Argument(help="Domain to check security records"),
    ],
) -> None:
    """
    Check email security records (SPF, DKIM, DMARC, CAA).

    Analyzes the domain's DNS security configuration.

    Example:
        dnsmenace security google.com
        dnsmenace security example.org
    """
    print_banner()

    console.print(f"\n[bold]Security Analysis for:[/bold] {domain}\n")

    checks: list[SecurityCheck] = []

    async def run_security_checks():
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 10.0

        # SPF Check
        try:
            txt_records = await resolver.resolve(domain, "TXT")
            spf_records = [str(r) for r in txt_records if "v=spf1" in str(r)]

            if spf_records:
                spf = spf_records[0]
                details = [spf]

                if "-all" in spf:
                    checks.append(SecurityCheck(
                        "SPF Record", "pass",
                        "SPF record found with strict policy (-all)",
                        details
                    ))
                elif "~all" in spf:
                    checks.append(SecurityCheck(
                        "SPF Record", "warn",
                        "SPF record found with soft fail (~all) - consider using -all",
                        details
                    ))
                elif "?all" in spf:
                    checks.append(SecurityCheck(
                        "SPF Record", "warn",
                        "SPF record found with neutral policy (?all) - not recommended",
                        details
                    ))
                else:
                    checks.append(SecurityCheck(
                        "SPF Record", "info",
                        "SPF record found",
                        details
                    ))
            else:
                checks.append(SecurityCheck(
                    "SPF Record", "fail",
                    "No SPF record found - email spoofing possible",
                    []
                ))
        except dns.exception.DNSException:
            checks.append(SecurityCheck(
                "SPF Record", "fail",
                "Could not query SPF record",
                []
            ))

        # DMARC Check
        try:
            dmarc_records = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc = str(list(dmarc_records)[0])
            details = [dmarc]

            if "p=reject" in dmarc:
                checks.append(SecurityCheck(
                    "DMARC Record", "pass",
                    "DMARC record found with reject policy",
                    details
                ))
            elif "p=quarantine" in dmarc:
                checks.append(SecurityCheck(
                    "DMARC Record", "pass",
                    "DMARC record found with quarantine policy",
                    details
                ))
            elif "p=none" in dmarc:
                checks.append(SecurityCheck(
                    "DMARC Record", "warn",
                    "DMARC record found but policy is 'none' (monitoring only)",
                    details
                ))
            else:
                checks.append(SecurityCheck(
                    "DMARC Record", "info",
                    "DMARC record found",
                    details
                ))
        except dns.resolver.NXDOMAIN:
            checks.append(SecurityCheck(
                "DMARC Record", "fail",
                "No DMARC record found - email authentication not enforced",
                []
            ))
        except dns.exception.DNSException:
            checks.append(SecurityCheck(
                "DMARC Record", "warn",
                "Could not query DMARC record",
                []
            ))

        # DKIM Check (common selectors)
        dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "email"]
        dkim_found = []

        for selector in dkim_selectors:
            try:
                dkim_records = await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                dkim_found.append(selector)
            except dns.exception.DNSException:
                pass

        if dkim_found:
            checks.append(SecurityCheck(
                "DKIM Records", "pass",
                f"DKIM selectors found: {', '.join(dkim_found)}",
                [f"Selector: {s}._domainkey.{domain}" for s in dkim_found]
            ))
        else:
            checks.append(SecurityCheck(
                "DKIM Records", "warn",
                "No common DKIM selectors found (may use custom selector)",
                [f"Checked: {', '.join(dkim_selectors)}"]
            ))

        # MX Record Check
        try:
            mx_records = await resolver.resolve(domain, "MX")
            mx_list = [str(r.exchange) for r in mx_records]
            checks.append(SecurityCheck(
                "MX Records", "info",
                f"Found {len(mx_list)} mail server(s)",
                mx_list
            ))
        except dns.exception.DNSException:
            checks.append(SecurityCheck(
                "MX Records", "info",
                "No MX records found (may not receive email)",
                []
            ))

        # CAA Record Check
        try:
            caa_records = await resolver.resolve(domain, "CAA")
            caa_list = [str(r) for r in caa_records]
            checks.append(SecurityCheck(
                "CAA Records", "pass",
                "CAA records found - certificate issuance restricted",
                caa_list
            ))
        except dns.resolver.NoAnswer:
            checks.append(SecurityCheck(
                "CAA Records", "warn",
                "No CAA records - any CA can issue certificates",
                []
            ))
        except dns.exception.DNSException:
            checks.append(SecurityCheck(
                "CAA Records", "info",
                "Could not query CAA records",
                []
            ))

        # NS Records
        try:
            ns_records = await resolver.resolve(domain, "NS")
            ns_list = [str(r) for r in ns_records]
            checks.append(SecurityCheck(
                "Nameservers", "info",
                f"Found {len(ns_list)} nameserver(s)",
                ns_list
            ))
        except dns.exception.DNSException:
            pass

    asyncio.run(run_security_checks())

    # Display results
    for check in checks:
        display_security_check(check)

    # Summary
    passes = sum(1 for c in checks if c.status == "pass")
    warns = sum(1 for c in checks if c.status == "warn")
    fails = sum(1 for c in checks if c.status == "fail")

    console.print(f"\n[bold]Summary:[/bold] {passes} passed, {warns} warnings, {fails} failed")


@app.command()
def reverse(
    ip: Annotated[
        str,
        typer.Argument(help="IP address to perform reverse DNS lookup"),
    ],
) -> None:
    """
    Perform reverse DNS (PTR) lookup for an IP address.

    Example:
        dnsmenace reverse 8.8.8.8
        dnsmenace reverse 1.1.1.1
    """
    print_banner()

    console.print(f"\n[bold]Reverse DNS Lookup for:[/bold] {ip}\n")

    # Validate IP
    try:
        socket.inet_aton(ip)
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
        except socket.error:
            console.print("[red]Invalid IP address[/red]")
            raise typer.Exit(1)

    async def do_reverse_lookup():
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 10.0

        try:
            # Create reverse lookup address
            from dns.reversename import from_address
            rev_name = from_address(ip)

            answers = await resolver.resolve(rev_name, "PTR")
            return [str(rdata) for rdata in answers], None
        except dns.resolver.NXDOMAIN:
            return [], "No PTR record found"
        except dns.exception.DNSException as e:
            return [], str(e)

    hostnames, error = asyncio.run(do_reverse_lookup())

    if error:
        console.print(f"[red]{error}[/red]")
    else:
        table = Table(box=box.ROUNDED, header_style="bold magenta")
        table.add_column("IP Address", style="cyan")
        table.add_column("Hostname(s)", style="green")

        table.add_row(ip, "\n".join(hostnames))
        console.print(table)

    # Also try to get additional info via whois-style lookup
    console.print("\n[bold]Additional Information:[/bold]")

    async def get_ip_info():
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                # Use ip-api.com for geolocation (free, no API key)
                response = await client.get(f"http://ip-api.com/json/{ip}")
                if response.status_code == 200:
                    return response.json()
            except Exception:
                pass
        return None

    info = asyncio.run(get_ip_info())

    if info and info.get("status") == "success":
        info_table = Table(box=box.SIMPLE, show_header=False)
        info_table.add_column("Field", style="dim")
        info_table.add_column("Value", style="white")

        if info.get("org"):
            info_table.add_row("Organization", info["org"])
        if info.get("as"):
            info_table.add_row("ASN", info["as"])
        if info.get("isp"):
            info_table.add_row("ISP", info["isp"])
        if info.get("country"):
            info_table.add_row("Country", f"{info['country']} ({info.get('countryCode', '')})")
        if info.get("city"):
            info_table.add_row("Location", f"{info['city']}, {info.get('regionName', '')}")

        console.print(info_table)
    else:
        console.print("[dim]Could not retrieve additional IP information[/dim]")


@app.command()
def axfr(
    domain: Annotated[
        str,
        typer.Argument(help="Domain to attempt zone transfer"),
    ],
) -> None:
    """
    Attempt DNS zone transfer (AXFR) - tests for misconfiguration.

    Zone transfers should only be allowed to authorized secondary nameservers.
    If this succeeds, it's a security vulnerability.

    Example:
        dnsmenace axfr example.com
        dnsmenace axfr zonetransfer.me  (known test domain)
    """
    print_banner()

    console.print(f"\n[bold]Zone Transfer Test for:[/bold] {domain}")
    console.print("[dim]Testing for AXFR misconfiguration...[/dim]\n")

    # First, get nameservers
    async def get_nameservers():
        resolver = dns.asyncresolver.Resolver()
        try:
            ns_records = await resolver.resolve(domain, "NS")
            return [str(r).rstrip('.') for r in ns_records]
        except dns.exception.DNSException:
            return []

    nameservers = asyncio.run(get_nameservers())

    if not nameservers:
        console.print("[red]Could not retrieve nameservers for domain[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Found {len(nameservers)} nameserver(s)[/cyan]\n")

    vulnerable = []

    for ns in nameservers:
        console.print(f"[dim]Testing {ns}...[/dim]", end=" ")

        try:
            # Resolve NS to IP
            resolver = dns.resolver.Resolver()
            try:
                ns_ip = str(resolver.resolve(ns, "A")[0])
            except dns.exception.DNSException:
                console.print("[yellow]Could not resolve[/yellow]")
                continue

            # Attempt zone transfer
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=10.0))

            # If we get here, transfer succeeded!
            console.print("[red]VULNERABLE![/red]")
            vulnerable.append((ns, zone))

        except dns.exception.FormError:
            console.print("[green]Refused (secure)[/green]")
        except dns.query.TransferError:
            console.print("[green]Transfer denied (secure)[/green]")
        except Exception as e:
            console.print(f"[yellow]Error: {type(e).__name__}[/yellow]")

    # Display results
    if vulnerable:
        console.print(Panel(
            "[red bold]SECURITY VULNERABILITY FOUND![/red bold]\n\n"
            f"Zone transfer is allowed on {len(vulnerable)} nameserver(s).\n"
            "This exposes your entire DNS zone to attackers.",
            border_style="red",
        ))

        for ns, zone in vulnerable:
            console.print(f"\n[bold]Records from {ns}:[/bold]")

            table = Table(box=box.SIMPLE, show_lines=False)
            table.add_column("Name", style="cyan")
            table.add_column("TTL", style="dim")
            table.add_column("Type", style="yellow")
            table.add_column("Data", style="green")

            record_count = 0
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        table.add_row(
                            str(name),
                            str(rdataset.ttl),
                            dns.rdatatype.to_text(rdataset.rdtype),
                            str(rdata)
                        )
                        record_count += 1
                        if record_count >= 50:  # Limit display
                            break
                    if record_count >= 50:
                        break
                if record_count >= 50:
                    break

            console.print(table)
            if record_count >= 50:
                console.print("[dim]... and more records (showing first 50)[/dim]")
    else:
        console.print(Panel(
            "[green]All nameservers properly deny zone transfers.[/green]\n"
            "No AXFR vulnerability detected.",
            border_style="green",
        ))


@app.command()
def propagation(
    domain: Annotated[
        str,
        typer.Argument(help="Domain to check propagation"),
    ],
    record_type: Annotated[
        RecordType,
        typer.Option(
            "--type", "-t",
            help="DNS record type to check",
        ),
    ] = RecordType.A,
) -> None:
    """
    Check DNS propagation across global DNS servers.

    Useful after making DNS changes to verify propagation.

    Example:
        dnsmenace propagation example.com
        dnsmenace propagation example.com -t MX
    """
    print_banner()

    console.print(f"\n[bold]DNS Propagation Check for:[/bold] {domain}")
    console.print(f"[bold]Record type:[/bold] {record_type.value}\n")

    results = asyncio.run(run_dns_queries(GLOBAL_DNS_SERVERS, domain, [record_type]))

    table = Table(
        title="Global DNS Propagation",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
    )

    table.add_column("DNS Provider", style="cyan")
    table.add_column("Location", style="dim")
    table.add_column("Response", style="green")
    table.add_column("Time (ms)", justify="right", style="blue")

    all_responses = []

    for result in results:
        if result.error:
            response = Text(result.error, style="red")
        else:
            response = Text("\n".join(result.answers) if result.answers else "No data")
            all_responses.append(sorted(result.answers))

        time_str = f"{result.response_time_ms:.1f}" if not result.error else "-"

        table.add_row(
            result.nameserver.name,
            result.nameserver.country,
            response,
            time_str,
        )

    console.print(table)

    # Check consistency
    if all_responses:
        unique = set(tuple(r) for r in all_responses)
        if len(unique) == 1:
            console.print("\n[green]✓ DNS is fully propagated - all servers return the same response[/green]")
        else:
            console.print(f"\n[yellow]! DNS propagation incomplete - {len(unique)} different responses detected[/yellow]")


@app.command()
def bulk(
    file: Annotated[
        Path,
        typer.Argument(help="File containing domains (one per line)"),
    ],
    record_type: Annotated[
        RecordType,
        typer.Option(
            "--type", "-t",
            help="DNS record type to query",
        ),
    ] = RecordType.A,
    output: Annotated[
        OutputFormat,
        typer.Option(
            "--output", "-o",
            help="Output format",
        ),
    ] = OutputFormat.TABLE,
) -> None:
    """
    Bulk DNS lookup from a file of domains.

    Example:
        dnsmenace bulk domains.txt
        dnsmenace bulk domains.txt -t MX -o json
    """
    print_banner()

    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    domains = [line.strip() for line in file.read_text().splitlines() if line.strip() and not line.startswith("#")]

    if not domains:
        console.print("[red]No domains found in file[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold]Bulk DNS Lookup[/bold]")
    console.print(f"[dim]Processing {len(domains)} domain(s)...[/dim]\n")

    async def bulk_lookup():
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        results = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Querying...", total=len(domains))

            for domain in domains:
                try:
                    answers = await resolver.resolve(domain, record_type.value)
                    results.append({
                        "domain": domain,
                        "record_type": record_type.value,
                        "answers": [str(r) for r in answers],
                        "error": None,
                    })
                except dns.resolver.NXDOMAIN:
                    results.append({
                        "domain": domain,
                        "record_type": record_type.value,
                        "answers": [],
                        "error": "NXDOMAIN",
                    })
                except dns.exception.DNSException as e:
                    results.append({
                        "domain": domain,
                        "record_type": record_type.value,
                        "answers": [],
                        "error": str(e),
                    })

                progress.advance(task)

        return results

    results = asyncio.run(bulk_lookup())

    if output == OutputFormat.JSON:
        console.print_json(json.dumps(results, indent=2))
    elif output == OutputFormat.CSV:
        csv_output = StringIO()
        writer = csv.writer(csv_output)
        writer.writerow(["domain", "record_type", "answers", "error"])
        for r in results:
            writer.writerow([r["domain"], r["record_type"], "|".join(r["answers"]), r["error"] or ""])
        console.print(csv_output.getvalue())
    else:
        table = Table(box=box.ROUNDED, header_style="bold magenta", show_lines=True)
        table.add_column("Domain", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Response", style="green")

        for r in results:
            if r["error"]:
                response = Text(r["error"], style="red")
            else:
                response = Text("\n".join(r["answers"]) if r["answers"] else "No data")

            table.add_row(r["domain"], r["record_type"], response)

        console.print(table)

    # Summary
    successful = sum(1 for r in results if not r["error"])
    console.print(f"\n[dim]Completed: {successful}/{len(results)} successful[/dim]")


@app.command()
def doh(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name to query"),
    ],
    record_types: Annotated[
        list[RecordType],
        typer.Option(
            "--type", "-t",
            help="DNS record type(s) to query",
        ),
    ] = [RecordType.A],
    provider: Annotated[
        str | None,
        typer.Option(
            "--provider", "-p",
            help="Specific DoH provider (cloudflare, google, quad9, adguard, nextdns)",
        ),
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option(
            "--output", "-o",
            help="Output format",
        ),
    ] = OutputFormat.TABLE,
) -> None:
    """
    Query DNS over HTTPS (DoH) - bypasses local DNS filtering.

    Uses encrypted HTTPS connections to DNS servers, providing privacy
    and bypassing local network DNS interception.

    Example:
        dnsmenace doh google.com
        dnsmenace doh example.com -t A -t AAAA -p cloudflare
    """
    print_banner()

    console.print(f"\n[bold cyan]DNS over HTTPS Query[/bold cyan]")
    console.print(f"[bold]Domain:[/bold] {domain}")
    console.print(f"[bold]Record types:[/bold] {', '.join(rt.value for rt in record_types)}")
    console.print(f"[dim]Using encrypted HTTPS connections...[/dim]\n")

    # Filter providers if specified
    if provider:
        provider_map = {p.name.lower(): p for p in DOH_PROVIDERS}
        if provider.lower() in provider_map:
            providers = [provider_map[provider.lower()]]
        else:
            console.print(f"[red]Unknown provider: {provider}[/red]")
            console.print(f"Available: {', '.join(provider_map.keys())}")
            raise typer.Exit(1)
    else:
        providers = DOH_PROVIDERS

    results = asyncio.run(run_doh_queries(providers, domain, record_types))

    # Display results
    console.print()
    if output == OutputFormat.TABLE:
        table = Table(
            title="DoH Query Results",
            box=box.ROUNDED,
            header_style="bold magenta",
            show_lines=True,
        )

        table.add_column("Provider", style="cyan", no_wrap=True)
        table.add_column("Country", style="dim")
        table.add_column("Type", style="yellow")
        table.add_column("Response", style="green")
        table.add_column("Time (ms)", justify="right", style="blue")

        for result in results:
            if result.error:
                response = Text(result.error, style="red")
            else:
                response = Text("\n".join(result.answers) if result.answers else "No data")

            time_str = f"{result.response_time_ms:.1f}" if not result.error else "-"

            table.add_row(
                result.nameserver.name,
                result.nameserver.country,
                result.record_type,
                response,
                time_str,
            )

        console.print(table)
    elif output == OutputFormat.JSON:
        display_results_json(results)
    elif output == OutputFormat.CSV:
        display_results_csv(results)

    # Summary
    successful = sum(1 for r in results if not r.error)
    console.print(f"\n[dim]Completed: {successful}/{len(results)} queries successful[/dim]")
    console.print("[dim]All queries used encrypted HTTPS (DoH)[/dim]")


@app.command()
def brute(
    domain: Annotated[
        str,
        typer.Argument(help="Base domain to enumerate subdomains"),
    ],
    wordlist_file: Annotated[
        Path | None,
        typer.Option(
            "--wordlist", "-w",
            help="Custom wordlist file (one subdomain per line)",
        ),
    ] = None,
    use_doh: Annotated[
        bool,
        typer.Option(
            "--doh",
            help="Use DNS over HTTPS for queries",
        ),
    ] = False,
    country: Annotated[
        str | None,
        typer.Option(
            "--country", "-c",
            help="Query using DNS servers from specific country",
        ),
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option(
            "--output", "-o",
            help="Output format",
        ),
    ] = OutputFormat.TABLE,
) -> None:
    """
    Bruteforce subdomain enumeration.

    Discovers subdomains by testing common names against DNS servers.
    Can query from specific countries to find geo-restricted subdomains.

    Example:
        dnsmenace brute example.com
        dnsmenace brute example.com --doh
        dnsmenace brute example.com -c CN -w custom_wordlist.txt
    """
    print_banner()

    console.print(f"\n[bold cyan]Subdomain Enumeration[/bold cyan]")
    console.print(f"[bold]Target:[/bold] {domain}")

    # Load wordlist
    if wordlist_file:
        if not wordlist_file.exists():
            console.print(f"[red]Wordlist file not found: {wordlist_file}[/red]")
            raise typer.Exit(1)
        wordlist = [
            line.strip()
            for line in wordlist_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        console.print(f"[bold]Wordlist:[/bold] {wordlist_file} ({len(wordlist)} entries)")
    else:
        wordlist = SUBDOMAIN_WORDLIST
        console.print(f"[bold]Wordlist:[/bold] Built-in ({len(wordlist)} entries)")

    if use_doh:
        console.print("[bold]Mode:[/bold] DNS over HTTPS (encrypted)")
    elif country:
        try:
            country_info = countries.get(country.upper())
            console.print(f"[bold]Country:[/bold] {country_info.name}")
        except KeyError:
            console.print(f"[red]Invalid country code: {country}[/red]")
            raise typer.Exit(1)
    else:
        console.print("[bold]Mode:[/bold] Default resolver")

    console.print()

    # Get nameserver if country specified
    nameserver_ip = None
    if country and not use_doh:
        with console.status("[bold green]Fetching nameserver..."):
            nameservers = asyncio.run(fetch_nameservers(country, limit=1))
        if nameservers:
            nameserver_ip = nameservers[0].ip
            console.print(f"[dim]Using nameserver: {nameserver_ip}[/dim]\n")

    # Run bruteforce
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Enumerating subdomains...",
            total=len(wordlist),
        )

        async def run_brute():
            found = []
            batch_size = 20

            for i in range(0, len(wordlist), batch_size):
                batch = wordlist[i:i + batch_size]

                async def check_one(sub: str) -> tuple[str, list[str]] | None:
                    fqdn = f"{sub}.{domain}"
                    if use_doh:
                        provider = DOH_PROVIDERS[0]
                        result = await query_doh(provider, fqdn, RecordType.A)
                        if result.answers:
                            return (fqdn, result.answers)
                    else:
                        resolver = dns.asyncresolver.Resolver()
                        if nameserver_ip:
                            resolver.nameservers = [nameserver_ip]
                        resolver.lifetime = 3.0
                        try:
                            answers = await resolver.resolve(fqdn, "A")
                            return (fqdn, [str(r) for r in answers])
                        except dns.exception.DNSException:
                            pass
                    return None

                tasks = [check_one(sub) for sub in batch]
                results = await asyncio.gather(*tasks)

                for result in results:
                    if result:
                        found.append(result)
                        progress.console.print(f"  [green]✓[/green] {result[0]} → {', '.join(result[1])}")

                progress.advance(task, len(batch))

            return found

        found_subdomains = asyncio.run(run_brute())

    console.print()

    if not found_subdomains:
        console.print("[yellow]No subdomains discovered.[/yellow]")
        raise typer.Exit(0)

    # Display results
    if output == OutputFormat.TABLE:
        table = Table(
            title=f"Discovered Subdomains for {domain}",
            box=box.ROUNDED,
            header_style="bold magenta",
            show_lines=True,
        )

        table.add_column("Subdomain", style="cyan")
        table.add_column("IP Address(es)", style="green")

        for fqdn, ips in found_subdomains:
            table.add_row(fqdn, "\n".join(ips))

        console.print(table)
    elif output == OutputFormat.JSON:
        output_data = [{"subdomain": fqdn, "addresses": ips} for fqdn, ips in found_subdomains]
        console.print_json(json.dumps(output_data, indent=2))
    elif output == OutputFormat.CSV:
        csv_output = StringIO()
        writer = csv.writer(csv_output)
        writer.writerow(["subdomain", "addresses"])
        for fqdn, ips in found_subdomains:
            writer.writerow([fqdn, "|".join(ips)])
        console.print(csv_output.getvalue())

    console.print(f"\n[bold green]Found {len(found_subdomains)} subdomain(s)[/bold green]")


@app.command()
def watch(
    domain: Annotated[
        str,
        typer.Argument(help="Domain to monitor"),
    ],
    record_type: Annotated[
        RecordType,
        typer.Option(
            "--type", "-t",
            help="DNS record type to monitor",
        ),
    ] = RecordType.A,
    interval: Annotated[
        int,
        typer.Option(
            "--interval", "-i",
            help="Refresh interval in seconds",
            min=5,
            max=300,
        ),
    ] = 10,
) -> None:
    """
    Live monitoring dashboard for DNS resolution.

    Continuously monitors DNS responses across global servers with
    real-time updates, latency tracking, and TTL countdowns.

    Example:
        dnsmenace watch google.com
        dnsmenace watch example.com -t AAAA -i 30
    """
    print_banner()

    console.print(f"\n[bold cyan]Live DNS Monitor[/bold cyan]")
    console.print(f"[bold]Domain:[/bold] {domain}")
    console.print(f"[bold]Record type:[/bold] {record_type.value}")
    console.print(f"[bold]Refresh interval:[/bold] {interval}s")
    console.print("[dim]Press Ctrl+C to exit[/dim]\n")

    # ASCII globe animation frames
    globe_frames = ["🌍", "🌎", "🌏"]

    def create_dashboard(results: list[DNSResult], frame: int, refresh_count: int) -> Table:
        """Create the live dashboard table."""
        table = Table(
            title=f"{globe_frames[frame % 3]} DNS Monitor - {domain} [{record_type.value}]",
            box=box.ROUNDED,
            header_style="bold magenta",
            show_lines=True,
            caption=f"Refresh #{refresh_count} | Interval: {interval}s | Ctrl+C to exit",
        )

        table.add_column("Server", style="cyan", no_wrap=True)
        table.add_column("Location", style="dim", width=6)
        table.add_column("Response", style="green", max_width=40)
        table.add_column("Latency", justify="right", style="blue", width=10)
        table.add_column("Status", justify="center", width=8)

        for result in results:
            if result.error:
                response = Text(result.error[:35], style="red")
                latency = "-"
                status = Text("✗", style="red")
            else:
                response_text = ", ".join(result.answers) if result.answers else "No data"
                if len(response_text) > 35:
                    response_text = response_text[:32] + "..."
                response = Text(response_text)

                latency_ms = result.response_time_ms
                if latency_ms < 50:
                    latency = Text(f"{latency_ms:.0f}ms", style="green")
                elif latency_ms < 150:
                    latency = Text(f"{latency_ms:.0f}ms", style="yellow")
                else:
                    latency = Text(f"{latency_ms:.0f}ms", style="red")

                status = Text("✓", style="green")

            table.add_row(
                result.nameserver.name,
                result.nameserver.country,
                response,
                latency,
                status,
            )

        return table

    refresh_count = 0
    frame = 0

    try:
        with Live(console=console, refresh_per_second=1, transient=True) as live:
            while True:
                refresh_count += 1

                # Fetch results
                async def fetch():
                    tasks = [
                        query_dns(ns, domain, record_type)
                        for ns in GLOBAL_DNS_SERVERS
                    ]
                    return await asyncio.gather(*tasks)

                results = asyncio.run(fetch())

                # Update display
                dashboard = create_dashboard(results, frame, refresh_count)
                live.update(dashboard)

                # Animate and wait
                for _ in range(interval):
                    frame += 1
                    dashboard = create_dashboard(results, frame, refresh_count)
                    live.update(dashboard)
                    time.sleep(1)

    except KeyboardInterrupt:
        console.print("\n[dim]Monitoring stopped.[/dim]")


@app.command()
def map(
    target: Annotated[
        str,
        typer.Argument(help="Domain or IP address to map"),
    ],
) -> None:
    """
    Visual network path mapping with geolocation.

    Resolves a domain and shows the geographic path from your location
    to the destination, including IP geolocation details.

    Example:
        dnsmenace map google.com
        dnsmenace map 8.8.8.8
    """
    print_banner()

    console.print(f"\n[bold cyan]Network Path Mapping[/bold cyan]")
    console.print(f"[bold]Target:[/bold] {target}\n")

    # Determine if target is IP or domain
    is_ip = False
    try:
        socket.inet_aton(target)
        is_ip = True
        resolved_ips = [target]
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, target)
            is_ip = True
            resolved_ips = [target]
        except socket.error:
            pass

    if not is_ip:
        # Resolve domain
        console.print("[dim]Resolving domain...[/dim]")
        resolver = dns.resolver.Resolver()
        try:
            answers = resolver.resolve(target, "A")
            resolved_ips = [str(r) for r in answers]
            console.print(f"[green]Resolved to: {', '.join(resolved_ips)}[/green]\n")
        except dns.exception.DNSException as e:
            console.print(f"[red]Could not resolve domain: {e}[/red]")
            raise typer.Exit(1)

    # Get geolocation for each IP
    async def get_all_geolocations():
        tasks = [get_ip_geolocation(ip) for ip in resolved_ips]
        return await asyncio.gather(*tasks)

    with console.status("[bold green]Fetching geolocation data..."):
        geolocations = asyncio.run(get_all_geolocations())

    # Build visual map
    tree = Tree(f"[bold cyan]🎯 {target}[/bold cyan]")

    for ip, geo in zip(resolved_ips, geolocations):
        if geo:
            # Build location string
            location_parts = []
            if geo.get("city"):
                location_parts.append(geo["city"])
            if geo.get("regionName"):
                location_parts.append(geo["regionName"])
            if geo.get("country"):
                location_parts.append(geo["country"])
            location = ", ".join(location_parts)

            # Add IP branch
            ip_branch = tree.add(f"[green]📍 {ip}[/green]")
            ip_branch.add(f"[dim]Location:[/dim] {location}")

            if geo.get("lat") and geo.get("lon"):
                ip_branch.add(f"[dim]Coordinates:[/dim] {geo['lat']:.4f}, {geo['lon']:.4f}")

            if geo.get("isp"):
                ip_branch.add(f"[dim]ISP:[/dim] {geo['isp']}")

            if geo.get("org"):
                ip_branch.add(f"[dim]Organization:[/dim] {geo['org']}")

            if geo.get("as"):
                ip_branch.add(f"[dim]ASN:[/dim] {geo['as']}")

            if geo.get("timezone"):
                ip_branch.add(f"[dim]Timezone:[/dim] {geo['timezone']}")
        else:
            tree.add(f"[yellow]📍 {ip}[/yellow] - [dim]Geolocation unavailable[/dim]")

    console.print(tree)

    # ASCII Map visualization
    if geolocations and any(g and g.get("lat") and g.get("lon") for g in geolocations):
        console.print("\n[bold]Geographic Distribution:[/bold]")

        # Simple ASCII world map representation
        map_width = 60
        map_height = 15

        # Create empty map
        world_map = [[" " for _ in range(map_width)] for _ in range(map_height)]

        # Add simple continent outlines (very simplified)
        continents = "." * map_width
        for row in range(map_height):
            world_map[row] = list(continents)

        # Plot IPs on map
        markers = []
        for geo in geolocations:
            if geo and geo.get("lat") and geo.get("lon"):
                # Convert lat/lon to map coordinates
                lat = geo["lat"]
                lon = geo["lon"]

                # Map -180 to 180 longitude to 0 to map_width
                x = int((lon + 180) / 360 * map_width)
                # Map 90 to -90 latitude to 0 to map_height
                y = int((90 - lat) / 180 * map_height)

                x = max(0, min(map_width - 1, x))
                y = max(0, min(map_height - 1, y))

                world_map[y][x] = "●"
                markers.append((x, y, geo.get("countryCode", "?")))

        # Print map with box
        console.print("┌" + "─" * map_width + "┐")
        for row in world_map:
            line = "".join(row)
            # Highlight markers
            line = line.replace("●", "[bold red]●[/bold red]")
            console.print(f"│{line}│")
        console.print("└" + "─" * map_width + "┘")

        # Legend
        console.print("\n[dim]● = Server location[/dim]")

    # Summary table
    console.print("\n[bold]Resolution Summary:[/bold]")
    summary_table = Table(box=box.SIMPLE, show_header=True)
    summary_table.add_column("IP Address", style="cyan")
    summary_table.add_column("Country", style="green")
    summary_table.add_column("Organization", style="dim")

    for ip, geo in zip(resolved_ips, geolocations):
        if geo:
            summary_table.add_row(
                ip,
                f"{geo.get('country', 'Unknown')} ({geo.get('countryCode', '?')})",
                geo.get("org", "Unknown"),
            )
        else:
            summary_table.add_row(ip, "Unknown", "Unknown")

    console.print(summary_table)


@app.command()
def countries_list(
    search: Annotated[
        str | None,
        typer.Option(
            "--search", "-s",
            help="Search for a country by name",
        ),
    ] = None,
) -> None:
    """
    List all available country codes.

    Example:
        dnsmenace countries-list
        dnsmenace countries-list --search germany
    """
    print_banner()

    table = Table(
        title="Available Countries",
        box=box.ROUNDED,
        header_style="bold magenta",
    )

    table.add_column("Code", style="cyan", no_wrap=True)
    table.add_column("Country", style="green")

    filtered_countries = []
    for c in countries:
        if search is None or search.lower() in c.name.lower():
            filtered_countries.append((c.alpha2, c.name))

    filtered_countries.sort(key=lambda x: x[1])

    for code, name in filtered_countries:
        table.add_row(code, name)

    console.print(table)
    console.print(f"\n[dim]Total: {len(filtered_countries)} countries[/dim]")


@app.command()
def lookup(
    country_name: Annotated[
        str,
        typer.Argument(help="Country name to look up"),
    ],
) -> None:
    """
    Look up a country code by name.

    Example:
        dnsmenace lookup "United States"
        dnsmenace lookup Germany
    """
    matches = []
    for c in countries:
        if country_name.lower() in c.name.lower():
            matches.append(c)

    if not matches:
        console.print(f"[red]No countries found matching '{country_name}'[/red]")
        raise typer.Exit(1)

    table = Table(box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Code", style="cyan")
    table.add_column("Country", style="green")

    for c in matches:
        table.add_row(c.alpha2, c.name)

    console.print(table)


@app.command()
def servers(
    country: Annotated[
        str,
        typer.Argument(help="Two-letter country code"),
    ],
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum number of servers to show"),
    ] = 20,
) -> None:
    """
    List available DNS servers for a country.

    Example:
        dnsmenace servers US --limit 10
    """
    print_banner()

    try:
        country_info = countries.get(country.upper())
        console.print(f"\n[bold]DNS Servers in {country_info.name}[/bold]\n")
    except KeyError:
        console.print(f"[red]Invalid country code: {country}[/red]")
        raise typer.Exit(1)

    with console.status("[bold green]Fetching nameservers..."):
        nameservers = asyncio.run(fetch_nameservers(country, limit))

    if not nameservers:
        console.print("[red]No nameservers found.[/red]")
        raise typer.Exit(1)

    table = Table(box=box.ROUNDED, header_style="bold magenta")
    table.add_column("IP Address", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Reliability", justify="right", style="yellow")

    for ns in nameservers:
        reliability = f"{ns.reliability:.1f}%" if ns.reliability else "N/A"
        table.add_row(ns.ip, ns.name or "Unknown", reliability)

    console.print(table)
    console.print(f"\n[dim]Found {len(nameservers)} nameservers[/dim]")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", "-v", help="Show version and exit"),
    ] = False,
) -> None:
    """
    DNSMenace - Query DNS servers from any country in the world.

    A powerful tool for security researchers, network administrators,
    and anyone interested in global DNS infrastructure.
    """
    if version:
        console.print("[bold cyan]dnsmenace[/bold cyan] version [green]3.0.0[/green]")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(Panel(
            "[bold]🔍 Security Research:[/bold]\n\n"
            "  [cyan]dnsmenace compare google.com -c US -c CN -c RU[/cyan]\n"
            "    Geo-diff mode - detect censorship & DNS poisoning\n\n"
            "  [cyan]dnsmenace brute example.com --doh[/cyan]\n"
            "    Subdomain enumeration (with DoH bypass)\n\n"
            "  [cyan]dnsmenace security example.com[/cyan]\n"
            "    Check SPF, DKIM, DMARC, CAA records\n\n"
            "  [cyan]dnsmenace axfr example.com[/cyan]\n"
            "    Zone transfer vulnerability test\n\n"
            "[bold]🔒 Privacy Mode (DoH):[/bold]\n\n"
            "  [cyan]dnsmenace doh google.com -t A -t AAAA[/cyan]\n"
            "    DNS over HTTPS - bypass local filtering\n\n"
            "[bold]📡 Monitoring & Mapping:[/bold]\n\n"
            "  [cyan]dnsmenace watch example.com -i 10[/cyan]\n"
            "    Live dashboard with global monitoring\n\n"
            "  [cyan]dnsmenace map google.com[/cyan]\n"
            "    Visual network path with geolocation\n\n"
            "[bold]🌐 Query Commands:[/bold]\n\n"
            "  [cyan]dnsmenace query -c DE -d google.com[/cyan]\n"
            "    Query from specific country\n\n"
            "  [cyan]dnsmenace propagation example.com[/cyan]\n"
            "    Global DNS propagation check\n\n"
            "Run [bold]dnsmenace --help[/bold] for all options.",
            title="Welcome to DNSMenace v3.0",
            border_style="cyan",
        ))


if __name__ == "__main__":
    app()
