#!/usr/bin/env python3
"""
dnsmenace - Global DNS Query Tool

Query DNS servers from any country in the world. Perfect for security research,
network debugging, and understanding global DNS infrastructure.
"""

from __future__ import annotations

import asyncio
import csv
import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from io import StringIO
from pathlib import Path
from typing import Annotated

import dns.asyncresolver
import dns.resolver
import httpx
from iso3166 import countries
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
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

[dim]Global DNS Query Tool v2.0.0[/dim]
"""
    console.print(banner)


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
        console.print("Use 'dnsmenace countries' to see available codes.")
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
    match output:
        case OutputFormat.TABLE:
            display_results_table(results)
        case OutputFormat.JSON:
            display_results_json(results)
        case OutputFormat.CSV:
            display_results_csv(results)

    # Summary
    successful = sum(1 for r in results if not r.error)
    console.print(f"\n[dim]Completed: {successful}/{len(results)} queries successful[/dim]")


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
        console.print("[bold cyan]dnsmenace[/bold cyan] version [green]2.0.0[/green]")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(Panel(
            "[bold]Quick Start:[/bold]\n\n"
            "  [cyan]dnsmenace query -c US -d example.com[/cyan]\n"
            "    Query US DNS servers for example.com\n\n"
            "  [cyan]dnsmenace query -c DE -d google.com -t A -t MX[/cyan]\n"
            "    Query German servers for A and MX records\n\n"
            "  [cyan]dnsmenace countries-list --search japan[/cyan]\n"
            "    Search for country codes\n\n"
            "  [cyan]dnsmenace servers JP --limit 10[/cyan]\n"
            "    List DNS servers in Japan\n\n"
            "Run [bold]dnsmenace --help[/bold] for all options.",
            title="Welcome to DNSMenace",
            border_style="cyan",
        ))


if __name__ == "__main__":
    app()
