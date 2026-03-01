"""CLI entry point: opnboss serve | scan | status."""

from __future__ import annotations

import asyncio
import sys

import typer
from rich import box
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="opnboss",
    help="OPNBoss — OPNSense Analyzer & Recommendation Service",
    no_args_is_help=True,
)
console = Console()


def _load_config(config_path: str) -> AppConfig:  # type: ignore[name-defined]  # noqa: F821
    from dotenv import load_dotenv

    from opn_boss.core.config import load_config

    load_dotenv()
    return load_config(config_path)


@app.command()
def serve(
    config: str = typer.Option("config/config.yaml", "--config", "-c", help="Path to config YAML"),
    host: str | None = typer.Option(None, "--host", help="Override API host"),
    port: int | None = typer.Option(None, "--port", "-p", help="Override API port"),
) -> None:
    """Start the OPNBoss web server and background scheduler."""
    import uvicorn

    from opn_boss.api.app import create_app
    from opn_boss.core.logging_config import configure_logging

    cfg = _load_config(config)
    configure_logging(cfg.logging.level, cfg.logging.format)

    actual_host = host or cfg.api.host
    actual_port = port or cfg.api.port

    console.print(f"[bold green]OPNBoss[/bold green] starting on http://{actual_host}:{actual_port}")
    console.print(f"  Config: {config}")
    console.print(f"  Firewalls: {', '.join(fw.firewall_id for fw in cfg.firewalls)}")

    fastapi_app = create_app(cfg)

    uvicorn.run(
        fastapi_app,
        host=actual_host,
        port=actual_port,
        log_level="warning",
    )


@app.command()
def scan(
    config: str = typer.Option("config/config.yaml", "--config", "-c", help="Path to config YAML"),
    firewall: str | None = typer.Option(None, "--firewall", "-f", help="Scan only this firewall ID"),
    json_output: bool = typer.Option(False, "--json", help="Output findings as JSON"),
) -> None:
    """Run an immediate scan and print findings to the terminal."""
    from opn_boss.core.database import create_tables
    from opn_boss.core.logging_config import configure_logging
    from opn_boss.service.main import OPNBossService

    cfg = _load_config(config)
    configure_logging(cfg.logging.level, cfg.logging.format)

    async def _run() -> None:
        await create_tables(cfg.database.url)

        service = OPNBossService(cfg)

        if firewall:
            # Filter config to only the requested firewall
            filtered_fws = [fw for fw in cfg.firewalls if fw.firewall_id == firewall]
            if not filtered_fws:
                console.print(f"[red]Firewall '{firewall}' not found in config[/red]")
                sys.exit(1)
            cfg.firewalls = filtered_fws

        console.print("[bold]Starting scan...[/bold]")
        summaries = await service.run_scan()

        if json_output:
            import json
            all_findings = []
            for s in summaries:
                for f in s.findings:
                    all_findings.append(f.to_dict())
            console.print(json.dumps(all_findings, indent=2, default=str))
            return

        for summary in summaries:
            _print_summary(summary)

    asyncio.run(_run())


def _print_summary(summary: SnapshotSummary) -> None:  # type: ignore[name-defined]  # noqa: F821
    from opn_boss.core.types import Severity

    status_color = {
        "completed": "green",
        "offline": "red",
        "failed": "red",
        "running": "yellow",
    }.get(summary.status, "white")

    console.print(
        f"\n[bold]Firewall:[/bold] {summary.firewall_id} "
        f"[{status_color}]({summary.status})[/{status_color}]"
    )
    console.print(
        f"  Critical: [red]{summary.critical_count}[/red]  "
        f"Warning: [yellow]{summary.warning_count}[/yellow]  "
        f"Info: [blue]{summary.info_count}[/blue]  "
        f"OK: [green]{summary.ok_count}[/green]"
    )

    if not summary.findings:
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold gray50")
    table.add_column("Severity", style="", width=10)
    table.add_column("Check", style="cyan", width=12)
    table.add_column("Title", style="", min_width=30)
    table.add_column("Category", style="gray50", width=14)

    severity_order = [Severity.CRITICAL, Severity.WARNING, Severity.INFO, Severity.OK]
    severity_styles = {
        Severity.CRITICAL: "red",
        Severity.WARNING: "yellow",
        Severity.INFO: "blue",
        Severity.OK: "green",
    }

    sorted_findings = sorted(
        summary.findings, key=lambda f: severity_order.index(f.severity)
    )

    for finding in sorted_findings:
        style = severity_styles.get(finding.severity, "white")
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/{style}]",
            finding.check_id,
            finding.title,
            finding.category.value,
        )

    console.print(table)

    # Print remediation for critical findings
    critical = [f for f in sorted_findings if f.severity.value == "critical"]
    for f in critical:
        if f.remediation:
            console.rule(f"[red]Remediation: {f.check_id}[/red]")
            console.print(f.remediation)


@app.command()
def status(
    config: str = typer.Option("config/config.yaml", "--config", "-c", help="Path to config YAML"),
) -> None:
    """Show current firewall reachability status."""
    from opn_boss.core.database import create_tables
    from opn_boss.core.logging_config import configure_logging
    from opn_boss.service.main import OPNBossService

    cfg = _load_config(config)
    configure_logging("WARNING", "text")

    async def _run() -> None:
        await create_tables(cfg.database.url)
        service = OPNBossService(cfg)
        states = await service.get_firewall_states()

        if not states:
            # No DB state yet — probe directly
            from opn_boss.opnsense.client import OPNSenseClient
            console.print("[yellow]No scan history found. Probing firewalls...[/yellow]")
            for fw in cfg.firewalls:
                client = OPNSenseClient(fw)
                online = await client.probe()
                status_str = "[green]ONLINE[/green]" if online else "[red]OFFLINE[/red]"
                console.print(f"  {fw.firewall_id} ({fw.role}): {status_str}")
            return

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Firewall", width=20)
        table.add_column("Role", width=10)
        table.add_column("Status", width=10)
        table.add_column("Last Seen", width=22)
        table.add_column("Last Checked", width=22)

        for s in states:
            status_str = "[green]ONLINE[/green]" if s["online"] else "[red]OFFLINE[/red]"
            table.add_row(
                s["firewall_id"],
                s["role"],
                status_str,
                s.get("last_seen") or "—",
                s.get("last_checked") or "—",
            )

        console.print(table)

    asyncio.run(_run())


if __name__ == "__main__":
    app()
