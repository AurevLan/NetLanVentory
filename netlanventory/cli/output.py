"""Rich output helpers — tables, progress bars, status display."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from rich import print as rprint
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

console = Console()


def status_style(status: str) -> str:
    return {
        "completed": "green",
        "running": "yellow",
        "pending": "dim",
        "failed": "red",
        "error": "red",
        "completed_with_errors": "yellow",
        "success": "green",
        "open": "green",
        "closed": "dim",
        "filtered": "yellow",
    }.get(status, "white")


def fmt_date(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


def assets_table(items: list[dict[str, Any]]) -> Table:
    table = Table(
        title=f"Assets ({len(items)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        show_lines=False,
    )
    table.add_column("IP", style="bold", no_wrap=True)
    table.add_column("MAC", style="dim", no_wrap=True)
    table.add_column("Hostname")
    table.add_column("Vendor")
    table.add_column("OS")
    table.add_column("Open ports", justify="right")
    table.add_column("Active", justify="center")
    table.add_column("Last seen", style="dim")

    for a in items:
        ports = a.get("ports", [])
        open_ports = [p for p in ports if p.get("state") == "open"]
        port_str = ", ".join(f"{p['port_number']}/{p['protocol']}" for p in open_ports[:8])
        if len(open_ports) > 8:
            port_str += f" +{len(open_ports) - 8}"

        active_text = Text("✓", style="green") if a.get("is_active") else Text("✗", style="dim")

        table.add_row(
            a.get("ip") or "—",
            a.get("mac") or "—",
            a.get("hostname") or "—",
            a.get("vendor") or "—",
            a.get("os_family") or "—",
            port_str or "—",
            active_text,
            fmt_date(a.get("last_seen")),
        )

    return table


def asset_detail(a: dict[str, Any]) -> None:
    """Print detailed view of a single asset."""
    console.rule(f"[bold cyan]Asset — {a.get('ip') or a.get('id')}")

    fields = [
        ("ID", a.get("id")),
        ("IP", a.get("ip")),
        ("MAC", a.get("mac")),
        ("Hostname", a.get("hostname")),
        ("Vendor", a.get("vendor")),
        ("Device type", a.get("device_type")),
        ("OS family", a.get("os_family")),
        ("OS version", a.get("os_version")),
        ("Active", str(a.get("is_active"))),
        ("Last seen", fmt_date(a.get("last_seen"))),
        ("Created", fmt_date(a.get("created_at"))),
    ]

    for label, value in fields:
        if value:
            console.print(f"  [dim]{label:<14}[/dim] {value}")

    ports = a.get("ports", [])
    if ports:
        console.print()
        port_table = Table(
            title="Open ports",
            header_style="bold cyan",
            border_style="dim",
            show_lines=False,
        )
        port_table.add_column("Port", justify="right")
        port_table.add_column("Proto")
        port_table.add_column("State")
        port_table.add_column("Service")
        port_table.add_column("Version")
        for p in ports:
            state_text = Text(p.get("state", "?"), style=status_style(p.get("state", "")))
            port_table.add_row(
                str(p.get("port_number", "")),
                p.get("protocol", ""),
                state_text,
                p.get("service_name") or "",
                p.get("version") or "",
            )
        console.print(port_table)


def scans_table(items: list[dict[str, Any]]) -> Table:
    table = Table(
        title=f"Scans ({len(items)})",
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Target")
    table.add_column("Modules")
    table.add_column("Status")
    table.add_column("Started", style="dim")
    table.add_column("Finished", style="dim")

    for s in items:
        modules = ", ".join(s.get("modules_run") or [])
        status = s.get("status", "?")
        status_text = Text(status, style=status_style(status))
        table.add_row(
            str(s.get("id", ""))[:8] + "…",
            s.get("target", ""),
            modules,
            status_text,
            fmt_date(s.get("started_at")),
            fmt_date(s.get("finished_at")),
        )
    return table


def modules_table(items: list[dict[str, Any]]) -> Table:
    table = Table(
        title=f"Available modules ({len(items)})",
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Name", style="bold")
    table.add_column("Display name")
    table.add_column("Category")
    table.add_column("Root?", justify="center")
    table.add_column("Version", style="dim")
    table.add_column("Description")

    for m in items:
        root_text = Text("✓", style="yellow") if m.get("requires_root") else Text("—", style="dim")
        table.add_row(
            m.get("name", ""),
            m.get("display_name", ""),
            m.get("category", ""),
            root_text,
            m.get("version", ""),
            m.get("description", ""),
        )
    return table


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    )
