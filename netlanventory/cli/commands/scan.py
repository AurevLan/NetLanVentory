"""CLI commands for running scans."""

from __future__ import annotations

import time

import click

from netlanventory.cli.output import console, scans_table, status_style


@click.group("scan")
def scan_cmd() -> None:
    """Network scanning operations."""


@scan_cmd.command("run")
@click.option(
    "--target", required=True, help="Target CIDR or IP (e.g. 192.168.1.0/24)"
)
@click.option(
    "--modules",
    default="arp_sweep",
    show_default=True,
    help="Comma-separated list of module slugs",
)
@click.option(
    "--wait/--no-wait",
    default=True,
    show_default=True,
    help="Wait for scan to finish before returning",
)
@click.option(
    "--poll-interval",
    default=3,
    show_default=True,
    help="Polling interval in seconds when --wait is set",
)
@click.pass_context
def scan_run(
    ctx: click.Context,
    target: str,
    modules: str,
    wait: bool,
    poll_interval: int,
) -> None:
    """Start a new network scan.

    Example:

        netlv scan run --target 192.168.1.0/24 \\
            --modules arp_sweep,port_scanner,service_detector,os_fingerprint
    """
    import httpx
    from rich.text import Text

    api_url: str = ctx.obj["api_url"]
    module_list = [m.strip() for m in modules.split(",") if m.strip()]

    console.print(f"[bold cyan]Starting scan[/bold cyan] on [bold]{target}[/bold]")
    console.print(f"  Modules: [dim]{', '.join(module_list)}[/dim]")

    try:
        r = httpx.post(
            f"{api_url}/api/v1/scans",
            json={"target": target, "modules": module_list},
            timeout=15,
        )
        r.raise_for_status()
        scan = r.json()
        scan_id = scan["id"]
        console.print(f"  Scan ID: [dim]{scan_id}[/dim]")
        console.print(f"  Status:  {Text(scan['status'], style=status_style(scan['status']))}")
    except httpx.ConnectError:
        console.print(f"[red]Cannot connect to API at {api_url}.[/red]")
        raise SystemExit(1)
    except httpx.HTTPStatusError as e:
        console.print(f"[red]API error {e.response.status_code}:[/red] {e.response.text}")
        raise SystemExit(1)

    if not wait:
        return

    # Poll until done
    terminal_states = {"completed", "completed_with_errors", "failed", "error"}
    with console.status("[dim]Waiting for scan to complete…[/dim]") as spinner:
        while True:
            time.sleep(poll_interval)
            try:
                r2 = httpx.get(f"{api_url}/api/v1/scans/{scan_id}", timeout=10)
                r2.raise_for_status()
                updated = r2.json()
                current_status = updated.get("status", "?")
                spinner.update(
                    f"[dim]Scan status: {current_status}[/dim]"
                )
                if current_status in terminal_states:
                    break
            except Exception as e:
                console.print(f"[yellow]Poll error:[/yellow] {e}")
                time.sleep(poll_interval)

    status = updated.get("status", "?")
    from rich.text import Text

    status_text = Text(status, style=status_style(status))
    console.print(f"\n[bold]Scan complete[/bold] — ", end="")
    console.print(status_text)

    summary = updated.get("summary", {}) or {}
    if summary.get("modules"):
        console.print("\n[dim]Module results:[/dim]")
        for mod_name, mod_info in summary["modules"].items():
            mod_status = mod_info.get("status", "?")
            assets_found = mod_info.get("assets_found", 0)
            err = mod_info.get("error", "")
            s_text = Text(mod_status, style=status_style(mod_status))
            line = f"  [cyan]{mod_name:<24}[/cyan] "
            console.print(line, end="")
            console.print(s_text, end="")
            if assets_found:
                console.print(f"  ({assets_found} assets)", end="")
            if err:
                console.print(f"  [red]{err}[/red]", end="")
            console.print()


@scan_cmd.command("list")
@click.option("--limit", default=20, show_default=True)
@click.pass_context
def scan_list(ctx: click.Context, limit: int) -> None:
    """List recent scans."""
    import httpx

    api_url: str = ctx.obj["api_url"]
    try:
        r = httpx.get(f"{api_url}/api/v1/scans", params={"limit": limit}, timeout=10)
        r.raise_for_status()
        items = r.json()["items"]
        console.print(scans_table(items))
    except httpx.ConnectError:
        console.print(f"[red]Cannot connect to API at {api_url}.[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)
