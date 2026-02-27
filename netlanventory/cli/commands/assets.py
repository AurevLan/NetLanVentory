"""CLI commands for asset management."""

from __future__ import annotations

import click

from netlanventory.cli.output import asset_detail, assets_table, console


@click.group("assets")
def assets_cmd() -> None:
    """Browse and search discovered assets."""


@assets_cmd.command("list")
@click.option("--limit", default=50, show_default=True, help="Max rows to display")
@click.option("--active-only", is_flag=True, default=False, help="Show only active assets")
@click.option("--filter", "filter_str", default="", help="Filter by IP/MAC/hostname")
@click.pass_context
def assets_list(
    ctx: click.Context, limit: int, active_only: bool, filter_str: str
) -> None:
    """List all discovered assets."""
    import httpx

    api_url: str = ctx.obj["api_url"]
    params: dict[str, str | int] = {"limit": limit}
    if active_only:
        params["active_only"] = "true"

    try:
        r = httpx.get(f"{api_url}/api/v1/assets", params=params, timeout=15)
        r.raise_for_status()
        items = r.json()["items"]

        if filter_str:
            fl = filter_str.lower()
            items = [
                a for a in items
                if fl in (a.get("ip") or "").lower()
                or fl in (a.get("mac") or "").lower()
                or fl in (a.get("hostname") or "").lower()
            ]

        console.print(assets_table(items))
        console.print(f"[dim]Showing {len(items)} of {r.json()['total']} assets.[/dim]")
    except httpx.ConnectError:
        console.print(f"[red]Cannot connect to API at {api_url}.[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


@assets_cmd.command("show")
@click.argument("ip_or_id")
@click.pass_context
def assets_show(ctx: click.Context, ip_or_id: str) -> None:
    """Show detailed information for an asset by IP or UUID."""
    import httpx

    api_url: str = ctx.obj["api_url"]
    try:
        # Try by IP first, then by UUID
        url = f"{api_url}/api/v1/assets/by-ip/{ip_or_id}"
        r = httpx.get(url, timeout=10)
        if r.status_code == 404:
            r = httpx.get(f"{api_url}/api/v1/assets/{ip_or_id}", timeout=10)
        r.raise_for_status()
        asset_detail(r.json())
    except httpx.ConnectError:
        console.print(f"[red]Cannot connect to API at {api_url}.[/red]")
        raise SystemExit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            console.print(f"[yellow]Asset {ip_or_id!r} not found.[/yellow]")
        else:
            console.print(f"[red]Error {e.response.status_code}:[/red] {e.response.text}")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)
