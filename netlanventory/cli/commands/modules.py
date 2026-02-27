"""CLI commands for module management."""

from __future__ import annotations

import click

from netlanventory.cli.output import console, modules_table


@click.group("modules")
def modules_cmd() -> None:
    """Manage and inspect scanning modules."""


@modules_cmd.command("list")
@click.pass_context
def modules_list(ctx: click.Context) -> None:
    """List all available scanning modules."""
    import httpx

    api_url: str = ctx.obj["api_url"]
    try:
        r = httpx.get(f"{api_url}/api/v1/modules", timeout=10)
        r.raise_for_status()
        data = r.json()
        console.print(modules_table(data["items"]))
    except httpx.ConnectError:
        console.print(
            f"[red]Cannot connect to API at {api_url}.[/red] "
            "Is the server running? (netlv serve)"
        )
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)
