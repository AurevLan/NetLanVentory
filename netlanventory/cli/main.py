"""NetLanVentory CLI entry point — `netlv` command group."""

from __future__ import annotations

import click

from netlanventory.cli.commands.assets import assets_cmd
from netlanventory.cli.commands.modules import modules_cmd
from netlanventory.cli.commands.scan import scan_cmd


@click.group()
@click.version_option(package_name="netlanventory")
@click.option(
    "--api-url",
    default="http://localhost:8000",
    envvar="NETLV_API_URL",
    show_default=True,
    help="Base URL of the NetLanVentory API server",
)
@click.pass_context
def cli(ctx: click.Context, api_url: str) -> None:
    """NetLanVentory — Modular network scanning and inventory tool.

    \b
    Quick start:
      netlv modules list
      netlv scan run --target 192.168.1.0/24 --modules arp_sweep,port_scanner
      netlv assets list
      netlv assets show 192.168.1.1

    API docs: http://localhost:8000/docs
    Dashboard: http://localhost:8000
    """
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url.rstrip("/")


# Register sub-commands
cli.add_command(scan_cmd)
cli.add_command(assets_cmd)
cli.add_command(modules_cmd)


@cli.command("serve")
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host")
@click.option("--port", default=8000, show_default=True, help="Bind port")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (dev mode)")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the NetLanVentory API server."""
    import uvicorn

    uvicorn.run(
        "netlanventory.api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    cli()
