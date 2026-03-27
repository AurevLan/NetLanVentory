"""CLI commands for cryptographic operations.

netlv crypto rotate-key --old-key HEX --new-key HEX
    Re-encrypts all SSH credentials using the new key.
"""

from __future__ import annotations

import asyncio

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group("crypto")
def crypto_cmd() -> None:
    """Cryptographic operations — key rotation, credential re-encryption."""


@crypto_cmd.command("rotate-key")
@click.option(
    "--old-key",
    required=True,
    envvar="OLD_SECRET_KEY",
    help="Current SECRET_KEY value (hex or plain string)",
)
@click.option(
    "--new-key",
    required=True,
    envvar="NEW_SECRET_KEY",
    help="New SECRET_KEY value to encrypt with",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Count affected rows without making changes",
)
def rotate_key(old_key: str, new_key: str, dry_run: bool) -> None:
    """Re-encrypt all SSH credentials with a new SECRET_KEY.

    This command decrypts every ssh_password_enc and ssh_private_key_enc
    field in Asset and SshProfile using the old key, then re-encrypts them
    with the new key. The operation is transactional — any failure triggers
    a full rollback.

    After running this command, update SECRET_KEY in your .env file.
    """
    if dry_run:
        console.print("[yellow]DRY RUN — no changes will be made[/yellow]")

    asyncio.run(_do_rotate(old_key, new_key, dry_run))


async def _do_rotate(old_key: str, new_key: str, dry_run: bool) -> None:
    import base64
    import hashlib

    from cryptography.fernet import Fernet, InvalidToken

    from netlanventory.core.database import get_session_factory
    from netlanventory.models.asset import Asset
    from netlanventory.models.ssh_profile import SshProfile
    from sqlalchemy import select

    def _make_fernet(key_str: str) -> Fernet:
        raw = key_str.encode()
        digest = hashlib.sha256(raw).digest()
        return Fernet(base64.urlsafe_b64encode(digest))

    old_fernet = _make_fernet(old_key)
    new_fernet = _make_fernet(new_key)

    def _reencrypt(ciphertext: str | None) -> str | None:
        if not ciphertext:
            return ciphertext
        try:
            plaintext = old_fernet.decrypt(ciphertext.encode())
            return new_fernet.encrypt(plaintext).decode()
        except InvalidToken:
            raise click.ClickException(
                f"Decryption failed — check that --old-key matches the current SECRET_KEY"
            )

    factory = get_session_factory()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Rotating credentials...", total=None)

        async with factory() as session:
            # Assets
            result = await session.execute(
                select(Asset).where(
                    (Asset.ssh_password_enc.isnot(None))
                    | (Asset.ssh_private_key_enc.isnot(None))
                )
            )
            assets = result.scalars().all()
            progress.update(task, description=f"Found {len(assets)} assets with SSH credentials")

            asset_count = 0
            for asset in assets:
                new_pw = _reencrypt(asset.ssh_password_enc)
                new_key_enc = _reencrypt(asset.ssh_private_key_enc)
                if not dry_run:
                    asset.ssh_password_enc = new_pw
                    asset.ssh_private_key_enc = new_key_enc
                asset_count += 1

            # SSH Profiles
            result2 = await session.execute(
                select(SshProfile).where(
                    (SshProfile.ssh_password_enc.isnot(None))
                    | (SshProfile.ssh_private_key_enc.isnot(None))
                )
            )
            profiles = result2.scalars().all()
            profile_count = 0
            for profile in profiles:
                new_pw = _reencrypt(profile.ssh_password_enc)
                new_key_enc = _reencrypt(profile.ssh_private_key_enc)
                if not dry_run:
                    profile.ssh_password_enc = new_pw
                    profile.ssh_private_key_enc = new_key_enc
                profile_count += 1

            if not dry_run:
                await session.commit()
                progress.update(task, description="Done ✓")

    if dry_run:
        console.print(
            f"[yellow]DRY RUN:[/yellow] Would re-encrypt "
            f"[bold]{asset_count}[/bold] asset(s) and "
            f"[bold]{profile_count}[/bold] SSH profile(s)."
        )
        console.print("Run without [cyan]--dry-run[/cyan] to apply.")
    else:
        console.print(
            f"[green]✓[/green] Re-encrypted "
            f"[bold]{asset_count}[/bold] asset(s) and "
            f"[bold]{profile_count}[/bold] SSH profile(s)."
        )
        console.print(
            "[yellow]Now update SECRET_KEY in your .env file to the new value.[/yellow]"
        )
