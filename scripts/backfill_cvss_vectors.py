"""Backfill ``cves.cvss_vector`` on rows scored before the column existed.

The SSVC engine (innovation #6, V2) derives Automatable / Technical Impact from
the CVSS vector when present, falling back to EPSS / base-score proxies when not.
Normal enrichment never revisits already-scored CVEs, so this one-shot drains
``cvss_vector IS NULL`` via OSV (+ NVD for canonical IDs).

Run inside the app container (it already has DATABASE_URL + deps). With the
stack up (``docker compose up -d``):

    docker compose run --rm api python scripts/backfill_cvss_vectors.py

    # preview without writing, or cap the work
    docker compose run --rm api python scripts/backfill_cvss_vectors.py --dry-run
    docker compose run --rm api python scripts/backfill_cvss_vectors.py \
        --batch-limit 40 --max-batches 5

After it completes, the hourly scheduler recomputes SSVC automatically; force it
sooner by restarting the API or hitting the SSVC endpoint per (cve, asset).
"""

from __future__ import annotations

import argparse
import asyncio

from netlanventory.core.config import get_settings
from netlanventory.core.cve_enrichment import backfill_cvss_vectors
from netlanventory.core.database import close_engine, get_session_factory


async def _run(batch_limit: int, max_batches: int | None, dry_run: bool) -> int:
    settings = get_settings()
    factory = get_session_factory()

    total_processed = 0
    total_updated = 0
    after_id = None
    batch_no = 0

    while True:
        if max_batches is not None and batch_no >= max_batches:
            print(f"Reached --max-batches={max_batches}, stopping early.")
            break

        async with factory() as session:
            processed, updated, last_id = await backfill_cvss_vectors(
                session,
                nvd_api_key=settings.nvd_api_key,
                batch_limit=batch_limit,
                after_id=after_id,
            )
            if dry_run:
                await session.rollback()
            else:
                await session.commit()

        if processed == 0:
            break

        batch_no += 1
        total_processed += processed
        total_updated += updated
        after_id = last_id
        print(
            f"batch {batch_no}: processed={processed} updated={updated} "
            f"(running total: {total_updated}/{total_processed})"
            + ("  [dry-run, rolled back]" if dry_run else "")
        )

    print(
        f"\nDone. {total_updated} vector(s) populated across {total_processed} "
        f"CVE(s) examined in {batch_no} batch(es)."
        + ("  No changes written (--dry-run)." if dry_run else "")
    )
    return total_updated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--batch-limit", type=int, default=60,
        help="CVEs fetched per batch (default: 60). Each row hits OSV (+NVD).",
    )
    parser.add_argument(
        "--max-batches", type=int, default=None,
        help="Stop after N batches (default: drain everything).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Fetch and report, but roll back every batch (no writes).",
    )
    args = parser.parse_args()

    try:
        asyncio.run(_run(args.batch_limit, args.max_batches, args.dry_run))
    finally:
        asyncio.run(close_engine())


if __name__ == "__main__":
    main()
