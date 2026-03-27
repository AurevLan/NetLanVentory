"""Server-Sent Events (SSE) router — real-time scan updates and notifications.

Clients connect to GET /events/stream?token=JWT and receive a stream of
JSON events as they happen (scan status changes, new CVEs, etc.).

Implementation uses a global asyncio.Queue-based fan-out:
- Producers (scan runners, scheduler) push events via `broadcast_event()`
- This endpoint pops events from per-client queues

The token is passed as a query parameter because EventSource (browser API)
does not support custom headers.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/events", tags=["events"])

# Global set of active client queues — each client has its own asyncio.Queue
_client_queues: set[asyncio.Queue] = set()

_HEARTBEAT_INTERVAL = 15  # seconds between keepalive pings


async def broadcast_event(event_type: str, payload: dict) -> None:
    """Push an event to all connected SSE clients.

    Call this from scan runners, scheduler, notifications, etc.
    Fire-and-forget — does not block.
    """
    data = json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **payload,
    }, default=str)

    dead: set[asyncio.Queue] = set()
    for queue in list(_client_queues):
        try:
            queue.put_nowait(data)
        except asyncio.QueueFull:
            dead.add(queue)

    for queue in dead:
        _client_queues.discard(queue)


async def _event_generator(token: str) -> AsyncGenerator[str, None]:
    """Yield SSE-formatted strings for a single client connection."""
    from netlanventory.core.auth import decode_access_token

    # Validate token
    try:
        claims = decode_access_token(token)
        if not claims:
            yield "event: error\ndata: {\"error\": \"Unauthorized\"}\n\n"
            return
    except Exception:
        yield "event: error\ndata: {\"error\": \"Invalid token\"}\n\n"
        return

    # Register this client
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    _client_queues.add(queue)
    logger.debug("SSE client connected", user=claims.get("sub", "?"))

    try:
        # Send an initial connected event
        yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"

        while True:
            try:
                # Wait for an event or send heartbeat
                data = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_INTERVAL)
                yield f"data: {data}\n\n"
            except asyncio.TimeoutError:
                # Heartbeat — keeps the connection alive through proxies
                ts = datetime.now(timezone.utc).isoformat()
                yield f": heartbeat {ts}\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        _client_queues.discard(queue)
        logger.debug("SSE client disconnected")


@router.get("/stream")
async def event_stream(
    token: str = Query(..., description="JWT access token"),
) -> StreamingResponse:
    """Server-Sent Events stream for real-time updates.

    Connect with:
        const es = new EventSource('/api/v1/events/stream?token=<JWT>');
        es.onmessage = (e) => console.log(JSON.parse(e.data));

    Events emitted:
    - scan_update: {scan_id, status, progress, module}
    - cve_alert: {asset_id, cve_id, severity}
    - new_asset: {asset_id, ip, discovery_source}
    - notification: {level, message, asset_id?}
    """
    return StreamingResponse(
        _event_generator(token),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable Nginx buffering
            "Connection": "keep-alive",
        },
    )
