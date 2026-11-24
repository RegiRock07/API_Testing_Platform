# backend/app/api/streaming.py
#
# Server-Sent Events (SSE) streaming endpoint.
#
# Runs the same compiled LangGraph pipeline as /api/run (orchestrator.py)
# in a worker thread, so no agent ever blocks the event loop. Nodes report
# progress through config["configurable"]["progress"]; the callback hands
# each event to the loop with loop.call_soon_threadsafe and this generator
# streams it as:
#
#   data: {"agent": "<name>", "status": "running|completed|skipped|error", "data": {...}}
#   ...
#   data: {"agent": "report", "status": "completed", "data": {"report": {...}}}
#   data: [DONE]
#
# Body (optional): {"safe_mode": true, "auth": {"type", "value", "header_name"}}

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import StreamingResponse

from app.api.firebase_auth import get_current_user
from app.database import save_report
from app.orchestrator import Orchestrator
from app.schemas.api_spec import ScanOptions
from app.services.spec_parser import SpecParser

logger = logging.getLogger(__name__)

stream_router = APIRouter()
spec_parser   = SpecParser()
orchestrator  = Orchestrator()

_DONE = object()   # sentinel: graph thread finished


def sse(agent: str, status: str, data: dict = None) -> str:
    """Format a single SSE event."""
    payload = {"agent": agent, "status": status}
    if data:
        payload["data"] = data
    return f"data: {json.dumps(payload, default=str)}\n\n"


@stream_router.post("/api/run/{spec_id}/stream", dependencies=[Depends(get_current_user)])
async def run_agents_stream(spec_id: str, options: Optional[ScanOptions] = Body(default=None)):
    """
    Run the scan graph and stream one event per agent as it progresses.
    The final `report completed` event carries the full report, sent only
    after the report has been saved.
    """
    scan = spec_parser.get_spec(spec_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Spec not found")

    parsed_data  = scan["parsed_data"]
    scan_options = (options or ScanOptions()).to_state()

    async def generate():
        loop  = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def push(item) -> None:
            # Called from the worker thread. If the client has gone and the
            # loop is shutting down, dropping the event is fine.
            try:
                loop.call_soon_threadsafe(queue.put_nowait, item)
            except RuntimeError:
                pass

        def progress(agent: str, status: str, data: Optional[dict] = None) -> None:
            push((agent, status, data))

        def run_graph() -> dict:
            try:
                return orchestrator.run_all(parsed_data, scan_options, progress=progress)
            finally:
                push(_DONE)

        future = loop.run_in_executor(None, run_graph)

        try:
            while True:
                item = await queue.get()
                if item is _DONE:
                    break
                agent, status, data = item
                yield sse(agent, status, data)

            report = await future                     # re-raises graph errors
            await asyncio.to_thread(save_report, spec_id, report)
            yield sse("report", "completed", {"report": report})

        except Exception as e:
            logger.exception(f"[Stream] scan {spec_id} failed")
            yield sse("error", "failed", {"message": str(e)})

        yield "data: [DONE]\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )
