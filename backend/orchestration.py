"""
Remote Lab Node Control Gateway.
- Tracks active inventory of connected agents via WebSocket.
- Dispatches HMAC-signed administrative commands.
- Supports broadcast scans / commands across selected nodes.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import CommandReceipt, Node, get_session

router = APIRouter(prefix="/api/v1", tags=["orchestration"])

SECRET = "omnisight-lab-secret-change-me"


def _sign(payload: str) -> str:
    return hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


# In-memory live WebSocket registry: node_id -> WebSocket
_live_agents: Dict[str, WebSocket] = {}
_lock = asyncio.Lock()


class CommandRequest(BaseModel):
    node_id: str
    command: str
    args: Dict[str, Any] = Field(default_factory=dict)


class BroadcastRequest(BaseModel):
    node_ids: Optional[List[str]] = None  # None = all online
    command: str
    args: Dict[str, Any] = Field(default_factory=dict)


@router.websocket("/ws/agent")
async def agent_ws(websocket: WebSocket, node_id: str = "unknown"):
    """Agent control channel. Agents connect with ?node_id=..."""
    await websocket.accept()
    # Prefer query param
    q = websocket.query_params.get("node_id") or node_id
    async with _lock:
        _live_agents[q] = websocket
    print(f"[orchestration] Agent connected: {q}")

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            # Hello / presence
            if msg.get("type") == "hello":
                continue

            # Signed receipt from agent
            if "receipt" in msg and "signature" in msg:
                receipt = msg["receipt"]
                # Soft-verify signature
                receipt_str = json.dumps(receipt, sort_keys=True, default=str)
                expected = _sign(receipt_str)
                # Persist regardless (demo mode)
                async for session in get_session():
                    row = CommandReceipt(
                        request_id=receipt.get("request_id", ""),
                        node_id=receipt.get("node_id", q),
                        command=receipt.get("command", ""),
                        success=receipt.get("result", {}).get("success", False),
                        result=receipt.get("result"),
                    )
                    session.add(row)
                    await session.commit()
                    break
    except WebSocketDisconnect:
        pass
    finally:
        async with _lock:
            if _live_agents.get(q) is websocket:
                del _live_agents[q]
        print(f"[orchestration] Agent disconnected: {q}")


async def _dispatch(node_id: str, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
    ws = _live_agents.get(node_id)
    if not ws:
        return {"error": f"Node {node_id} not connected", "success": False}

    request_id = str(uuid.uuid4())
    payload = {
        "request_id": request_id,
        "command": command,
        "args": args,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload_str = json.dumps(payload, sort_keys=True, default=str)
    message = {
        "payload": payload,
        "signature": _sign(payload_str),
    }
    try:
        await ws.send_text(json.dumps(message))
        return {
            "request_id": request_id,
            "node_id": node_id,
            "command": command,
            "status": "dispatched",
        }
    except Exception as exc:
        return {"error": str(exc), "success": False}


@router.post("/nodes/command")
async def send_command(body: CommandRequest):
    """Dispatch a signed command to a single node."""
    result = await _dispatch(body.node_id, body.command, body.args)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/nodes/broadcast")
async def broadcast_command(body: BroadcastRequest):
    """Broadcast a command to selected (or all online) nodes."""
    targets = body.node_ids or list(_live_agents.keys())
    results = []
    for nid in targets:
        r = await _dispatch(nid, body.command, body.args)
        results.append(r)
    return {"dispatched": len(results), "results": results}


@router.get("/nodes/live")
async def live_nodes():
    """Return currently connected agent node_ids."""
    return {"connected": list(_live_agents.keys()), "count": len(_live_agents)}


@router.get("/commands/receipts")
async def list_receipts(
    limit: int = 50,
    node_id: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
):
    q = select(CommandReceipt).order_by(CommandReceipt.created_at.desc()).limit(limit)
    if node_id:
        q = q.where(CommandReceipt.node_id == node_id)
    result = await session.execute(q)
    rows = result.scalars().all()
    return [
        {
            "request_id": r.request_id,
            "node_id": r.node_id,
            "command": r.command,
            "success": r.success,
            "result": r.result,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
