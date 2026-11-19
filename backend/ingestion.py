"""
Dual-channel ingestion: real-time JSON agent streams + bulk CSV uploads.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import Alert, Event, Node, get_session
from backend.rules import evaluate_events

router = APIRouter(prefix="/api/v1", tags=["ingestion"])


class TelemetryEvent(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[str] = None
    node_id: Optional[str] = None
    source: str = "unknown"
    event_type: str = "log"
    severity: str = "info"
    raw: str = ""
    src_ip: Optional[str] = None
    user: Optional[str] = None
    path: Optional[str] = None
    backfill: bool = False
    extra: Optional[Dict[str, Any]] = None


class IngestBatch(BaseModel):
    node_id: str
    events: List[TelemetryEvent]
    shipped_at: Optional[str] = None


class NodeRegister(BaseModel):
    node_id: str
    hostname: str
    platform: Optional[str] = None
    ip: Optional[str] = None
    agent_version: Optional[str] = None
    registered_at: Optional[str] = None


def _parse_ts(val: Optional[str]) -> datetime:
    if not val:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


@router.post("/ingest/events")
async def ingest_events(
    body: IngestBatch,
    x_node_id: Optional[str] = Header(None),
    x_signature: Optional[str] = Header(None),
    session: AsyncSession = Depends(get_session),
):
    """Real-time JSON telemetry ingestion from edge agents."""
    # Signature verification is soft in demo mode (log only)
    node_id = body.node_id or x_node_id or "unknown"
    stored: List[Event] = []
    for e in body.events:
        eid = e.event_id or hashlib.sha256(
            f"{e.raw}:{e.timestamp}:{node_id}".encode()
        ).hexdigest()[:16]
        # Dedup check
        existing = await session.execute(select(Event).where(Event.event_id == eid))
        if existing.scalar_one_or_none():
            continue
        row = Event(
            event_id=eid,
            timestamp=_parse_ts(e.timestamp),
            node_id=e.node_id or node_id,
            source=e.source,
            event_type=e.event_type,
            severity=e.severity,
            raw=e.raw,
            src_ip=e.src_ip,
            user=e.user,
            path=e.path,
            backfill=e.backfill,
            extra=e.extra,
        )
        session.add(row)
        stored.append(row)

    # Touch node last_seen
    node_q = await session.execute(select(Node).where(Node.node_id == node_id))
    node = node_q.scalar_one_or_none()
    if node:
        node.last_seen = datetime.now(timezone.utc)
        node.status = "online"

    await session.commit()

    # Run detection engine on the new batch
    alerts = await evaluate_events(session, stored)

    return {
        "accepted": len(stored),
        "alerts_generated": len(alerts),
        "node_id": node_id,
    }


@router.post("/ingest/csv")
async def ingest_csv(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
):
    """Bulk CSV upload. Expected columns: timestamp,node_id,source,event_type,severity,raw,..."""
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    stored = 0
    rows: List[Event] = []
    for row in reader:
        eid = hashlib.sha256(
            f"{row.get('raw','')}:{row.get('timestamp','')}:{row.get('node_id','')}".encode()
        ).hexdigest()[:16]
        existing = await session.execute(select(Event).where(Event.event_id == eid))
        if existing.scalar_one_or_none():
            continue
        evt = Event(
            event_id=eid,
            timestamp=_parse_ts(row.get("timestamp")),
            node_id=row.get("node_id", "csv-import"),
            source=row.get("source", "csv"),
            event_type=row.get("event_type", "log"),
            severity=row.get("severity", "info"),
            raw=row.get("raw", ""),
            src_ip=row.get("src_ip"),
            user=row.get("user"),
            path=row.get("path"),
            backfill=row.get("backfill", "false").lower() in ("1", "true", "yes"),
        )
        session.add(evt)
        rows.append(evt)
        stored += 1
    await session.commit()
    alerts = await evaluate_events(session, rows)
    return {"accepted": stored, "alerts_generated": len(alerts)}


@router.post("/nodes/register")
async def register_node(
    body: NodeRegister,
    session: AsyncSession = Depends(get_session),
):
    q = await session.execute(select(Node).where(Node.node_id == body.node_id))
    node = q.scalar_one_or_none()
    if node:
        node.hostname = body.hostname
        node.platform = body.platform
        node.ip = body.ip
        node.agent_version = body.agent_version
        node.last_seen = datetime.now(timezone.utc)
        node.status = "online"
    else:
        node = Node(
            node_id=body.node_id,
            hostname=body.hostname,
            platform=body.platform,
            ip=body.ip,
            agent_version=body.agent_version,
            status="online",
        )
        session.add(node)
    await session.commit()
    return {"status": "registered", "node_id": body.node_id}


@router.get("/events")
async def list_events(
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    node_id: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
):
    q = select(Event).order_by(Event.timestamp.desc()).limit(limit).offset(offset)
    if event_type:
        q = q.where(Event.event_type == event_type)
    if severity:
        q = q.where(Event.severity == severity)
    if node_id:
        q = q.where(Event.node_id == node_id)
    result = await session.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "event_id": r.event_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "node_id": r.node_id,
            "source": r.source,
            "event_type": r.event_type,
            "severity": r.severity,
            "raw": r.raw,
            "src_ip": r.src_ip,
            "user": r.user,
            "path": r.path,
            "backfill": r.backfill,
        }
        for r in rows
    ]


@router.get("/alerts")
async def list_alerts(
    status: Optional[str] = None,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
):
    q = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if status:
        q = q.where(Alert.status == status)
    result = await session.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "alert_id": r.alert_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "title": r.title,
            "description": r.description,
            "severity": r.severity,
            "risk_score": r.risk_score,
            "ai_brief": r.ai_brief,
            "node_id": r.node_id,
            "status": r.status,
            "rule_name": r.rule_name,
            "evidence_event_ids": r.evidence_event_ids,
            "remediation_log": r.remediation_log,
        }
        for r in rows
    ]


@router.get("/nodes")
async def list_nodes(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Node).order_by(Node.last_seen.desc()))
    rows = result.scalars().all()
    now = datetime.now(timezone.utc)
    out = []
    for r in rows:
        # Mark offline if last_seen > 60s ago
        status = r.status
        if r.last_seen and (now - r.last_seen).total_seconds() > 60:
            status = "offline"
        out.append(
            {
                "node_id": r.node_id,
                "hostname": r.hostname,
                "platform": r.platform,
                "ip": r.ip,
                "agent_version": r.agent_version,
                "status": status,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "registered_at": r.registered_at.isoformat() if r.registered_at else None,
            }
        )
    return out
