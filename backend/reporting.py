"""
Automated PDF / JSON forensic report generator using reportlab.
Endpoint: GET /api/v1/reports/incident/{alert_id}/pdf
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import Alert, Event, Node, CommandReceipt, get_session

router = APIRouter(prefix="/api/v1/reports", tags=["reporting"])


def _styles():
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontSize=18,
            textColor=colors.HexColor("#0b0f19"),
            spaceAfter=6,
            fontName="Helvetica-Bold",
        ),
        "heading": ParagraphStyle(
            "Heading",
            parent=base["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6,
            fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#334155"),
            leading=12,
        ),
        "mono": ParagraphStyle(
            "Mono",
            parent=base["Normal"],
            fontSize=8,
            fontName="Courier",
            textColor=colors.HexColor("#0f172a"),
            leading=10,
        ),
        "meta": ParagraphStyle(
            "Meta",
            parent=base["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#64748b"),
        ),
        "critical": ParagraphStyle(
            "Critical",
            parent=base["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#b91c1c"),
            fontName="Helvetica-Bold",
        ),
    }
    return styles


def _build_pdf(alert: Alert, evidence: List[Event], node: Optional[Node], receipts: List[CommandReceipt]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )
    styles = _styles()
    story = []

    # Header
    story.append(Paragraph("OMNISIGHT SIEM — Incident Forensic Report", styles["title"]))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} · Confidential",
        styles["meta"],
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

    # Incident metadata
    story.append(Paragraph("1. Incident Metadata", styles["heading"]))
    meta_data = [
        ["Alert ID", alert.alert_id],
        ["Title", alert.title or "—"],
        ["Severity", (alert.severity or "—").upper()],
        ["Risk Score", f"{alert.risk_score:.0f} / 100"],
        ["Status", alert.status or "—"],
        ["Rule", alert.rule_name or "—"],
        ["Node", alert.node_id or "—"],
        ["Created", alert.created_at.isoformat() if alert.created_at else "—"],
    ]
    t = Table(meta_data, colWidths=[1.6 * inch, 5 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0f172a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t)

    # AI Threat Brief
    story.append(Paragraph("2. AI Threat Brief", styles["heading"]))
    brief = alert.ai_brief or "No AI brief available."
    story.append(Paragraph(brief, styles["body"]))

    # Description
    story.append(Paragraph("3. Description", styles["heading"]))
    story.append(Paragraph(alert.description or "—", styles["body"]))

    # Affected Node
    story.append(Paragraph("4. Affected Node Details", styles["heading"]))
    if node:
        node_data = [
            ["Node ID", node.node_id],
            ["Hostname", node.hostname or "—"],
            ["IP Address", node.ip or "—"],
            ["Platform", node.platform or "—"],
            ["Agent Version", node.agent_version or "—"],
            ["Last Seen", node.last_seen.isoformat() if node.last_seen else "—"],
            ["Status", node.status or "—"],
        ]
        nt = Table(node_data, colWidths=[1.6 * inch, 5 * inch])
        nt.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        story.append(nt)
    else:
        story.append(Paragraph("Node details not found in inventory.", styles["body"]))

    # Evidence Timeline
    story.append(Paragraph("5. Raw Evidence Event Timeline", styles["heading"]))
    if evidence:
        for e in evidence[:30]:
            line = (
                f"<b>{e.timestamp.isoformat() if e.timestamp else '—'}</b> "
                f"[{e.event_type}/{e.severity}] {e.raw[:180]}"
            )
            story.append(Paragraph(line, styles["mono"]))
            story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No linked evidence events.", styles["body"]))

    # Remediation Audit Log
    story.append(Paragraph("6. Remediation Audit Log", styles["heading"]))
    rem_log = alert.remediation_log or []
    if rem_log:
        for entry in rem_log:
            story.append(Paragraph(json.dumps(entry, default=str), styles["mono"]))
    elif receipts:
        for r in receipts:
            story.append(Paragraph(
                f"{r.created_at} · {r.command} · success={r.success}",
                styles["mono"],
            ))
    else:
        story.append(Paragraph("No remediation actions recorded yet.", styles["body"]))

    # Footer
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8")))
    story.append(Paragraph(
        "Omnisight SIEM · Local-first security platform · Report generated for authorized lab use only",
        styles["meta"],
    ))

    doc.build(story)
    return buffer.getvalue()


@router.get("/incident/{alert_id}/pdf")
async def incident_pdf(alert_id: str, session: AsyncSession = Depends(get_session)):
    q = await session.execute(select(Alert).where(Alert.alert_id == alert_id))
    alert = q.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    evidence: List[Event] = []
    if alert.evidence_event_ids:
        for eid in alert.evidence_event_ids:
            eq = await session.execute(select(Event).where(Event.event_id == eid))
            e = eq.scalar_one_or_none()
            if e:
                evidence.append(e)
    # Also pull recent events from same node
    if alert.node_id:
        eq2 = await session.execute(
            select(Event)
            .where(Event.node_id == alert.node_id)
            .order_by(Event.timestamp.desc())
            .limit(15)
        )
        for e in eq2.scalars().all():
            if e not in evidence:
                evidence.append(e)

    node = None
    if alert.node_id:
        nq = await session.execute(select(Node).where(Node.node_id == alert.node_id))
        node = nq.scalar_one_or_none()

    rq = await session.execute(
        select(CommandReceipt)
        .where(CommandReceipt.node_id == alert.node_id)
        .order_by(CommandReceipt.created_at.desc())
        .limit(10)
    )
    receipts = list(rq.scalars().all())

    pdf_bytes = _build_pdf(alert, evidence, node, receipts)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="omnisight-incident-{alert_id}.pdf"'
        },
    )


@router.get("/incident/{alert_id}/json")
async def incident_json(alert_id: str, session: AsyncSession = Depends(get_session)):
    q = await session.execute(select(Alert).where(Alert.alert_id == alert_id))
    alert = q.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "alert_id": alert.alert_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "ai_brief": alert.ai_brief,
        "node_id": alert.node_id,
        "status": alert.status,
        "rule_name": alert.rule_name,
        "evidence_event_ids": alert.evidence_event_ids,
        "remediation_log": alert.remediation_log,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }
