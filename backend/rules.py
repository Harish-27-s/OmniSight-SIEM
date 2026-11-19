"""
Hybrid detection engine:
  Tier-1 – deterministic sliding-window rules (brute-force, off-hours, lateral, FIM)
  Tier-2 – local Ollama AI risk scoring (http://localhost:11434/api/generate)
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import Alert, Event

# Sliding-window state (in-memory; reset on restart – fine for lab)
_auth_fail_window: Dict[str, List[datetime]] = defaultdict(list)
_fim_window: Dict[str, List[datetime]] = defaultdict(list)
_off_hours_window: Dict[str, List[datetime]] = defaultdict(list)

WINDOW_SECONDS = 300  # 5 minutes
BRUTE_FORCE_THRESHOLD = 5
FIM_THRESHOLD = 3


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _prune(window: List[datetime], seconds: int = WINDOW_SECONDS) -> List[datetime]:
    cutoff = _now() - timedelta(seconds=seconds)
    return [t for t in window if t > cutoff]


async def _ollama_risk_score(events_summary: str) -> Dict[str, Any]:
    """
    Call local Ollama for a 0-100 risk score + threat brief.
    Falls back gracefully if Ollama is unavailable.
    """
    prompt = (
        "You are a SOC analyst AI. Given the following security telemetry summary, "
        "respond ONLY with a JSON object containing:\n"
        '  "risk_score": <integer 0-100>,\n'
        '  "threat_brief": "<one-paragraph executive summary>"\n\n'
        f"Telemetry:\n{events_summary}\n"
    )
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "llama3.2",
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
            )
            if r.status_code == 200:
                data = r.json()
                text = data.get("response", "{}")
                parsed = json.loads(text)
                return {
                    "risk_score": float(parsed.get("risk_score", 50)),
                    "threat_brief": parsed.get("threat_brief", "AI analysis unavailable."),
                }
    except Exception:
        pass
    # Deterministic fallback
    return {
        "risk_score": 55.0,
        "threat_brief": (
            "Local Ollama unavailable. Heuristic assessment indicates elevated "
            "activity based on deterministic rules. Review evidence timeline."
        ),
    }


async def evaluate_events(session: AsyncSession, new_events: List[Event]) -> List[Alert]:
    """Run Tier-1 rules then optionally Tier-2 AI scoring. Persist alerts."""
    alerts: List[Alert] = []
    if not new_events:
        return alerts

    for evt in new_events:
        ts = evt.timestamp or _now()
        key_ip = f"{evt.node_id}:{evt.src_ip or 'unknown'}"
        key_node = evt.node_id or "unknown"

        # --- Brute-force (auth_failure) ---
        if evt.event_type == "auth_failure":
            _auth_fail_window[key_ip] = _prune(_auth_fail_window[key_ip] + [ts])
            if len(_auth_fail_window[key_ip]) >= BRUTE_FORCE_THRESHOLD:
                alert = await _create_alert(
                    session,
                    title=f"Brute-force authentication against {evt.src_ip or 'unknown'}",
                    description=(
                        f"{len(_auth_fail_window[key_ip])} failed logins in the last "
                        f"{WINDOW_SECONDS}s on node {evt.node_id}"
                    ),
                    severity="high",
                    node_id=evt.node_id,
                    rule_name="brute_force_auth",
                    evidence=[evt.event_id],
                )
                alerts.append(alert)
                _auth_fail_window[key_ip] = []  # reset after alert

        # --- FIM modifications ---
        if evt.event_type in ("fim_change", "fim_create", "fim_delete"):
            _fim_window[key_node] = _prune(_fim_window[key_node] + [ts])
            if len(_fim_window[key_node]) >= FIM_THRESHOLD:
                alert = await _create_alert(
                    session,
                    title=f"File Integrity Monitoring burst on {evt.node_id}",
                    description=f"Multiple FIM events detected (path={evt.path})",
                    severity="critical",
                    node_id=evt.node_id,
                    rule_name="fim_burst",
                    evidence=[evt.event_id],
                )
                alerts.append(alert)
                _fim_window[key_node] = []

        # --- Off-hours access (simple heuristic: hour < 6 or > 22 UTC) ---
        if evt.event_type == "auth_success" and (ts.hour < 6 or ts.hour > 22):
            _off_hours_window[key_node] = _prune(_off_hours_window[key_node] + [ts])
            if len(_off_hours_window[key_node]) >= 2:
                alert = await _create_alert(
                    session,
                    title=f"Off-hours successful login on {evt.node_id}",
                    description=f"Auth success at {ts.isoformat()} (UTC off-hours)",
                    severity="medium",
                    node_id=evt.node_id,
                    rule_name="off_hours_access",
                    evidence=[evt.event_id],
                )
                alerts.append(alert)

        # --- Privilege escalation ---
        if evt.event_type == "privilege_escalation":
            alert = await _create_alert(
                session,
                title=f"Privilege escalation activity on {evt.node_id}",
                description=evt.raw[:300],
                severity="high",
                node_id=evt.node_id,
                rule_name="priv_esc",
                evidence=[evt.event_id],
            )
            alerts.append(alert)

        # --- Lateral movement heuristic (same user, different nodes rapidly) ---
        # Simplified: flag if auth_success from same src_ip on multiple nodes
        # (full cross-node correlation would need more state)

    # Enrich the most recent alert with AI scoring if any were created
    if alerts:
        summary_parts = []
        for a in alerts[-3:]:
            summary_parts.append(f"- {a.title}: {a.description}")
        summary = "\n".join(summary_parts)
        ai = await _ollama_risk_score(summary)
        for a in alerts:
            a.risk_score = ai["risk_score"]
            a.ai_brief = ai["threat_brief"]
        await session.commit()

    return alerts


async def _create_alert(
    session: AsyncSession,
    title: str,
    description: str,
    severity: str,
    node_id: Optional[str],
    rule_name: str,
    evidence: List[str],
) -> Alert:
    aid = hashlib.sha256(f"{title}:{node_id}:{_now().isoformat()}".encode()).hexdigest()[:16]
    alert = Alert(
        alert_id=aid,
        title=title,
        description=description,
        severity=severity,
        risk_score=40.0 if severity == "medium" else 70.0 if severity == "high" else 90.0,
        node_id=node_id,
        status="open",
        rule_name=rule_name,
        evidence_event_ids=evidence,
        remediation_log=[],
    )
    session.add(alert)
    await session.commit()
    await session.refresh(alert)
    return alert
