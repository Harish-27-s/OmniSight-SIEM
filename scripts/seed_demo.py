"""
Generate a 48-hour synthetic multi-vector threat dataset and load it into SQLite.
Also creates a handful of demo alerts so the dashboard is populated on first run.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.database import Alert, Event, Node, init_db, AsyncSessionLocal

NODES = [
    {"node_id": "lab-node-01", "hostname": "lab-web-01", "ip": "10.0.1.11", "platform": "Linux-6.5"},
    {"node_id": "lab-node-02", "hostname": "lab-db-01", "ip": "10.0.1.12", "platform": "Linux-6.5"},
    {"node_id": "lab-node-03", "hostname": "lab-jump-01", "ip": "10.0.1.13", "platform": "Linux-6.1"},
]

USERS = ["alice", "bob", "charlie", "admin", "svc_backup", "root"]
SRC_IPS = ["203.0.113.45", "198.51.100.22", "192.0.2.88", "10.0.1.50", "172.16.0.9"]
PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/usr/bin/sudo",
    "/var/www/html/index.php",
    "/tmp/suspicious.sh",
    "/etc/ssh/sshd_config",
]


def _eid(*parts) -> str:
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()[:16]


async def seed():
    await init_db()
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=48)

    async with AsyncSessionLocal() as session:
        # Nodes
        for n in NODES:
            session.add(
                Node(
                    node_id=n["node_id"],
                    hostname=n["hostname"],
                    ip=n["ip"],
                    platform=n["platform"],
                    agent_version="1.0.0",
                    status="online",
                    last_seen=now,
                )
            )

        events = []
        t = start
        while t < now:
            node = random.choice(NODES)
            roll = random.random()

            if roll < 0.35:
                # Auth failure (potential brute force)
                user = random.choice(USERS)
                ip = random.choice(SRC_IPS)
                raw = f"{t.strftime('%b %d %H:%M:%S')} {node['hostname']} sshd[1234]: Failed password for {user} from {ip} port 22 ssh2"
                events.append(
                    Event(
                        event_id=_eid("authf", t, ip, user),
                        timestamp=t,
                        node_id=node["node_id"],
                        source="auth",
                        event_type="auth_failure",
                        severity="medium",
                        raw=raw,
                        src_ip=ip,
                        user=user,
                        backfill=True,
                    )
                )
            elif roll < 0.50:
                # Auth success
                user = random.choice(USERS[:3])
                ip = random.choice(SRC_IPS[3:])
                raw = f"{t.strftime('%b %d %H:%M:%S')} {node['hostname']} sshd[1234]: Accepted password for {user} from {ip} port 22 ssh2"
                events.append(
                    Event(
                        event_id=_eid("auths", t, ip, user),
                        timestamp=t,
                        node_id=node["node_id"],
                        source="auth",
                        event_type="auth_success",
                        severity="info",
                        raw=raw,
                        src_ip=ip,
                        user=user,
                        backfill=True,
                    )
                )
            elif roll < 0.60:
                # FIM
                path = random.choice(PATHS)
                et = random.choice(["fim_change", "fim_create", "fim_delete"])
                events.append(
                    Event(
                        event_id=_eid("fim", t, path),
                        timestamp=t,
                        node_id=node["node_id"],
                        source="fim",
                        event_type=et,
                        severity="high",
                        raw=f"File integrity event: {et} on {path}",
                        path=path,
                        backfill=True,
                    )
                )
            elif roll < 0.70:
                # Privilege escalation
                raw = f"{t.strftime('%b %d %H:%M:%S')} {node['hostname']} sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
                events.append(
                    Event(
                        event_id=_eid("priv", t),
                        timestamp=t,
                        node_id=node["node_id"],
                        source="auth",
                        event_type="privilege_escalation",
                        severity="high",
                        raw=raw,
                        user="alice",
                        backfill=True,
                    )
                )
            elif roll < 0.85:
                # DB slow query
                events.append(
                    Event(
                        event_id=_eid("db", t),
                        timestamp=t,
                        node_id=node["node_id"],
                        source="database",
                        event_type="slow_query",
                        severity="low",
                        raw=f"Slow query: SELECT * FROM users WHERE email LIKE '%@%' took 4.2s",
                        backfill=True,
                    )
                )
            else:
                # Generic app log
                events.append(
                    Event(
                        event_id=_eid("app", t),
                        timestamp=t,
                        node_id=node["node_id"],
                        source="application",
                        event_type="log",
                        severity="info",
                        raw=f"Application heartbeat OK — uptime {random.randint(100,9999)}s",
                        backfill=True,
                    )
                )

            t += timedelta(minutes=random.randint(1, 12))

        session.add_all(events)

        # Seed a few high-signal alerts
        demo_alerts = [
            Alert(
                alert_id=_eid("alert", "bf1"),
                title="Brute-force authentication against 203.0.113.45",
                description="12 failed logins in a 5-minute window targeting user admin on lab-node-01",
                severity="high",
                risk_score=82.0,
                ai_brief=(
                    "Multiple failed SSH authentication attempts from 203.0.113.45 indicate a "
                    "credential-stuffing or password-spray campaign. Recommend blocking the source "
                    "IP and reviewing account lockout policy. No successful login observed yet."
                ),
                node_id="lab-node-01",
                status="open",
                rule_name="brute_force_auth",
                evidence_event_ids=[],
                remediation_log=[],
            ),
            Alert(
                alert_id=_eid("alert", "fim1"),
                title="File Integrity Monitoring burst on lab-node-02",
                description="Critical system binaries and configuration files modified in rapid succession",
                severity="critical",
                risk_score=94.0,
                ai_brief=(
                    "FIM events on /etc/shadow, /usr/bin/sudo and /etc/ssh/sshd_config within a short "
                    "window strongly suggest possible privilege-escalation or persistence activity. "
                    "Immediate isolation and forensic imaging of lab-node-02 is advised."
                ),
                node_id="lab-node-02",
                status="open",
                rule_name="fim_burst",
                evidence_event_ids=[],
                remediation_log=[],
            ),
            Alert(
                alert_id=_eid("alert", "off1"),
                title="Off-hours successful login on lab-node-03",
                description="Successful authentication at 03:14 UTC from internal jump host",
                severity="medium",
                risk_score=48.0,
                ai_brief=(
                    "Successful login outside normal business hours. Correlate with change tickets "
                    "and on-call schedules. Low-to-moderate risk if expected maintenance window."
                ),
                node_id="lab-node-03",
                status="acknowledged",
                rule_name="off_hours_access",
                evidence_event_ids=[],
                remediation_log=[{"action": "acknowledged", "by": "analyst1", "at": now.isoformat()}],
            ),
        ]
        session.add_all(demo_alerts)
        await session.commit()
        print(f"Seeded {len(events)} events, {len(NODES)} nodes, {len(demo_alerts)} alerts.")


if __name__ == "__main__":
    asyncio.run(seed())
