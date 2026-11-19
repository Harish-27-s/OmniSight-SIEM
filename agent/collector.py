"""
Multi-vector live tailing collector.
Monitors OS auth logs, database slow-query logs, file-integrity directories,
and application logs simultaneously. Ships events via transport.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from agent.backfill import backfill_logs, parse_line
from agent.transport import AgentTransport


# Default watch targets (adjust for the host OS)
DEFAULT_AUTH_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/messages",
]
DEFAULT_DB_PATHS = [
    "/var/log/mysql/slow.log",
    "/var/log/postgresql/postgresql.log",
    "/tmp/omnisight_demo_db.log",
]
DEFAULT_FIM_DIRS = [
    "/etc",
    "/usr/bin",
    "/tmp/omnisight_fim",
]
DEFAULT_APP_PATHS = [
    "/var/log/syslog",
    "/tmp/omnisight_app.log",
]


class FileTailer:
    """Simple async-friendly file tailer that tracks inode + offset."""

    def __init__(self, path: str, source: str):
        self.path = Path(path)
        self.source = source
        self._fh = None
        self._inode: Optional[int] = None
        self._pos = 0

    def _open(self):
        if not self.path.exists():
            return False
        try:
            st = self.path.stat()
            self._fh = open(self.path, "r", encoding="utf-8", errors="replace")
            self._inode = st.st_ino
            # Start at end for live tail (backfill handles history)
            self._fh.seek(0, 2)
            self._pos = self._fh.tell()
            return True
        except OSError:
            return False

    def _rotated(self) -> bool:
        if not self.path.exists() or self._inode is None:
            return True
        try:
            return self.path.stat().st_ino != self._inode
        except OSError:
            return True

    def read_new_lines(self) -> List[str]:
        lines: List[str] = []
        if self._fh is None:
            if not self._open():
                return lines
        if self._rotated():
            try:
                if self._fh:
                    self._fh.close()
            except Exception:
                pass
            self._fh = None
            if not self._open():
                return lines
        try:
            while True:
                line = self._fh.readline()
                if not line:
                    break
                lines.append(line)
                self._pos = self._fh.tell()
        except OSError:
            pass
        return lines


class FIMWatcher:
    """Lightweight file-integrity monitor (hash + mtime)."""

    def __init__(self, directories: List[str], node_id: str):
        self.directories = [Path(d) for d in directories]
        self.node_id = node_id
        self._baseline: Dict[str, str] = {}

    def _hash_file(self, path: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def scan(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        current: Dict[str, str] = {}
        for d in self.directories:
            if not d.exists():
                continue
            for root, _, files in os.walk(d):
                for name in files:
                    p = Path(root) / name
                    try:
                        # Skip very large files
                        if p.stat().st_size > 5_000_000:
                            continue
                    except OSError:
                        continue
                    digest = self._hash_file(p)
                    if digest is None:
                        continue
                    key = str(p)
                    current[key] = digest
                    if key in self._baseline and self._baseline[key] != digest:
                        events.append(
                            {
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "node_id": self.node_id,
                                "source": "fim",
                                "event_type": "fim_change",
                                "severity": "high",
                                "path": key,
                                "old_hash": self._baseline[key][:16],
                                "new_hash": digest[:16],
                                "raw": f"File integrity change detected: {key}",
                                "backfill": False,
                            }
                        )
                    elif key not in self._baseline and self._baseline:
                        # New file after baseline established
                        events.append(
                            {
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "node_id": self.node_id,
                                "source": "fim",
                                "event_type": "fim_create",
                                "severity": "medium",
                                "path": key,
                                "new_hash": digest[:16],
                                "raw": f"New file observed: {key}",
                                "backfill": False,
                            }
                        )
        if not self._baseline:
            self._baseline = current  # first scan = baseline
        else:
            # Detect deletions
            for key in set(self._baseline) - set(current):
                events.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "node_id": self.node_id,
                        "source": "fim",
                        "event_type": "fim_delete",
                        "severity": "high",
                        "path": key,
                        "raw": f"File deleted: {key}",
                        "backfill": False,
                    }
                )
            self._baseline = current
        return events


class MultiVectorCollector:
    """Orchestrates live tailing + FIM + optional backfill, ships via transport."""

    def __init__(
        self,
        node_id: Optional[str] = None,
        backend_url: str = "http://127.0.0.1:8000",
        ws_url: str = "ws://127.0.0.1:8000/ws/agent",
        secret: str = "omnisight-lab-secret-change-me",
        do_backfill: bool = True,
    ):
        self.node_id = node_id or f"{platform.node()}-{socket.gethostname()}"
        self.transport = AgentTransport(
            node_id=self.node_id,
            backend_url=backend_url,
            ws_url=ws_url,
            secret=secret,
        )
        self.auth_tailers = [FileTailer(p, "auth") for p in DEFAULT_AUTH_PATHS]
        self.db_tailers = [FileTailer(p, "database") for p in DEFAULT_DB_PATHS]
        self.app_tailers = [FileTailer(p, "application") for p in DEFAULT_APP_PATHS]
        self.fim = FIMWatcher(DEFAULT_FIM_DIRS, self.node_id)
        self.do_backfill = do_backfill
        self._running = False

    async def _emit(self, events: List[Dict[str, Any]]):
        if not events:
            return
        for e in events:
            e.setdefault("node_id", self.node_id)
            e.setdefault("backfill", False)
            if "event_id" not in e:
                e["event_id"] = hashlib.sha256(
                    f"{e.get('raw','')}:{e.get('timestamp')}".encode()
                ).hexdigest()[:16]
        await self.transport.ship_events(events)

    async def run_backfill(self):
        dirs = list({str(Path(p).parent) for p in DEFAULT_AUTH_PATHS + DEFAULT_APP_PATHS})
        dirs.append("/tmp")
        batch: List[Dict[str, Any]] = []
        for evt in backfill_logs(dirs, node_id=self.node_id, max_files=20, max_lines_per_file=200):
            batch.append(evt)
            if len(batch) >= 50:
                await self._emit(batch)
                batch = []
        if batch:
            await self._emit(batch)

    async def _poll_tailers(self, tailers: List[FileTailer]):
        events: List[Dict[str, Any]] = []
        for t in tailers:
            for line in t.read_new_lines():
                evt = parse_line(line, source=t.source, node_id=self.node_id)
                if evt:
                    evt["backfill"] = False
                    events.append(evt)
        return events

    async def run(self):
        self._running = True
        print(f"[collector] Starting Omnisight Edge Agent node_id={self.node_id}")

        # Start control listener in background
        control_task = asyncio.create_task(self.transport.listen_control())

        if self.do_backfill:
            print("[collector] Running historical backfill…")
            try:
                await self.run_backfill()
            except Exception as exc:
                print(f"[collector] Backfill error (non-fatal): {exc}")

        print("[collector] Entering live multi-vector loop")
        while self._running:
            try:
                all_events: List[Dict[str, Any]] = []
                all_events.extend(await self._poll_tailers(self.auth_tailers))
                all_events.extend(await self._poll_tailers(self.db_tailers))
                all_events.extend(await self._poll_tailers(self.app_tailers))
                all_events.extend(self.fim.scan())
                if all_events:
                    await self._emit(all_events)
                    print(f"[collector] Shipped {len(all_events)} events")
            except Exception as exc:
                print(f"[collector] Loop error: {exc}")
            await asyncio.sleep(2.0)

        control_task.cancel()
        await self.transport.close()

    def stop(self):
        self._running = False


def main():
    parser = argparse.ArgumentParser(description="Omnisight SIEM Edge Agent")
    parser.add_argument("--node-id", default=None)
    parser.add_argument("--backend", default="http://127.0.0.1:8000")
    parser.add_argument("--ws", default="ws://127.0.0.1:8000/ws/agent")
    parser.add_argument("--secret", default="omnisight-lab-secret-change-me")
    parser.add_argument("--no-backfill", action="store_true")
    args = parser.parse_args()

    collector = MultiVectorCollector(
        node_id=args.node_id,
        backend_url=args.backend,
        ws_url=args.ws,
        secret=args.secret,
        do_backfill=not args.no_backfill,
    )
    try:
        asyncio.run(collector.run())
    except KeyboardInterrupt:
        print("\n[collector] Shutting down")
        collector.stop()


if __name__ == "__main__":
    main()
