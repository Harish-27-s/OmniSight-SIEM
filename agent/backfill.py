"""
Historical log backfill module.
Scans for rotated / compressed logs (.gz, .1, etc.), decompresses,
parses chronologically from byte zero, and yields events with backfill flag.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional


# Common log patterns
AUTH_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)"
)
SYSLOG_TS = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def _parse_ts(line: str, year: Optional[int] = None) -> Optional[datetime]:
    """Best-effort syslog timestamp parse (no year)."""
    m = SYSLOG_TS.match(line)
    if not m:
        return None
    try:
        # Assume current year if not present
        y = year or datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{y} {m.group(1)}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _open_log(path: Path):
    """Open plain or gzipped log file."""
    if path.suffix == ".gz" or str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def discover_log_files(directories: Iterable[str], patterns: Optional[List[str]] = None) -> List[Path]:
    """
    Discover rotated and compressed log files under given directories.
    Looks for *.log, *.log.1, *.log.gz, auth.log*, secure*, messages*, etc.
    """
    patterns = patterns or [
        "*.log",
        "*.log.*",
        "auth.log*",
        "secure*",
        "messages*",
        "syslog*",
        "*.gz",
    ]
    found: List[Path] = []
    for d in directories:
        p = Path(d)
        if not p.exists():
            continue
        for pat in patterns:
            found.extend(p.glob(pat))
            found.extend(p.rglob(pat))
    # Deduplicate and sort by mtime (oldest first for chronological backfill)
    unique = sorted(set(found), key=lambda x: x.stat().st_mtime)
    return unique


def parse_line(line: str, source: str, node_id: str) -> Optional[Dict[str, Any]]:
    """Parse a single log line into a structured event dict."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    ts = _parse_ts(line)
    event: Dict[str, Any] = {
        "timestamp": (ts or datetime.now(timezone.utc)).isoformat(),
        "node_id": node_id,
        "source": source,
        "raw": line,
        "backfill": True,
        "event_type": "log",
        "severity": "info",
    }

    # Auth heuristics
    lower = line.lower()
    if "failed password" in lower or "authentication failure" in lower:
        event["event_type"] = "auth_failure"
        event["severity"] = "medium"
        m = re.search(r"from\s+(\S+)", line)
        if m:
            event["src_ip"] = m.group(1)
        m = re.search(r"for\s+(\S+)", line)
        if m:
            event["user"] = m.group(1)
    elif "accepted password" in lower or "session opened" in lower:
        event["event_type"] = "auth_success"
        event["severity"] = "info"
    elif "sudo" in lower and ("command" in lower or "session" in lower):
        event["event_type"] = "privilege_escalation"
        event["severity"] = "high"
    elif "invalid user" in lower:
        event["event_type"] = "auth_failure"
        event["severity"] = "medium"

    # File integrity style
    if "integrity" in lower or "fim" in lower or "modified" in lower:
        event["event_type"] = "fim_change"
        event["severity"] = "high"

    return event


def backfill_logs(
    directories: List[str],
    node_id: str = "lab-node-01",
    max_files: int = 50,
    max_lines_per_file: int = 5000,
) -> Generator[Dict[str, Any], None, None]:
    """
    Generator that yields historical events in roughly chronological order.
    Opens each file from byte zero (seek(0)), parses lines, marks backfill=True.
    """
    files = discover_log_files(directories)[:max_files]
    for fpath in files:
        source = str(fpath)
        try:
            with _open_log(fpath) as fh:
                # Explicit seek(0) for clarity (already at start for new open)
                if hasattr(fh, "seek"):
                    fh.seek(0)
                count = 0
                for line in fh:
                    if count >= max_lines_per_file:
                        break
                    evt = parse_line(line, source=source, node_id=node_id)
                    if evt:
                        evt["file"] = source
                        evt["event_id"] = hashlib.sha256(
                            f"{source}:{line}:{count}".encode()
                        ).hexdigest()[:16]
                        yield evt
                        count += 1
        except (OSError, gzip.BadGzipFile, UnicodeDecodeError) as exc:
            # Skip unreadable files gracefully
            yield {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "node_id": node_id,
                "source": "backfill",
                "event_type": "backfill_error",
                "severity": "low",
                "raw": f"Failed to parse {fpath}: {exc}",
                "backfill": True,
            }


if __name__ == "__main__":
    # Quick smoke test
    dirs = ["/var/log", "/tmp"]
    for i, e in enumerate(backfill_logs(dirs, max_files=5, max_lines_per_file=10)):
        print(e)
        if i > 20:
            break
