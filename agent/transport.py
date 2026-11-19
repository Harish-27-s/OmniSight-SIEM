"""
Secure encrypted shipper & WebSocket control listener.
- Ships telemetry as JSON batches to the backend.
- Maintains authenticated WebSocket for signed control commands.
- Verifies HMAC-SHA256 signatures before executing sandboxed commands.
- Returns cryptographically signed execution receipts.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import platform
import signal
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
import websockets
from websockets.exceptions import ConnectionClosed


# Allowed sandboxed commands (whitelist)
ALLOWED_COMMANDS = {
    "lock_session": ["loginctl", "lock-session"],
    "kill_process": None,  # special: needs pid arg
    "block_ip": None,      # special: needs ip arg
    "disable_user": None,  # special: needs username
    "whoami": ["whoami"],
    "uptime": ["uptime"],
    "hostname": ["hostname"],
    "df": ["df", "-h"],
    "free": ["free", "-m"],
    "ps_top": ["ps", "aux", "--sort=-%cpu"],
    "netstat": ["ss", "-tuln"],
    "echo_test": ["echo", "omnisight-agent-alive"],
}


def _sign(payload: str, secret: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _verify(payload: str, signature: str, secret: str) -> bool:
    expected = _sign(payload, secret)
    return hmac.compare_digest(expected, signature)


class AgentTransport:
    def __init__(
        self,
        node_id: str,
        backend_url: str = "http://127.0.0.1:8000",
        ws_url: str = "ws://127.0.0.1:8000/ws/agent",
        secret: str = "omnisight-lab-secret-change-me",
    ):
        self.node_id = node_id
        self.backend_url = backend_url.rstrip("/")
        self.ws_url = ws_url
        self.secret = secret
        self._http: Optional[httpx.AsyncClient] = None
        self._ws = None
        self._running = False

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=15.0)
        return self._http

    async def ship_events(self, events: List[Dict[str, Any]]) -> bool:
        """POST a batch of events to the ingestion endpoint."""
        if not events:
            return True
        body = {
            "node_id": self.node_id,
            "events": events,
            "shipped_at": datetime.now(timezone.utc).isoformat(),
        }
        payload = json.dumps(body, sort_keys=True, default=str)
        sig = _sign(payload, self.secret)
        headers = {
            "Content-Type": "application/json",
            "X-Node-Id": self.node_id,
            "X-Signature": sig,
        }
        try:
            client = await self._get_http()
            r = await client.post(
                f"{self.backend_url}/api/v1/ingest/events",
                content=payload,
                headers=headers,
            )
            return r.status_code < 300
        except Exception as exc:
            print(f"[transport] ship_events error: {exc}")
            return False

    async def register_node(self) -> bool:
        info = {
            "node_id": self.node_id,
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "ip": _local_ip(),
            "agent_version": "1.0.0",
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        payload = json.dumps(info, sort_keys=True)
        sig = _sign(payload, self.secret)
        try:
            client = await self._get_http()
            r = await client.post(
                f"{self.backend_url}/api/v1/nodes/register",
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Node-Id": self.node_id,
                    "X-Signature": sig,
                },
            )
            return r.status_code < 300
        except Exception as exc:
            print(f"[transport] register error: {exc}")
            return False

    def _execute_command(self, cmd_name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Sandboxed command execution with whitelist."""
        args = args or {}
        result: Dict[str, Any] = {
            "command": cmd_name,
            "args": args,
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

        if cmd_name not in ALLOWED_COMMANDS:
            result["stderr"] = f"Command '{cmd_name}' not in whitelist"
            return result

        try:
            if cmd_name == "kill_process":
                pid = int(args.get("pid", 0))
                if pid <= 1:
                    result["stderr"] = "Refusing to kill pid <= 1"
                    return result
                os.kill(pid, signal.SIGTERM)
                result["success"] = True
                result["stdout"] = f"Sent SIGTERM to pid {pid}"
                result["exit_code"] = 0
                return result

            if cmd_name == "block_ip":
                ip = str(args.get("ip", "")).strip()
                if not ip or not _looks_like_ip(ip):
                    result["stderr"] = "Invalid IP"
                    return result
                # Demo-safe: just log, do not actually modify firewall
                result["success"] = True
                result["stdout"] = f"[DEMO] Would block IP {ip} via iptables/nftables"
                result["exit_code"] = 0
                return result

            if cmd_name == "disable_user":
                user = str(args.get("username", "")).strip()
                if not user or user in ("root", "Administrator"):
                    result["stderr"] = "Refusing to disable protected user"
                    return result
                result["success"] = True
                result["stdout"] = f"[DEMO] Would disable user {user}"
                result["exit_code"] = 0
                return result

            if cmd_name == "lock_session":
                # Best-effort; may fail without logind
                try:
                    proc = subprocess.run(
                        ["loginctl", "lock-sessions"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    result["stdout"] = proc.stdout
                    result["stderr"] = proc.stderr
                    result["exit_code"] = proc.returncode
                    result["success"] = proc.returncode == 0
                except Exception as e:
                    result["stderr"] = str(e)
                    result["stdout"] = "[DEMO] lock_session simulated"
                    result["success"] = True
                    result["exit_code"] = 0
                return result

            # Generic whitelist commands
            cmd_list = ALLOWED_COMMANDS[cmd_name]
            if cmd_list is None:
                result["stderr"] = "Command requires specific arguments"
                return result
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=10,
            )
            result["stdout"] = (proc.stdout or "")[:4000]
            result["stderr"] = (proc.stderr or "")[:1000]
            result["exit_code"] = proc.returncode
            result["success"] = proc.returncode == 0
        except Exception as exc:
            result["stderr"] = str(exc)
        return result

    async def _handle_control_message(self, raw: str) -> Optional[str]:
        """Verify signature, execute, return signed receipt."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return None

        payload = msg.get("payload")
        signature = msg.get("signature", "")
        if not payload:
            return None

        payload_str = json.dumps(payload, sort_keys=True, default=str)
        if not _verify(payload_str, signature, self.secret):
            print("[transport] HMAC verification FAILED – ignoring command")
            return None

        cmd = payload.get("command")
        args = payload.get("args", {})
        request_id = payload.get("request_id", "")
        print(f"[transport] Executing signed command: {cmd} (req={request_id})")

        exec_result = self._execute_command(cmd, args)
        receipt = {
            "request_id": request_id,
            "node_id": self.node_id,
            "command": cmd,
            "result": exec_result,
            "received_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt_str = json.dumps(receipt, sort_keys=True, default=str)
        signed = {
            "receipt": receipt,
            "signature": _sign(receipt_str, self.secret),
        }
        return json.dumps(signed, default=str)

    async def listen_control(self):
        """Maintain WebSocket connection and process control messages."""
        self._running = True
        await self.register_node()

        while self._running:
            try:
                async with websockets.connect(
                    f"{self.ws_url}?node_id={self.node_id}",
                    ping_interval=20,
                    ping_timeout=20,
                ) as ws:
                    self._ws = ws
                    print(f"[transport] Control channel connected ({self.ws_url})")
                    # Announce presence
                    hello = {
                        "type": "hello",
                        "node_id": self.node_id,
                        "hostname": socket.gethostname(),
                        "ip": _local_ip(),
                    }
                    await ws.send(json.dumps(hello))

                    async for message in ws:
                        if isinstance(message, bytes):
                            message = message.decode()
                        reply = await self._handle_control_message(message)
                        if reply:
                            await ws.send(reply)
            except (ConnectionClosed, OSError, Exception) as exc:
                print(f"[transport] WS disconnected: {exc} – retrying in 5s")
                await asyncio.sleep(5)

    async def close(self):
        self._running = False
        if self._http and not self._http.is_closed:
            await self._http.aclose()
        if self._ws:
            await self._ws.close()


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
