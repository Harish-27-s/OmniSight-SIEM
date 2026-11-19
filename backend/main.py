"""
Omnisight SIEM — FastAPI entry point.
Routers + background task loops (node heartbeat cleanup, etc.).
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, update

from backend.database import Node, init_db, AsyncSessionLocal
from backend import ingestion, orchestration, reporting


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Background: mark stale nodes offline
    task = asyncio.create_task(_node_watchdog())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="Omnisight SIEM",
    description="Local-first modular security platform — ingestion, detection, orchestration, reporting",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingestion.router)
app.include_router(orchestration.router)
app.include_router(reporting.router)


@app.get("/")
async def root():
    return {
        "name": "Omnisight SIEM",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/api/v1/health")
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "connected_agents": len(orchestration._live_agents),
    }


async def _node_watchdog():
    """Periodically mark nodes offline if last_seen is stale."""
    while True:
        try:
            async with AsyncSessionLocal() as session:
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=90)
                await session.execute(
                    update(Node)
                    .where(Node.last_seen < cutoff)
                    .where(Node.status != "offline")
                    .values(status="offline")
                )
                await session.commit()
        except Exception:
            pass
        await asyncio.sleep(30)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
