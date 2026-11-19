"""
Async SQLAlchemy ORM setup with SQLite (aiosqlite).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    JSON,
    Index,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = "sqlite+aiosqlite:///./omnisight.db"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(32), unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), index=True)
    node_id = Column(String(128), index=True)
    source = Column(String(64), index=True)
    event_type = Column(String(64), index=True)
    severity = Column(String(16), index=True)
    raw = Column(Text)
    src_ip = Column(String(64), nullable=True, index=True)
    user = Column(String(128), nullable=True)
    path = Column(String(512), nullable=True)
    backfill = Column(Boolean, default=False)
    extra = Column(JSON, nullable=True)
    ingested_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_events_ts_type", "timestamp", "event_type"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(32), unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    title = Column(String(256))
    description = Column(Text)
    severity = Column(String(16), index=True)
    risk_score = Column(Float, default=0.0)
    ai_brief = Column(Text, nullable=True)
    node_id = Column(String(128), index=True)
    status = Column(String(32), default="open", index=True)  # open, acknowledged, remediated, closed
    rule_name = Column(String(128), nullable=True)
    evidence_event_ids = Column(JSON, nullable=True)
    remediation_log = Column(JSON, nullable=True)


class Node(Base):
    __tablename__ = "nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    node_id = Column(String(128), unique=True, index=True)
    hostname = Column(String(256))
    platform = Column(String(256), nullable=True)
    ip = Column(String(64), nullable=True)
    agent_version = Column(String(32), nullable=True)
    status = Column(String(32), default="online")  # online, offline, degraded
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    registered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    meta = Column(JSON, nullable=True)


class CommandReceipt(Base):
    __tablename__ = "command_receipts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), index=True)
    node_id = Column(String(128), index=True)
    command = Column(String(64))
    success = Column(Boolean)
    result = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
