"""Optional self-hosted API for persisting and browsing local scan results.

The API is deliberately opt-in. It has no cloud synchronization, telemetry, or
source-code upload behavior: scans run on paths explicitly allowed by the host.
"""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine, select, text
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

from . import __version__
from .baseline import load as load_baseline
from .config import load_config
from .engine import ConfigurationError, scan
from .models import ScanResult, ScanSummary
from .rules import RULES


class Base(DeclarativeBase):
    pass


class RepositoryRecord(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    path: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    scans: Mapped[list[ScanRecord]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    result_json: Mapped[str] = mapped_column(Text)
    findings_count: Mapped[int] = mapped_column(Integer)
    high_count: Mapped[int] = mapped_column(Integer)
    medium_count: Mapped[int] = mapped_column(Integer)
    low_count: Mapped[int] = mapped_column(Integer)
    repository: Mapped[RepositoryRecord] = relationship(back_populates="scans")


class ScanRequest(BaseModel):
    path: str = Field(min_length=1, max_length=2048)
    use_baseline: bool = True


class RepositoryView(BaseModel):
    id: str
    path: str
    created_at: datetime
    latest_scan: ScanSummary | None = None


class SettingsView(BaseModel):
    allowed_roots: list[str]


def _database_url() -> str:
    return os.getenv("REPODOCTOR_DATABASE_URL", "sqlite:///./repodoctor.db")


def _allowed_roots() -> list[Path]:
    configured = os.getenv("REPODOCTOR_ALLOWED_ROOTS")
    values = configured.split(os.pathsep) if configured else []
    return [Path(value).resolve() for value in values if value]


def _is_allowed(path: Path, roots: list[Path]) -> bool:
    return any(_within(path, root) for root in roots)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _summary(record: ScanRecord, path: str) -> ScanSummary:
    result = ScanResult.model_validate_json(record.result_json)
    return ScanSummary(
        id=record.id,
        repository=path,
        created_at=record.created_at.isoformat(),
        findings_count=record.findings_count,
        high_count=record.high_count,
        medium_count=record.medium_count,
        low_count=record.low_count,
        scores=result.scores,
    )


def create_app(database_url: str | None = None) -> FastAPI:
    """Create the API app; production schema migrations are performed by Alembic."""
    url = database_url or _database_url()
    engine = create_engine(
        url,
        future=True,
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
    )
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    allowed_roots = _allowed_roots()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        Base.metadata.create_all(engine)
        yield

    app = FastAPI(title="RepoDoctor API", version=__version__, docs_url="/docs", lifespan=lifespan)
    origins = [
        item
        for item in os.getenv("REPODOCTOR_CORS_ORIGINS", "http://localhost:3000").split(",")
        if item
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    def get_session() -> Generator[Session]:
        with sessions() as session:
            yield session

    @app.get("/api/health")
    def health(session: Session = Depends(get_session)) -> dict[str, str]:  # noqa: B008
        """Report readiness only after the persistence layer is reachable."""
        session.execute(text("SELECT 1"))
        return {"status": "ok", "service": "repodoctor-api"}

    @app.get("/api/settings", response_model=SettingsView)
    def settings() -> SettingsView:
        # Database URLs commonly embed credentials, so they must never be exposed
        # through the browser-facing API.
        return SettingsView(allowed_roots=[str(root) for root in allowed_roots])

    @app.get("/api/rules")
    def rules() -> list[dict[str, Any]]:
        return [spec.model_dump(mode="json") for spec in RULES.values()]

    @app.get("/api/repositories", response_model=list[RepositoryView])
    def repositories(session: Session = Depends(get_session)) -> list[RepositoryView]:  # noqa: B008
        records = session.scalars(
            select(RepositoryRecord).order_by(RepositoryRecord.created_at.desc())
        ).all()
        response: list[RepositoryView] = []
        for record in records:
            latest = session.scalars(
                select(ScanRecord)
                .where(ScanRecord.repository_id == record.id)
                .order_by(ScanRecord.created_at.desc())
                .limit(1)
            ).first()
            response.append(
                RepositoryView(
                    id=record.id,
                    path=record.path,
                    created_at=record.created_at,
                    latest_scan=_summary(latest, record.path) if latest else None,
                )
            )
        return response

    @app.post("/api/scans", response_model=ScanSummary, status_code=201)
    def create_scan(
        request: ScanRequest,
        session: Session = Depends(get_session),  # noqa: B008
    ) -> ScanSummary:
        if not allowed_roots:
            raise HTTPException(
                status_code=503,
                detail="REPODOCTOR_ALLOWED_ROOTS must be configured before scans are accepted",
            )
        root = Path(request.path).resolve()
        if not root.is_dir():
            raise HTTPException(status_code=422, detail="path must be an existing directory")
        if not _is_allowed(root, allowed_roots):
            raise HTTPException(status_code=403, detail="path is outside REPODOCTOR_ALLOWED_ROOTS")
        try:
            result = scan(
                root,
                config=load_config(root),
                baseline=load_baseline(root) if request.use_baseline else None,
            )
        except (ConfigurationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        repository = session.scalar(
            select(RepositoryRecord).where(RepositoryRecord.path == str(root))
        )
        if repository is None:
            repository = RepositoryRecord(id=str(uuid.uuid4()), path=str(root))
            session.add(repository)
            session.flush()
        counts = Counter(item.severity.value for item in result.findings)
        record = ScanRecord(
            id=str(uuid.uuid4()),
            repository_id=repository.id,
            result_json=result.model_dump_json(),
            findings_count=len(result.findings),
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return _summary(record, repository.path)

    @app.get("/api/scans/{scan_id}", response_model=ScanResult)
    def scan_detail(
        scan_id: str,
        session: Session = Depends(get_session),  # noqa: B008
    ) -> ScanResult:
        record = session.get(ScanRecord, scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return ScanResult.model_validate_json(record.result_json)

    @app.get("/api/repositories/{repository_id}/scans", response_model=list[ScanSummary])
    def repository_scans(
        repository_id: str,
        session: Session = Depends(get_session),  # noqa: B008
    ) -> list[ScanSummary]:
        repository = session.get(RepositoryRecord, repository_id)
        if repository is None:
            raise HTTPException(status_code=404, detail="repository not found")
        records = session.scalars(
            select(ScanRecord)
            .where(ScanRecord.repository_id == repository_id)
            .order_by(ScanRecord.created_at.desc())
        ).all()
        return [_summary(record, repository.path) for record in records]

    return app
