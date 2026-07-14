"""Data models for Case Management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class JobStatus(str, Enum):
    """Job lifecycle states."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @classmethod
    def from_str(cls, value: str) -> "JobStatus":
        try:
            return cls(value.lower())
        except ValueError:
            return cls.QUEUED


class CaseStatus(str, Enum):
    """Case status enumeration."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"

    @classmethod
    def from_str(cls, value: str) -> "CaseStatus":
        """Convert string to CaseStatus."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.OPEN


class Severity(str, Enum):
    """Severity level enumeration."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Convert string to Severity."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.MEDIUM


class IOCType(str, Enum):
    """IOC type enumeration."""

    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    JA3 = "ja3"
    URL = "url"

    @classmethod
    def from_str(cls, value: str) -> "IOCType":
        """Convert string to IOCType."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.IP


@dataclass
class IOC:
    """Indicator of Compromise."""

    id: int | None = None
    ioc_type: IOCType = IOCType.IP
    value: str = ""
    context: str = ""
    severity: Severity = Severity.MEDIUM

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "context": self.context,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IOC":
        return cls(
            id=data.get("id"),
            ioc_type=IOCType.from_str(data.get("ioc_type", "ip")),
            value=data.get("value", ""),
            context=data.get("context", ""),
            severity=Severity.from_str(data.get("severity", "medium")),
        )


@dataclass
class Note:
    """Case or analysis note."""

    id: int | None = None
    content: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Note":
        created_at = data.get("created_at")
        updated_at = data.get("updated_at")

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)

        return cls(
            id=data.get("id"),
            content=data.get("content", ""),
            created_at=created_at or datetime.now(),
            updated_at=updated_at,
        )


@dataclass
class Analysis:
    """PCAP analysis linked to a case."""

    id: str = ""
    case_id: str = ""
    pcap_path: str = ""
    pcap_hash: str = ""
    packet_count: int = 0
    analyzed_at: datetime = field(default_factory=datetime.now)
    features: dict = field(default_factory=dict)
    osint: dict = field(default_factory=dict)
    report: str = ""
    yara_results: dict | None = None
    dns_analysis: dict | None = None
    tls_analysis: dict | None = None
    attack_mapping: dict | None = None
    capture_metrics: dict | None = None
    iocs: list[IOC] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "pcap_path": self.pcap_path,
            "pcap_hash": self.pcap_hash,
            "packet_count": self.packet_count,
            "analyzed_at": self.analyzed_at.isoformat() if self.analyzed_at else None,
            "features": self.features,
            "osint": self.osint,
            "report": self.report,
            "yara_results": self.yara_results,
            "dns_analysis": self.dns_analysis,
            "tls_analysis": self.tls_analysis,
            "attack_mapping": self.attack_mapping,
            "capture_metrics": self.capture_metrics,
            "iocs": [ioc.to_dict() for ioc in self.iocs],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Analysis":
        analyzed_at = data.get("analyzed_at")
        if isinstance(analyzed_at, str):
            analyzed_at = datetime.fromisoformat(analyzed_at)

        iocs = [IOC.from_dict(i) for i in data.get("iocs", [])]

        return cls(
            id=data.get("id", ""),
            case_id=data.get("case_id", ""),
            pcap_path=data.get("pcap_path", ""),
            pcap_hash=data.get("pcap_hash", ""),
            packet_count=data.get("packet_count", 0),
            analyzed_at=analyzed_at or datetime.now(),
            features=data.get("features", {}),
            osint=data.get("osint", {}),
            report=data.get("report", ""),
            yara_results=data.get("yara_results"),
            dns_analysis=data.get("dns_analysis"),
            tls_analysis=data.get("tls_analysis"),
            attack_mapping=data.get("attack_mapping"),
            capture_metrics=data.get("capture_metrics"),
            iocs=iocs,
        )


@dataclass
class Case:
    """Investigation case containing analyses."""

    id: str = ""
    title: str = ""
    description: str = ""
    status: CaseStatus = CaseStatus.OPEN
    severity: Severity = Severity.MEDIUM
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    closed_at: datetime | None = None
    tags: list[str] = field(default_factory=list)
    analyses: list[Analysis] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "tags": self.tags,
            "analyses": [a.to_dict() for a in self.analyses],
            "notes": [n.to_dict() for n in self.notes],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        created_at = data.get("created_at")
        updated_at = data.get("updated_at")
        closed_at = data.get("closed_at")

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        if isinstance(closed_at, str):
            closed_at = datetime.fromisoformat(closed_at)

        analyses = [Analysis.from_dict(a) for a in data.get("analyses", [])]
        notes = [Note.from_dict(n) for n in data.get("notes", [])]

        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            status=CaseStatus.from_str(data.get("status", "open")),
            severity=Severity.from_str(data.get("severity", "medium")),
            created_at=created_at or datetime.now(),
            updated_at=updated_at or datetime.now(),
            closed_at=closed_at,
            tags=data.get("tags", []),
            analyses=analyses,
            notes=notes,
        )

    @property
    def analysis_count(self) -> int:
        """Get number of analyses."""
        return len(self.analyses)

    @property
    def ioc_count(self) -> int:
        """Get total IOC count across all analyses."""
        return sum(len(a.iocs) for a in self.analyses)

    def add_analysis(self, analysis: Analysis) -> None:
        """Add analysis to case."""
        analysis.case_id = self.id
        self.analyses.append(analysis)
        self.updated_at = datetime.now()

    def add_note(self, content: str) -> Note:
        """Add note to case."""
        note = Note(content=content)
        self.notes.append(note)
        self.updated_at = datetime.now()
        return note

    def close(self) -> None:
        """Close the case."""
        self.status = CaseStatus.CLOSED
        self.closed_at = datetime.now()
        self.updated_at = datetime.now()

    def reopen(self) -> None:
        """Reopen the case."""
        self.status = CaseStatus.OPEN
        self.closed_at = None
        self.updated_at = datetime.now()


@dataclass
class Job:
    """Async pipeline execution job."""

    id: str = ""
    case_id: str = ""
    pcap_path: str = ""
    options_json: str | None = None
    status: JobStatus = JobStatus.QUEUED
    progress_stage: str | None = None
    progress_done: int = 0
    progress_total: int = 10
    submitted_at: datetime = field(default_factory=datetime.now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    heartbeat_at: datetime | None = None
    error_code: str | None = None
    error_detail: str | None = None
    result_json: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "pcap_path": self.pcap_path,
            "options_json": self.options_json,
            "status": self.status.value,
            "progress_stage": self.progress_stage,
            "progress_done": self.progress_done,
            "progress_total": self.progress_total,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "heartbeat_at": self.heartbeat_at.isoformat() if self.heartbeat_at else None,
            "error_code": self.error_code,
            "error_detail": self.error_detail,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Job":
        submitted_at = data.get("submitted_at")
        started_at = data.get("started_at")
        finished_at = data.get("finished_at")
        heartbeat_at = data.get("heartbeat_at")

        if isinstance(submitted_at, str):
            submitted_at = datetime.fromisoformat(submitted_at)
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at)
        if isinstance(finished_at, str):
            finished_at = datetime.fromisoformat(finished_at)
        if isinstance(heartbeat_at, str):
            heartbeat_at = datetime.fromisoformat(heartbeat_at)

        return cls(
            id=data.get("id", ""),
            case_id=data.get("case_id", ""),
            pcap_path=data.get("pcap_path", ""),
            options_json=data.get("options_json"),
            status=JobStatus.from_str(data.get("status", "queued")),
            progress_stage=data.get("progress_stage"),
            progress_done=data.get("progress_done", 0),
            progress_total=data.get("progress_total", 10),
            submitted_at=submitted_at or datetime.now(),
            started_at=started_at,
            finished_at=finished_at,
            heartbeat_at=heartbeat_at,
            error_code=data.get("error_code"),
            error_detail=data.get("error_detail"),
            result_json=data.get("result_json"),
        )
