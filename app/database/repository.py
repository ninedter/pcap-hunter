"""Repository layer for Case Management database operations."""

from __future__ import annotations

import gzip
import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.database.models import IOC, Analysis, Case, CaseStatus, IOCType, Job, JobStatus, Note, Severity
from app.utils.logger import get_logger

logger = get_logger(__name__)


class CaseRepository:
    """Repository for case management CRUD operations."""

    def __init__(self, db_path: str | None = None):
        """
        Initialize repository with database path.

        Args:
            db_path: Path to SQLite database. Defaults to data/cases.db
        """
        if db_path:
            self._db_path = Path(db_path)
        else:
            self._db_path = Path(__file__).parent.parent.parent / "data" / "cases.db"

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        """Initialize database schema."""
        conn = self._get_conn()
        try:
            conn.executescript(
                """
                -- Cases table
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'open',
                    severity TEXT DEFAULT 'medium',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    closed_at TIMESTAMP
                );

                -- Analyses linked to cases
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
                    pcap_path TEXT NOT NULL,
                    pcap_hash TEXT,
                    packet_count INTEGER DEFAULT 0,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    features_json TEXT,
                    osint_json TEXT,
                    report_md TEXT,
                    yara_json TEXT,
                    dns_json TEXT,
                    tls_json TEXT,
                    attack_mapping_json TEXT,
                    capture_metrics_json TEXT,
                    session_artifacts_json TEXT
                );

                -- IOCs extracted from analyses
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT REFERENCES analyses(id) ON DELETE CASCADE,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    context TEXT,
                    severity TEXT DEFAULT 'medium',
                    UNIQUE(analysis_id, ioc_type, value)
                );

                -- User notes
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
                    analysis_id TEXT REFERENCES analyses(id) ON DELETE CASCADE,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP
                );

                -- Tags for organization
                CREATE TABLE IF NOT EXISTS tags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL
                );

                CREATE TABLE IF NOT EXISTS case_tags (
                    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
                    tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
                    PRIMARY KEY (case_id, tag_id)
                );

                -- Jobs table for async pipeline execution
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
                    pcap_path TEXT NOT NULL,
                    options_json TEXT,
                    status TEXT NOT NULL DEFAULT 'queued',
                    progress_stage TEXT,
                    progress_done INTEGER DEFAULT 0,
                    progress_total INTEGER DEFAULT 10,
                    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    heartbeat_at TIMESTAMP,
                    error_code TEXT,
                    error_detail TEXT,
                    result_json BLOB
                );

                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_analyses_case ON analyses(case_id);
                CREATE INDEX IF NOT EXISTS idx_iocs_analysis ON iocs(analysis_id);
                CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(ioc_type, value);
                CREATE INDEX IF NOT EXISTS idx_notes_case ON notes(case_id);
                CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
                CREATE INDEX IF NOT EXISTS idx_jobs_case ON jobs(case_id);
                """
            )
            # Existing case databases predate ATT&CK and capture-quality
            # persistence.  Add the columns in place so upgrades do not erase
            # prior investigations.
            for column in ("attack_mapping_json", "capture_metrics_json", "session_artifacts_json"):
                try:
                    conn.execute(f"ALTER TABLE analyses ADD COLUMN {column} TEXT")  # noqa: S608 — fixed column names
                except sqlite3.OperationalError as exc:
                    if "duplicate column name" not in str(exc).lower():
                        raise
            conn.commit()

            # Idempotent column additions (ALTER TABLE ADD COLUMN errors if column exists)
            try:
                conn.execute("ALTER TABLE cases ADD COLUMN source TEXT DEFAULT 'ui'")
                conn.commit()
            except sqlite3.OperationalError:
                pass  # column already exists
        finally:
            conn.close()

    # ==================== Case CRUD ====================

    def create_case(self, case: Case) -> str:
        """
        Create a new case.

        Args:
            case: Case object to create.

        Returns:
            Generated case ID.
        """
        if not case.id:
            case.id = str(uuid.uuid4())[:8]

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO cases (id, title, description, status, severity, created_at, updated_at, closed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case.id,
                    case.title,
                    case.description,
                    case.status.value,
                    case.severity.value,
                    case.created_at.isoformat(),
                    case.updated_at.isoformat(),
                    case.closed_at.isoformat() if case.closed_at else None,
                ),
            )

            # Add tags
            for tag in case.tags:
                self._add_tag_internal(conn, case.id, tag)

            conn.commit()
            logger.info("Created case: %s", case.id)
            return case.id
        finally:
            conn.close()

    def get_case(self, case_id: str) -> Case | None:
        """
        Get case by ID with all relations.

        Args:
            case_id: Case ID.

        Returns:
            Case object or None if not found.
        """
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not row:
                return None

            case = self._row_to_case(dict(row))

            # Load tags
            case.tags = self._get_case_tags(conn, case_id)

            # Load analyses
            case.analyses = self._get_case_analyses(conn, case_id)

            # Load notes
            case.notes = self._get_case_notes(conn, case_id)

            return case
        finally:
            conn.close()

    def list_cases(
        self,
        status: CaseStatus | None = None,
        tags: list[str] | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Case]:
        """
        List cases with optional filters.

        Args:
            status: Filter by status.
            tags: Filter by tags.
            search: Search in title and description.
            limit: Maximum results.
            offset: Results offset.

        Returns:
            List of Case objects.
        """
        conn = self._get_conn()
        try:
            query = "SELECT DISTINCT c.* FROM cases c"
            params: list[Any] = []
            conditions = []

            if tags:
                query += " JOIN case_tags ct ON c.id = ct.case_id JOIN tags t ON ct.tag_id = t.id"
                placeholders = ",".join("?" * len(tags))
                conditions.append(f"t.name IN ({placeholders})")
                params.extend(tags)

            if status:
                conditions.append("c.status = ?")
                params.append(status.value)

            if search:
                escaped_search = self._escape_like(search)
                conditions.append("(c.title LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\')")
                params.extend([f"%{escaped_search}%", f"%{escaped_search}%"])

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY c.updated_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            cases = []
            for row in rows:
                case = self._row_to_case(dict(row))
                case.tags = self._get_case_tags(conn, case.id)
                cases.append(case)

            return cases
        finally:
            conn.close()

    def update_case(self, case: Case) -> None:
        """
        Update case metadata.

        Args:
            case: Case object with updated fields.
        """
        case.updated_at = datetime.now()
        conn = self._get_conn()
        try:
            conn.execute(
                """
                UPDATE cases SET
                    title = ?, description = ?, status = ?, severity = ?,
                    updated_at = ?, closed_at = ?
                WHERE id = ?
                """,
                (
                    case.title,
                    case.description,
                    case.status.value,
                    case.severity.value,
                    case.updated_at.isoformat(),
                    case.closed_at.isoformat() if case.closed_at else None,
                    case.id,
                ),
            )

            # Update tags
            conn.execute("DELETE FROM case_tags WHERE case_id = ?", (case.id,))
            for tag in case.tags:
                self._add_tag_internal(conn, case.id, tag)

            conn.commit()
            logger.info("Updated case: %s", case.id)
        finally:
            conn.close()

    def delete_case(self, case_id: str) -> bool:
        """
        Delete case and all related data.

        The schema declares ON DELETE CASCADE foreign keys, but SQLite's
        foreign_keys pragma is off per connection, so related rows in iocs,
        notes, analyses, case_tags, and jobs are deleted explicitly here.

        Args:
            case_id: Case ID to delete.

        Returns:
            True if the case existed and was deleted.
        """
        conn = self._get_conn()
        try:
            # FK pragma is off (INSERT OR REPLACE in save_analysis would
            # cascade-wipe children if enabled) -> delete related rows explicitly,
            # children first.
            conn.execute(
                "DELETE FROM iocs WHERE analysis_id IN (SELECT id FROM analyses WHERE case_id = ?)",
                (case_id,),
            )
            conn.execute(
                "DELETE FROM notes WHERE case_id = ? OR analysis_id IN (SELECT id FROM analyses WHERE case_id = ?)",
                (case_id, case_id),
            )
            conn.execute("DELETE FROM analyses WHERE case_id = ?", (case_id,))
            conn.execute("DELETE FROM case_tags WHERE case_id = ?", (case_id,))
            conn.execute("DELETE FROM jobs WHERE case_id = ?", (case_id,))
            cur = conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
            conn.commit()
            logger.info("Deleted case and related data: %s", case_id)
            return cur.rowcount > 0
        except Exception as e:
            logger.error("Failed to delete case %s: %s", case_id, e)
            return False
        finally:
            conn.close()

    def clear_all(self) -> bool:
        """
        Clear all data from all tables. Use with caution.

        Returns:
            True if cleared successfully.
        """
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM notes")
            conn.execute("DELETE FROM iocs")
            conn.execute("DELETE FROM analyses")
            conn.execute("DELETE FROM case_tags")
            conn.execute("DELETE FROM tags")
            conn.execute("DELETE FROM jobs")
            conn.execute("DELETE FROM cases")
            conn.commit()
            logger.info("Cleared all case data from database")
            return True
        except Exception as e:
            logger.error("Failed to clear all data: %s", e)
            return False
        finally:
            conn.close()

    # ==================== Analysis Operations ====================

    def save_analysis(self, analysis: Analysis) -> str:
        """
        Save analysis to database.

        Args:
            analysis: Analysis object.

        Returns:
            Analysis ID.
        """
        if not analysis.id:
            analysis.id = str(uuid.uuid4())[:12]

        conn = self._get_conn()
        try:
            # Compress JSON fields
            features_json = self._compress_json(analysis.features) if analysis.features else None
            osint_json = self._compress_json(analysis.osint) if analysis.osint else None
            yara_json = self._compress_json(analysis.yara_results) if analysis.yara_results else None
            dns_json = self._compress_json(analysis.dns_analysis) if analysis.dns_analysis else None
            tls_json = self._compress_json(analysis.tls_analysis) if analysis.tls_analysis else None
            attack_mapping_json = self._compress_json(analysis.attack_mapping) if analysis.attack_mapping else None
            capture_metrics_json = self._compress_json(analysis.capture_metrics) if analysis.capture_metrics else None
            session_artifacts_json = (
                self._compress_json(analysis.session_artifacts) if analysis.session_artifacts else None
            )

            params = (
                analysis.id,
                analysis.case_id,
                analysis.pcap_path,
                analysis.pcap_hash,
                analysis.packet_count,
                analysis.analyzed_at.isoformat(),
                features_json,
                osint_json,
                analysis.report,
                yara_json,
                dns_json,
                tls_json,
                attack_mapping_json,
                capture_metrics_json,
                session_artifacts_json,
            )
            conn.execute(
                """
                INSERT INTO analyses
                (id, case_id, pcap_path, pcap_hash, packet_count, analyzed_at,
                 features_json, osint_json, report_md, yara_json, dns_json, tls_json,
                 attack_mapping_json, capture_metrics_json, session_artifacts_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    case_id = excluded.case_id,
                    pcap_path = excluded.pcap_path,
                    pcap_hash = excluded.pcap_hash,
                    packet_count = excluded.packet_count,
                    analyzed_at = excluded.analyzed_at,
                    features_json = excluded.features_json,
                    osint_json = excluded.osint_json,
                    report_md = excluded.report_md,
                    yara_json = excluded.yara_json,
                    dns_json = excluded.dns_json,
                    tls_json = excluded.tls_json,
                    attack_mapping_json = excluded.attack_mapping_json,
                    capture_metrics_json = excluded.capture_metrics_json,
                    session_artifacts_json = excluded.session_artifacts_json
                """,
                params,
            )

            # Save IOCs as a replacement set for this analysis ID.
            conn.execute("DELETE FROM iocs WHERE analysis_id = ?", (analysis.id,))
            for ioc in analysis.iocs:
                self._save_ioc(conn, analysis.id, ioc)

            conn.commit()
            logger.info("Saved analysis: %s", analysis.id)
            return analysis.id
        finally:
            conn.close()

    def get_analysis(self, analysis_id: str) -> Analysis | None:
        """
        Get analysis by ID.

        Args:
            analysis_id: Analysis ID.

        Returns:
            Analysis object or None.
        """
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
            if not row:
                return None

            return self._row_to_analysis(dict(row), conn)
        finally:
            conn.close()

    # ==================== IOC Operations ====================

    def extract_iocs(self, analysis: Analysis) -> list[IOC]:
        """
        Extract IOCs from analysis results.

        Args:
            analysis: Analysis object.

        Returns:
            List of extracted IOCs.
        """
        iocs = []
        artifacts = analysis.features.get("artifacts", {})

        # Extract IPs
        for ip in artifacts.get("ips", []):
            iocs.append(IOC(ioc_type=IOCType.IP, value=ip, context="Extracted from PCAP"))

        # Extract domains
        for domain in artifacts.get("domains", []):
            iocs.append(IOC(ioc_type=IOCType.DOMAIN, value=domain, context="Extracted from PCAP"))

        # Extract hashes
        for h in artifacts.get("hashes", []):
            iocs.append(IOC(ioc_type=IOCType.HASH, value=h, context="Carved file hash"))

        # Extract JA3
        for ja3 in artifacts.get("ja3", []):
            iocs.append(IOC(ioc_type=IOCType.JA3, value=ja3, context="TLS fingerprint"))

        return iocs

    def search_iocs(self, value: str, ioc_type: IOCType | None = None) -> list[tuple[IOC, Case]]:
        """
        Search IOCs across all cases.

        Args:
            value: Value to search.
            ioc_type: Optional IOC type filter.

        Returns:
            List of (IOC, Case) tuples.
        """
        conn = self._get_conn()
        try:
            escaped_value = self._escape_like(value)
            query = """
                SELECT i.*, a.case_id, c.title as case_title
                FROM iocs i
                JOIN analyses a ON i.analysis_id = a.id
                JOIN cases c ON a.case_id = c.id
                WHERE i.value LIKE ? ESCAPE '\\'
            """
            params: list[Any] = [f"%{escaped_value}%"]

            if ioc_type:
                query += " AND i.ioc_type = ?"
                params.append(ioc_type.value)

            query += " LIMIT 100"

            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                ioc = IOC(
                    id=row["id"],
                    ioc_type=IOCType.from_str(row["ioc_type"]),
                    value=row["value"],
                    context=row["context"] or "",
                    severity=Severity.from_str(row["severity"] or "medium"),
                )
                case = Case(id=row["case_id"], title=row["case_title"])
                results.append((ioc, case))

            return results
        finally:
            conn.close()

    # ==================== Note Operations ====================

    def add_note(self, case_id: str, content: str, analysis_id: str | None = None) -> int:
        """
        Add note to case.

        Args:
            case_id: Case ID.
            content: Note content.
            analysis_id: Optional analysis ID.

        Returns:
            Note ID.
        """
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                """
                INSERT INTO notes (case_id, analysis_id, content, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (case_id, analysis_id, content, datetime.now().isoformat()),
            )
            conn.commit()
            return cursor.lastrowid or 0
        finally:
            conn.close()

    def update_note(self, note_id: int, content: str) -> None:
        """Update existing note."""
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE notes SET content = ?, updated_at = ? WHERE id = ?",
                (content, datetime.now().isoformat(), note_id),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_note(self, note_id: int) -> None:
        """Delete note."""
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
            conn.commit()
        finally:
            conn.close()

    # ==================== Tag Operations ====================

    def add_tag(self, case_id: str, tag: str) -> None:
        """Add tag to case."""
        conn = self._get_conn()
        try:
            self._add_tag_internal(conn, case_id, tag)
            conn.commit()
        finally:
            conn.close()

    def remove_tag(self, case_id: str, tag: str) -> None:
        """Remove tag from case."""
        conn = self._get_conn()
        try:
            tag_row = conn.execute("SELECT id FROM tags WHERE name = ?", (tag,)).fetchone()
            if tag_row:
                conn.execute("DELETE FROM case_tags WHERE case_id = ? AND tag_id = ?", (case_id, tag_row["id"]))
                conn.commit()
        finally:
            conn.close()

    def list_tags(self) -> list[str]:
        """List all tags."""
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT DISTINCT name FROM tags ORDER BY name").fetchall()
            return [row["name"] for row in rows]
        finally:
            conn.close()

    # ==================== Helper Methods ====================

    @staticmethod
    def _escape_like(value: str) -> str:
        """Escape special characters for SQL LIKE queries (%, _, \\)."""
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def _add_tag_internal(self, conn: sqlite3.Connection, case_id: str, tag: str) -> None:
        """Add tag internally within a transaction."""
        # Ensure tag exists
        conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
        tag_row = conn.execute("SELECT id FROM tags WHERE name = ?", (tag,)).fetchone()
        if tag_row:
            conn.execute("INSERT OR IGNORE INTO case_tags (case_id, tag_id) VALUES (?, ?)", (case_id, tag_row["id"]))

    def _get_case_tags(self, conn: sqlite3.Connection, case_id: str) -> list[str]:
        """Get tags for a case."""
        rows = conn.execute(
            """
            SELECT t.name FROM tags t
            JOIN case_tags ct ON t.id = ct.tag_id
            WHERE ct.case_id = ?
            """,
            (case_id,),
        ).fetchall()
        return [row["name"] for row in rows]

    def _get_case_analyses(self, conn: sqlite3.Connection, case_id: str) -> list[Analysis]:
        """Get analyses for a case."""
        rows = conn.execute("SELECT * FROM analyses WHERE case_id = ?", (case_id,)).fetchall()
        return [self._row_to_analysis(dict(row), conn) for row in rows]

    def _get_case_notes(self, conn: sqlite3.Connection, case_id: str) -> list[Note]:
        """Get notes for a case."""
        rows = conn.execute("SELECT * FROM notes WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
        return [self._row_to_note(dict(row)) for row in rows]

    def _save_ioc(self, conn: sqlite3.Connection, analysis_id: str, ioc: IOC) -> None:
        """Save IOC to database."""
        conn.execute(
            """
            INSERT OR IGNORE INTO iocs (analysis_id, ioc_type, value, context, severity)
            VALUES (?, ?, ?, ?, ?)
            """,
            (analysis_id, ioc.ioc_type.value, ioc.value, ioc.context, ioc.severity.value),
        )

    def _row_to_case(self, row: dict) -> Case:
        """Convert database row to Case object."""
        created_at = row.get("created_at")
        updated_at = row.get("updated_at")
        closed_at = row.get("closed_at")

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        if isinstance(closed_at, str):
            closed_at = datetime.fromisoformat(closed_at)

        return Case(
            id=row["id"],
            title=row["title"],
            description=row.get("description") or "",
            status=CaseStatus.from_str(row.get("status", "open")),
            severity=Severity.from_str(row.get("severity", "medium")),
            created_at=created_at or datetime.now(),
            updated_at=updated_at or datetime.now(),
            closed_at=closed_at,
        )

    def _row_to_analysis(self, row: dict, conn: sqlite3.Connection) -> Analysis:
        """Convert database row to Analysis object."""
        analyzed_at = row.get("analyzed_at")
        if isinstance(analyzed_at, str):
            analyzed_at = datetime.fromisoformat(analyzed_at)

        # Decompress JSON fields
        features = self._decompress_json(row.get("features_json")) or {}
        osint = self._decompress_json(row.get("osint_json")) or {}
        yara_results = self._decompress_json(row.get("yara_json"))
        dns_analysis = self._decompress_json(row.get("dns_json"))
        tls_analysis = self._decompress_json(row.get("tls_json"))
        attack_mapping = self._decompress_json(row.get("attack_mapping_json"))
        capture_metrics = self._decompress_json(row.get("capture_metrics_json"))
        session_artifacts = self._decompress_json(row.get("session_artifacts_json"))

        # Load IOCs
        ioc_rows = conn.execute("SELECT * FROM iocs WHERE analysis_id = ?", (row["id"],)).fetchall()
        iocs = [
            IOC(
                id=r["id"],
                ioc_type=IOCType.from_str(r["ioc_type"]),
                value=r["value"],
                context=r["context"] if r["context"] else "",
                severity=Severity.from_str(r["severity"] if r["severity"] else "medium"),
            )
            for r in ioc_rows
        ]

        return Analysis(
            id=row["id"],
            case_id=row.get("case_id") or "",
            pcap_path=row.get("pcap_path") or "",
            pcap_hash=row.get("pcap_hash") or "",
            packet_count=row.get("packet_count") or 0,
            analyzed_at=analyzed_at or datetime.now(),
            features=features,
            osint=osint,
            report=row.get("report_md") or "",
            yara_results=yara_results,
            dns_analysis=dns_analysis,
            tls_analysis=tls_analysis,
            attack_mapping=attack_mapping,
            capture_metrics=capture_metrics,
            session_artifacts=session_artifacts,
            iocs=iocs,
        )

    def _row_to_note(self, row: dict) -> Note:
        """Convert database row to Note object."""
        created_at = row.get("created_at")
        updated_at = row.get("updated_at")

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)

        return Note(
            id=row["id"],
            content=row.get("content") or "",
            created_at=created_at or datetime.now(),
            updated_at=updated_at,
        )

    def _compress_json(self, data: dict | list | None) -> bytes | None:
        """Compress JSON data."""
        if data is None:
            return None
        json_str = json.dumps(data)
        return gzip.compress(json_str.encode("utf-8"))

    def _decompress_json(self, data: bytes | None) -> dict | list | None:
        """Decompress JSON data."""
        if data is None:
            return None
        try:
            json_str = gzip.decompress(data).decode("utf-8")
            return json.loads(json_str)
        except Exception:
            # Try without decompression (for backwards compatibility)
            try:
                if isinstance(data, bytes):
                    return json.loads(data.decode("utf-8"))
                return json.loads(data)
            except Exception:
                return None

    def get_statistics(self) -> dict[str, Any]:
        """Get repository statistics."""
        conn = self._get_conn()
        try:
            cases_count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            analyses_count = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            iocs_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

            by_status = {}
            for row in conn.execute("SELECT status, COUNT(*) as cnt FROM cases GROUP BY status").fetchall():
                by_status[row["status"]] = row["cnt"]

            return {
                "total_cases": cases_count,
                "total_analyses": analyses_count,
                "total_iocs": iocs_count,
                "by_status": by_status,
            }
        finally:
            conn.close()

    # ==================== Job CRUD ====================

    def create_job(self, job: Job) -> str:
        if not job.id:
            job.id = f"j_{uuid.uuid4().hex[:8]}"
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO jobs (id, case_id, pcap_path, options_json, status,
                                  progress_stage, progress_done, progress_total,
                                  submitted_at, heartbeat_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.id,
                    job.case_id,
                    job.pcap_path,
                    job.options_json,
                    job.status.value,
                    job.progress_stage,
                    job.progress_done,
                    job.progress_total,
                    job.submitted_at.isoformat(),
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()
            return job.id
        finally:
            conn.close()

    def get_job(self, job_id: str) -> Job | None:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if not row:
                return None
            return Job.from_dict(dict(row))
        finally:
            conn.close()

    def list_jobs(
        self,
        *,
        case_id: str | None = None,
        statuses: list[JobStatus] | None = None,
        limit: int = 100,
    ) -> list[Job]:
        """List recent jobs, optionally scoped to a case and lifecycle states."""
        clauses: list[str] = []
        params: list[Any] = []
        if case_id:
            clauses.append("case_id = ?")
            params.append(case_id)
        if statuses:
            placeholders = ", ".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")  # noqa: S608 - placeholders only
            params.extend(status.value for status in statuses)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 1000)))
        conn = self._get_conn()
        try:
            rows = conn.execute(
                f"SELECT * FROM jobs {where} ORDER BY submitted_at DESC LIMIT ?",  # noqa: S608 - fixed clauses
                params,
            ).fetchall()
            return [Job.from_dict(dict(row)) for row in rows]
        finally:
            conn.close()

    def update_job_status(
        self,
        job_id: str,
        status: JobStatus,
        error_code: str | None = None,
        error_detail: str | None = None,
        result_json: bytes | None = None,
    ) -> None:
        now = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            if status == JobStatus.RUNNING:
                conn.execute(
                    "UPDATE jobs SET status=?, started_at=?, heartbeat_at=? WHERE id=?",
                    (status.value, now, now, job_id),
                )
            elif status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
                conn.execute(
                    """UPDATE jobs SET status=?, finished_at=?, error_code=?,
                                        error_detail=?, result_json=? WHERE id=?""",
                    (status.value, now, error_code, error_detail, result_json, job_id),
                )
            else:
                conn.execute("UPDATE jobs SET status=? WHERE id=?", (status.value, job_id))
            conn.commit()
        finally:
            conn.close()

    def start_job_if_queued(self, job_id: str) -> bool:
        """Atomically flip a QUEUED job to RUNNING; False if it is missing or no longer queued."""
        now = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            cur = conn.execute(
                "UPDATE jobs SET status='running', started_at=?, heartbeat_at=? WHERE id=? AND status='queued'",
                (now, now, job_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def cancel_job_if_queued(self, job_id: str) -> bool:
        """Atomically cancel a job only while it is still QUEUED; False if missing or already started."""
        conn = self._get_conn()
        try:
            cur = conn.execute(
                "UPDATE jobs SET status='cancelled', finished_at=?, error_code=NULL, error_detail=NULL, "
                "result_json=NULL WHERE id=? AND status='queued'",
                (datetime.now().isoformat(), job_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def complete_job(self, job_id: str, result_json: bytes) -> None:
        """Mark a job done and reconcile its progress in one atomic write.

        Skipped stages never emit progress events, so a finished job would
        otherwise freeze at its last snapshot (e.g. 50%).
        """
        now = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE jobs SET status='done', finished_at=?, heartbeat_at=?, error_code=NULL, "
                "error_detail=NULL, result_json=?, progress_stage='Complete', progress_done=progress_total "
                "WHERE id=?",
                (now, now, result_json, job_id),
            )
            conn.commit()
        finally:
            conn.close()

    def update_job_progress(self, job_id: str, stage: str, done: int, total: int) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE jobs SET progress_stage=?, progress_done=?, progress_total=?, heartbeat_at=? WHERE id=?",
                (stage, done, total, datetime.now().isoformat(), job_id),
            )
            conn.commit()
        finally:
            conn.close()

    def touch_job_heartbeat(self, job_id: str) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE jobs SET heartbeat_at=? WHERE id=?",
                (datetime.now().isoformat(), job_id),
            )
            conn.commit()
        finally:
            conn.close()

    def find_stale_running_jobs(self, stale_after_seconds: int = 120) -> list[Job]:
        cutoff = (datetime.now() - timedelta(seconds=stale_after_seconds)).isoformat()
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM jobs WHERE status='running' AND heartbeat_at < ?",
                (cutoff,),
            ).fetchall()
            return [Job.from_dict(dict(r)) for r in rows]
        finally:
            conn.close()

    def count_active_jobs(self) -> int:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued', 'running')").fetchone()
            return int(row[0])
        finally:
            conn.close()
