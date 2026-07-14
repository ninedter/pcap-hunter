"""Tests for Case Management module."""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from app.database.models import (
    IOC,
    Analysis,
    Case,
    CaseStatus,
    IOCType,
    Job,
    Note,
    Severity,
)
from app.database.repository import CaseRepository


class TestCaseStatus:
    """Test CaseStatus enum."""

    def test_values(self):
        assert CaseStatus.OPEN.value == "open"
        assert CaseStatus.IN_PROGRESS.value == "in_progress"
        assert CaseStatus.CLOSED.value == "closed"

    def test_from_str(self):
        assert CaseStatus.from_str("open") == CaseStatus.OPEN
        assert CaseStatus.from_str("OPEN") == CaseStatus.OPEN
        assert CaseStatus.from_str("in_progress") == CaseStatus.IN_PROGRESS
        assert CaseStatus.from_str("closed") == CaseStatus.CLOSED
        assert CaseStatus.from_str("invalid") == CaseStatus.OPEN  # default


class TestSeverity:
    """Test Severity enum."""

    def test_values(self):
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_from_str(self):
        assert Severity.from_str("low") == Severity.LOW
        assert Severity.from_str("HIGH") == Severity.HIGH
        assert Severity.from_str("invalid") == Severity.MEDIUM  # default


class TestIOCType:
    """Test IOCType enum."""

    def test_values(self):
        assert IOCType.IP.value == "ip"
        assert IOCType.DOMAIN.value == "domain"
        assert IOCType.HASH.value == "hash"
        assert IOCType.JA3.value == "ja3"
        assert IOCType.URL.value == "url"

    def test_from_str(self):
        assert IOCType.from_str("ip") == IOCType.IP
        assert IOCType.from_str("DOMAIN") == IOCType.DOMAIN
        assert IOCType.from_str("invalid") == IOCType.IP  # default


class TestIOC:
    """Test IOC dataclass."""

    def test_default_values(self):
        ioc = IOC()
        assert ioc.id is None
        assert ioc.ioc_type == IOCType.IP
        assert ioc.value == ""
        assert ioc.context == ""
        assert ioc.severity == Severity.MEDIUM

    def test_to_dict(self):
        ioc = IOC(
            id=1,
            ioc_type=IOCType.DOMAIN,
            value="evil.com",
            context="C2 server",
            severity=Severity.HIGH,
        )
        d = ioc.to_dict()
        assert d["id"] == 1
        assert d["ioc_type"] == "domain"
        assert d["value"] == "evil.com"
        assert d["context"] == "C2 server"
        assert d["severity"] == "high"

    def test_from_dict(self):
        data = {
            "id": 2,
            "ioc_type": "hash",
            "value": "abc123",
            "context": "Malware hash",
            "severity": "critical",
        }
        ioc = IOC.from_dict(data)
        assert ioc.id == 2
        assert ioc.ioc_type == IOCType.HASH
        assert ioc.value == "abc123"
        assert ioc.severity == Severity.CRITICAL


class TestNote:
    """Test Note dataclass."""

    def test_default_values(self):
        note = Note()
        assert note.id is None
        assert note.content == ""
        assert isinstance(note.created_at, datetime)
        assert note.updated_at is None

    def test_to_dict(self):
        now = datetime.now()
        note = Note(id=1, content="Test note", created_at=now)
        d = note.to_dict()
        assert d["id"] == 1
        assert d["content"] == "Test note"
        assert d["created_at"] == now.isoformat()

    def test_from_dict(self):
        data = {
            "id": 3,
            "content": "Important finding",
            "created_at": "2024-01-15T10:30:00",
        }
        note = Note.from_dict(data)
        assert note.id == 3
        assert note.content == "Important finding"
        assert note.created_at.year == 2024


class TestAnalysis:
    """Test Analysis dataclass."""

    def test_default_values(self):
        analysis = Analysis()
        assert analysis.id == ""
        assert analysis.case_id == ""
        assert analysis.pcap_path == ""
        assert analysis.packet_count == 0
        assert analysis.features == {}
        assert analysis.iocs == []

    def test_to_dict(self):
        analysis = Analysis(
            id="ANL-001",
            case_id="CASE-001",
            pcap_path="/path/to/file.pcap",
            pcap_hash="abc123",
            packet_count=1000,
            features={"test": "value"},
            iocs=[IOC(value="1.2.3.4")],
        )
        d = analysis.to_dict()
        assert d["id"] == "ANL-001"
        assert d["case_id"] == "CASE-001"
        assert d["packet_count"] == 1000
        assert len(d["iocs"]) == 1

    def test_to_dict_and_repository_round_trip_new_analytic_fields(self, tmp_path):
        analysis = Analysis(
            case_id="CASE-001",
            pcap_path="/tmp/test.pcap",
            attack_mapping={"attack_version": "19.1", "techniques": [{"technique_id": "T1571"}]},
            capture_metrics={"flow_count": 4, "visibility_gaps": ["zeek"]},
        )
        payload = analysis.to_dict()
        restored = Analysis.from_dict(payload)

        assert restored.attack_mapping["attack_version"] == "19.1"
        assert restored.capture_metrics["flow_count"] == 4

        repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
        analysis_id = repo.save_analysis(analysis)
        persisted = repo.get_analysis(analysis_id)

        assert persisted is not None
        assert persisted.attack_mapping["techniques"][0]["technique_id"] == "T1571"
        assert persisted.capture_metrics["visibility_gaps"] == ["zeek"]

    def test_from_dict(self):
        data = {
            "id": "ANL-002",
            "case_id": "CASE-002",
            "pcap_path": "/path/to/test.pcap",
            "packet_count": 500,
            "iocs": [{"ioc_type": "ip", "value": "8.8.8.8"}],
        }
        analysis = Analysis.from_dict(data)
        assert analysis.id == "ANL-002"
        assert len(analysis.iocs) == 1
        assert analysis.iocs[0].value == "8.8.8.8"


class TestCase:
    """Test Case dataclass."""

    def test_default_values(self):
        case = Case()
        assert case.id == ""
        assert case.title == ""
        assert case.status == CaseStatus.OPEN
        assert case.severity == Severity.MEDIUM
        assert case.analyses == []
        assert case.notes == []
        assert case.tags == []

    def test_to_dict(self):
        case = Case(
            id="CASE-001",
            title="Malware Investigation",
            description="Investigating suspicious traffic",
            status=CaseStatus.IN_PROGRESS,
            severity=Severity.HIGH,
            tags=["malware", "c2"],
        )
        d = case.to_dict()
        assert d["id"] == "CASE-001"
        assert d["title"] == "Malware Investigation"
        assert d["status"] == "in_progress"
        assert d["severity"] == "high"
        assert d["tags"] == ["malware", "c2"]

    def test_from_dict(self):
        data = {
            "id": "CASE-002",
            "title": "Test Case",
            "status": "closed",
            "severity": "low",
            "analyses": [],
            "notes": [],
        }
        case = Case.from_dict(data)
        assert case.id == "CASE-002"
        assert case.status == CaseStatus.CLOSED
        assert case.severity == Severity.LOW

    def test_analysis_count(self):
        case = Case()
        assert case.analysis_count == 0
        case.analyses.append(Analysis())
        assert case.analysis_count == 1

    def test_ioc_count(self):
        case = Case()
        assert case.ioc_count == 0
        analysis = Analysis(iocs=[IOC(), IOC()])
        case.analyses.append(analysis)
        assert case.ioc_count == 2

    def test_add_analysis(self):
        case = Case(id="CASE-001")
        analysis = Analysis(id="ANL-001")
        case.add_analysis(analysis)
        assert len(case.analyses) == 1
        assert analysis.case_id == "CASE-001"

    def test_add_note(self):
        case = Case(id="CASE-001")
        note = case.add_note("Test note content")
        assert len(case.notes) == 1
        assert note.content == "Test note content"

    def test_close_and_reopen(self):
        case = Case(status=CaseStatus.OPEN)
        case.close()
        assert case.status == CaseStatus.CLOSED
        assert case.closed_at is not None

        case.reopen()
        assert case.status == CaseStatus.OPEN
        assert case.closed_at is None


class TestCaseRepository:
    """Test CaseRepository class."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        Path(db_path).unlink(missing_ok=True)

    @pytest.fixture
    def repo(self, temp_db):
        """Create repository with temp database."""
        return CaseRepository(temp_db)

    def test_create_case(self, repo):
        """Test creating a case."""
        case = Case(
            title="Test Case",
            description="Test description",
            severity=Severity.HIGH,
        )
        case_id = repo.create_case(case)
        assert case_id != ""
        assert len(case_id) == 8  # UUID prefix

    def test_get_case(self, repo):
        """Test getting a case by ID."""
        case = Case(title="Get Test")
        case_id = repo.create_case(case)

        retrieved = repo.get_case(case_id)
        assert retrieved is not None
        assert retrieved.id == case_id
        assert retrieved.title == "Get Test"

    def test_get_case_not_found(self, repo):
        """Test getting non-existent case."""
        result = repo.get_case("nonexistent-id")
        assert result is None

    def test_list_cases(self, repo):
        """Test listing all cases."""
        repo.create_case(Case(title="Case 1"))
        repo.create_case(Case(title="Case 2"))
        repo.create_case(Case(title="Case 3"))

        cases = repo.list_cases()
        assert len(cases) == 3

    def test_list_cases_with_status_filter(self, repo):
        """Test listing cases with status filter."""
        repo.create_case(Case(title="Open Case", status=CaseStatus.OPEN))
        repo.create_case(Case(title="Closed Case", status=CaseStatus.CLOSED))

        open_cases = repo.list_cases(status=CaseStatus.OPEN)
        assert len(open_cases) == 1
        assert open_cases[0].title == "Open Case"

    def test_update_case(self, repo):
        """Test updating a case."""
        case_id = repo.create_case(Case(title="Original"))
        case = repo.get_case(case_id)
        case.title = "Updated"
        case.status = CaseStatus.IN_PROGRESS

        repo.update_case(case)
        retrieved = repo.get_case(case_id)
        assert retrieved.title == "Updated"
        assert retrieved.status == CaseStatus.IN_PROGRESS

    def test_delete_case(self, repo):
        """Test deleting a case."""
        case_id = repo.create_case(Case(title="To Delete"))
        assert repo.get_case(case_id) is not None

        repo.delete_case(case_id)
        assert repo.get_case(case_id) is None

    def test_clear_all(self, repo):
        """Test clearing all data from repository."""
        # Create some data
        c1 = repo.create_case(Case(title="Case 1"))
        repo.create_case(Case(title="Case 2"))
        repo.add_note(c1, "Note 1")
        repo.save_analysis(Analysis(case_id=c1, pcap_path="/p1.pcap"))

        assert len(repo.list_cases()) == 2

        # Clear all
        assert repo.clear_all() is True

        # Verify empty
        assert len(repo.list_cases()) == 0
        assert repo.get_case(c1) is None
        assert repo.get_statistics()["total_cases"] == 0
        assert repo.get_statistics()["total_analyses"] == 0

    def test_clear_all_reaps_jobs(self, repo):
        """clear_all must delete job rows along with the case data."""
        case_id = repo.create_case(Case(title="With Job"))
        job_id = repo.create_job(Job(case_id=case_id, pcap_path="/p.pcap"))
        assert repo.get_job(job_id) is not None

        assert repo.clear_all() is True

        assert repo.get_job(job_id) is None
        conn = repo._get_conn()
        try:
            assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
        finally:
            conn.close()

    def test_save_analysis_to_case(self, repo):
        """Test saving analysis to case."""
        case_id = repo.create_case(Case(title="With Analysis"))
        analysis = Analysis(
            case_id=case_id,
            pcap_path="/path/to/file.pcap",
            pcap_hash="abc123",
            packet_count=1000,
        )

        analysis_id = repo.save_analysis(analysis)
        assert analysis_id != ""

        # Verify it's linked to case
        updated_case = repo.get_case(case_id)
        assert len(updated_case.analyses) == 1

    def test_get_analysis(self, repo):
        """Test getting analysis by ID."""
        case_id = repo.create_case(Case(title="Analysis Test"))
        analysis = Analysis(
            case_id=case_id,
            pcap_path="/test.pcap",
            packet_count=500,
        )
        analysis_id = repo.save_analysis(analysis)

        retrieved = repo.get_analysis(analysis_id)
        assert retrieved is not None
        assert retrieved.packet_count == 500

    def test_save_analysis_with_iocs(self, repo):
        """Test saving analysis with IOCs."""
        case_id = repo.create_case(Case(title="With IOCs"))
        analysis = Analysis(
            case_id=case_id,
            pcap_path="/test.pcap",
            iocs=[
                IOC(ioc_type=IOCType.IP, value="1.2.3.4", severity=Severity.HIGH),
                IOC(ioc_type=IOCType.DOMAIN, value="evil.com"),
            ],
        )
        analysis_id = repo.save_analysis(analysis)

        retrieved = repo.get_analysis(analysis_id)
        assert len(retrieved.iocs) == 2

    def test_save_analysis_replaces_existing_iocs(self, repo):
        """Saving an existing analysis ID must not leave stale IOC rows."""
        case_id = repo.create_case(Case(title="Replace IOCs"))
        analysis = Analysis(
            id="analysis-1",
            case_id=case_id,
            pcap_path="/test.pcap",
            iocs=[
                IOC(ioc_type=IOCType.IP, value="1.2.3.4"),
                IOC(ioc_type=IOCType.DOMAIN, value="old.example"),
            ],
        )
        repo.save_analysis(analysis)

        analysis.iocs = [IOC(ioc_type=IOCType.HASH, value="ab" * 32)]
        repo.save_analysis(analysis)

        retrieved = repo.get_analysis("analysis-1")
        assert [ioc.value for ioc in retrieved.iocs] == ["ab" * 32]
        assert retrieved.iocs[0].ioc_type == IOCType.HASH

    def test_search_iocs(self, repo):
        """Test IOC search."""
        case_id = repo.create_case(Case(title="IOC Search Test"))
        analysis = Analysis(
            case_id=case_id,
            pcap_path="/test.pcap",
            iocs=[
                IOC(ioc_type=IOCType.IP, value="192.168.1.1"),
                IOC(ioc_type=IOCType.IP, value="192.168.1.2"),
                IOC(ioc_type=IOCType.DOMAIN, value="evil.com"),
            ],
        )
        repo.save_analysis(analysis)

        # Search by value
        results = repo.search_iocs(value="192.168")
        assert len(results) == 2

        # Search by type
        results = repo.search_iocs(value="", ioc_type=IOCType.DOMAIN)
        assert len(results) == 1
        assert results[0][0].value == "evil.com"

    def test_add_note_to_case(self, repo):
        """Test adding note to case."""
        case_id = repo.create_case(Case(title="With Note"))
        note_id = repo.add_note(case_id, "Test note content")

        assert note_id is not None

        # Verify note is linked
        updated_case = repo.get_case(case_id)
        assert len(updated_case.notes) == 1
        assert updated_case.notes[0].content == "Test note content"

    def test_case_with_tags(self, repo):
        """Test case with tags."""
        case = Case(
            title="Tagged Case",
            tags=["malware", "c2", "urgent"],
        )
        case_id = repo.create_case(case)

        retrieved = repo.get_case(case_id)
        assert len(retrieved.tags) == 3
        assert "malware" in retrieved.tags

    def test_get_statistics(self, repo):
        """Test getting repository statistics."""
        repo.create_case(Case(title="Case 1", status=CaseStatus.OPEN))
        repo.create_case(Case(title="Case 2", status=CaseStatus.CLOSED))

        stats = repo.get_statistics()
        assert stats["total_cases"] == 2
        assert "by_status" in stats
        assert stats["by_status"].get("open", 0) == 1
        assert stats["by_status"].get("closed", 0) == 1


class TestCascadeDeletion:
    """Deleting a case must remove every related row — the FK pragma is off, so
    the schema's declared ON DELETE CASCADE clauses never fire on their own."""

    def test_delete_case_cascades_all_related_rows(self, tmp_path):
        repo = CaseRepository(db_path=str(tmp_path / "t.db"))
        repo.create_case(
            Case(id="del00001", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW, tags=["x"])
        )
        analysis = Analysis(case_id="del00001", pcap_path="x.pcap", packet_count=1, features={"artifacts": {}})
        analysis.iocs = [IOC(ioc_type=IOCType.IP, value="203.0.113.9", context="t", severity=Severity.HIGH)]
        aid = repo.save_analysis(analysis)
        repo.add_note("del00001", "investigation note", analysis_id=aid)
        job_id = repo.create_job(Job(case_id="del00001", pcap_path="x.pcap", options_json="{}"))

        assert repo.delete_case("del00001") is True

        conn = repo._get_conn()
        try:
            for table, where, arg in [
                ("analyses", "id = ?", aid),
                ("iocs", "analysis_id = ?", aid),
                ("jobs", "id = ?", job_id),
                ("case_tags", "case_id = ?", "del00001"),
                ("notes", "case_id = ?", "del00001"),
            ]:
                n = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", (arg,)).fetchone()[0]
                assert n == 0, f"{table} row survived case deletion"
        finally:
            conn.close()

    def test_delete_case_returns_false_for_unknown_case(self, tmp_path):
        repo = CaseRepository(db_path=str(tmp_path / "t.db"))
        assert repo.delete_case("nonexistent-id") is False

    def test_delete_case_leaves_other_cases_intact(self, tmp_path):
        """The explicit child-table deletes must be scoped to the deleted case only."""
        repo = CaseRepository(db_path=str(tmp_path / "t.db"))
        for cid, ip in [("del00003", "203.0.113.3"), ("keep0001", "203.0.113.4")]:
            repo.create_case(Case(id=cid, title="t", status=CaseStatus.OPEN, severity=Severity.MEDIUM, tags=["x"]))
            analysis = Analysis(case_id=cid, pcap_path="x.pcap", packet_count=1, features={"artifacts": {}})
            analysis.iocs = [IOC(ioc_type=IOCType.IP, value=ip, context="t", severity=Severity.HIGH)]
            aid = repo.save_analysis(analysis)
            repo.add_note(cid, "note", analysis_id=aid)
            repo.create_job(Job(case_id=cid, pcap_path="x.pcap", options_json="{}"))

        assert repo.delete_case("del00003") is True

        survivor = repo.get_case("keep0001")
        assert survivor is not None
        assert len(survivor.analyses) == 1
        assert len(survivor.analyses[0].iocs) == 1
        assert len(survivor.notes) == 1
        assert survivor.tags == ["x"]
        conn = repo._get_conn()
        try:
            n = conn.execute("SELECT COUNT(*) FROM jobs WHERE case_id = ?", ("keep0001",)).fetchone()[0]
            assert n == 1
        finally:
            conn.close()

    def test_feed_does_not_serve_iocs_from_deleted_case(self, tmp_path):
        """Regression: a deleted case's IOCs kept serving in the feed forever,
        because only the cases row was removed and the feed joins iocs->analyses."""
        from app.api.feed import IOCFilter, query_iocs

        repo = CaseRepository(db_path=str(tmp_path / "t.db"))
        repo.create_case(Case(id="del00002", title="t", status=CaseStatus.OPEN, severity=Severity.MEDIUM))
        analysis = Analysis(case_id="del00002", pcap_path="x.pcap", packet_count=1, features={"artifacts": {}})
        analysis.iocs = [IOC(ioc_type=IOCType.IP, value="203.0.113.9", context="t", severity=Severity.HIGH)]
        repo.save_analysis(analysis)
        assert query_iocs(repo, IOCFilter()) != [], "sanity: IOC must serve before deletion"

        assert repo.delete_case("del00002") is True

        assert query_iocs(repo, IOCFilter()) == []


class TestRepositoryCompression:
    """Test data compression in repository."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        Path(db_path).unlink(missing_ok=True)

    def test_large_features_compression(self, temp_db):
        """Test that large features data is stored and retrieved correctly."""
        repo = CaseRepository(temp_db)
        case_id = repo.create_case(Case(title="Compression Test"))

        # Create analysis with large features dict
        large_features = {
            "flows": [{"data": "x" * 1000} for _ in range(100)],
            "stats": {"key": "value" * 100},
        }
        analysis = Analysis(
            case_id=case_id,
            pcap_path="/test.pcap",
            features=large_features,
        )

        repo.save_analysis(analysis)
        retrieved_case = repo.get_case(case_id)

        # Verify features are preserved after storage/retrieval
        assert len(retrieved_case.analyses) == 1
        assert "flows" in retrieved_case.analyses[0].features
        assert len(retrieved_case.analyses[0].features["flows"]) == 100
