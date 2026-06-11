"""YARA rule scanning for carved files and malware detection."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.utils.logger import get_logger

logger = get_logger(__name__)


def _is_safe_path(base_path: str | Path, target_path: str | Path) -> bool:
    """
    Check if target_path is safely within base_path.

    Resolves symlinks and ensures no path traversal escapes the base directory.

    Args:
        base_path: The allowed base directory.
        target_path: The path to validate.

    Returns:
        True if target_path is within base_path, False otherwise.
    """
    try:
        # Check for null bytes (path injection attack)
        if isinstance(target_path, str) and "\x00" in target_path:
            logger.warning("Null byte detected in path: %s", target_path)
            return False

        target = Path(target_path)

        # Check if path is a symlink (before resolving)
        if target.is_symlink():
            logger.warning("Symlink detected, rejecting: %s", target_path)
            return False

        # Resolve to absolute path and check containment
        base = Path(base_path).resolve()
        resolved_target = target.resolve()

        # Check if target is relative to base (i.e., within base)
        resolved_target.relative_to(base)
        return True
    except (ValueError, OSError):
        return False


# Try to import yara, but make it optional
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not installed. YARA scanning disabled.")


@dataclass
class YARAMatch:
    """Represents a single YARA rule match."""

    rule_name: str
    rule_tags: list[str]
    meta: dict[str, Any]
    strings: list[tuple[int, str, bytes]]  # (offset, identifier, data)
    file_path: str
    file_hash: str

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "rule_name": self.rule_name,
            "rule_tags": self.rule_tags,
            "meta": self.meta,
            "strings": [
                {
                    "offset": offset,
                    "identifier": identifier,
                    "data": data.hex() if isinstance(data, bytes) else str(data),
                }
                for offset, identifier, data in self.strings[:10]  # Limit strings
            ],
            "file_path": self.file_path,
            "file_hash": self.file_hash,
        }


@dataclass
class YARAScanResult:
    """Result of scanning a single file."""

    file_path: str
    file_hash: str
    file_size: int
    matches: list[YARAMatch] = field(default_factory=list)
    scan_time: float = 0.0
    error: str | None = None

    @property
    def has_matches(self) -> bool:
        """Check if any rules matched."""
        return len(self.matches) > 0

    @property
    def severity(self) -> str:
        """Determine severity based on matches."""
        if not self.matches:
            return "clean"

        # Check for high-severity tags
        all_tags = []
        for match in self.matches:
            all_tags.extend(match.rule_tags)

        if any(t in all_tags for t in ["malware", "trojan", "ransomware", "backdoor"]):
            return "critical"
        if any(t in all_tags for t in ["suspicious", "packed", "obfuscated"]):
            return "high"
        if any(t in all_tags for t in ["pup", "adware", "miner"]):
            return "medium"
        return "low"

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "matches": [m.to_dict() for m in self.matches],
            "scan_time": self.scan_time,
            "error": self.error,
            "severity": self.severity,
            "has_matches": self.has_matches,
        }


class YARAScanner:
    """YARA rule scanner for malware detection."""

    # Resource limits
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file
    MAX_SCAN_TIMEOUT = 60  # seconds per file

    def __init__(self, rules_dirs: list[str] | None = None, allowed_base: str | None = None):
        """
        Initialize YARA scanner.

        Args:
            rules_dirs: List of directories containing YARA rules.
                       If None, uses default rules directory.
            allowed_base: Optional base directory for path validation.
                         If set, only files within this directory can be scanned.
        """
        self._rules: yara.Rules | None = None
        self._rule_count = 0
        self._rules_dirs: list[Path] = []
        self._allowed_base: Path | None = Path(allowed_base).resolve() if allowed_base else None

        if not YARA_AVAILABLE:
            logger.warning("YARA not available, scanner will be disabled")
            return

        # Set up rules directories
        if rules_dirs:
            self._rules_dirs = [Path(d) for d in rules_dirs if Path(d).exists()]
        else:
            # Use default rules directory
            default_dir = Path(__file__).parent.parent / "data" / "yara"
            if default_dir.exists():
                self._rules_dirs = [default_dir]

        # Load rules on init
        self.load_rules()

    @property
    def is_available(self) -> bool:
        """Check if YARA scanning is available."""
        return YARA_AVAILABLE and self._rules is not None

    @property
    def rule_count(self) -> int:
        """Get number of loaded rules."""
        return self._rule_count

    def load_rules(self) -> int:
        """
        Compile all YARA rules from configured directories.

        Returns:
            Number of rules loaded.
        """
        if not YARA_AVAILABLE:
            return 0

        rule_files: dict[str, str] = {}
        self._rule_count = 0

        for rules_dir in self._rules_dirs:
            if not rules_dir.exists():
                continue

            # Find all .yar and .yara files
            for ext in ["*.yar", "*.yara"]:
                for rule_file in rules_dir.rglob(ext):
                    namespace = rule_file.stem
                    rule_files[namespace] = str(rule_file)

        if not rule_files:
            logger.info("No YARA rules found")
            return 0

        try:
            self._rules = yara.compile(filepaths=rule_files)
            # Count rules (approximate by namespace count)
            self._rule_count = len(rule_files)
            logger.info("Loaded %d YARA rule files", self._rule_count)
            return self._rule_count
        except yara.SyntaxError as e:
            logger.error("YARA syntax error: %s", e)
            return 0
        except yara.Error as e:
            logger.error("YARA error loading rules: %s", e)
            return 0

    def add_custom_rules(self, rules_path: str) -> bool:
        """
        Add custom rule file or directory.

        Args:
            rules_path: Path to rule file or directory.

        Returns:
            True if rules were added successfully.
        """
        path = Path(rules_path)
        if not path.exists():
            logger.error("Rules path not found: %s", rules_path)
            return False

        if path.is_dir():
            self._rules_dirs.append(path)
        elif path.is_file() and path.suffix in [".yar", ".yara"]:
            # Add parent directory
            self._rules_dirs.append(path.parent)
        else:
            logger.error("Invalid rules path: %s", rules_path)
            return False

        # Reload all rules
        return self.load_rules() > 0

    def _extract_strings(self, strings) -> list[tuple[int, str, bytes]]:
        """
        Extract string matches from YARA results.

        Handles both yara-python API versions:
        - >= 4.x: Uses StringMatch objects with .instances property
        - < 4.x: Uses tuples of (offset, identifier, data)

        Args:
            strings: List of string matches from yara.

        Returns:
            List of (offset, identifier, data) tuples.
        """
        result = []
        for s in strings:
            try:
                # New yara-python 4.x API: StringMatch objects with .instances
                if hasattr(s, "instances"):
                    identifier = s.identifier if hasattr(s, "identifier") else str(s)
                    for instance in s.instances:
                        offset = instance.offset if hasattr(instance, "offset") else 0
                        data = instance.matched_data if hasattr(instance, "matched_data") else b""
                        result.append((offset, identifier, data))
                # Old API: tuples of (offset, identifier, data)
                elif isinstance(s, (list, tuple)) and len(s) >= 3:
                    result.append((s[0], s[1], s[2]))
                else:
                    # Fallback for unknown formats
                    logger.debug("Unknown YARA string format: %s", type(s))
                    result.append((0, str(s), b""))
            except (AttributeError, TypeError, IndexError) as e:
                logger.warning("Error extracting YARA string match: %s", e)
                continue
        return result

    def scan_file(self, file_path: str) -> YARAScanResult:
        """
        Scan a single file with YARA rules.

        Args:
            file_path: Path to file to scan.

        Returns:
            YARAScanResult with matches and metadata.
        """
        path = Path(file_path)
        result = YARAScanResult(
            file_path=file_path,
            file_hash="",
            file_size=0,
        )

        # Validate path is within allowed base if set
        if self._allowed_base and not _is_safe_path(self._allowed_base, file_path):
            result.error = f"Path outside allowed directory: {file_path}"
            logger.warning("Attempted to scan path outside allowed base: %s", file_path)
            return result

        # Validate file
        if not path.exists():
            result.error = f"File not found: {file_path}"
            return result

        if not path.is_file():
            result.error = f"Not a file: {file_path}"
            return result

        try:
            result.file_size = path.stat().st_size
        except OSError as e:
            result.error = f"Cannot access file: {e}"
            return result

        # Check size limit
        if result.file_size > self.MAX_FILE_SIZE:
            result.error = f"File too large: {result.file_size} bytes (max: {self.MAX_FILE_SIZE})"
            return result

        if result.file_size == 0:
            result.error = "File is empty"
            return result

        # Check if YARA is available
        if not self.is_available:
            result.error = "YARA scanning not available"
            return result

        # Read file and compute hash
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            result.file_hash = hashlib.sha256(data).hexdigest()
        except OSError as e:
            result.error = f"Error reading file: {e}"
            return result

        # Scan with YARA
        start_time = time.time()
        try:
            matches = self._rules.match(data=data, timeout=self.MAX_SCAN_TIMEOUT)
            result.scan_time = time.time() - start_time

            # Convert matches
            for match in matches:
                yara_match = YARAMatch(
                    rule_name=match.rule,
                    rule_tags=list(match.tags),
                    meta=dict(match.meta),
                    strings=self._extract_strings(match.strings),
                    file_path=file_path,
                    file_hash=result.file_hash,
                )
                result.matches.append(yara_match)

        except yara.TimeoutError:
            result.error = "YARA scan timeout"
            result.scan_time = time.time() - start_time
        except yara.Error as e:
            result.error = f"YARA scan error: {e}"
            result.scan_time = time.time() - start_time

        return result

    def scan_carved(self, carved: list[dict], phase=None) -> dict:
        """
        Scan all carved files with progress tracking.

        Args:
            carved: List of carved file dictionaries from carve_http_payloads.
            phase: Optional PhaseHandle for progress tracking.

        Returns:
            Dictionary with scan results and summary.
        """
        results = {
            "scanned": 0,
            "matched": 0,
            "errors": 0,
            "results": [],
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0},
            "yara_available": self.is_available,
            "rule_count": self._rule_count,
        }

        if not carved:
            if phase:
                phase.done("No files to scan.")
            return results

        if not self.is_available:
            # Distinguish "library missing" from "library fine, no rules loaded" —
            # the latter is the default state (no rules ship with the app) and
            # "not available" misleads users into debugging their install.
            if YARA_AVAILABLE:
                if phase:
                    phase.done("No YARA rules configured — add a rules directory in Config.")
                results["error"] = "no yara rules configured"
            else:
                if phase:
                    phase.done("YARA not available.")
                results["error"] = "YARA scanning not available"
            return results

        total = len(carved)
        if phase:
            phase.set(5, f"Scanning {total} files...")

        for i, item in enumerate(carved, start=1):
            if phase and phase.should_skip():
                break

            file_path = item.get("path")
            if not file_path:
                continue

            scan_result = self.scan_file(file_path)
            results["scanned"] += 1

            if scan_result.error:
                results["errors"] += 1
            elif scan_result.has_matches:
                results["matched"] += 1

            results["by_severity"][scan_result.severity] += 1
            results["results"].append(scan_result.to_dict())

            if phase:
                pct = 5 + int((i / total) * 90)
                phase.set(pct, f"Scanned {i}/{total} files, {results['matched']} matches")

        if phase:
            if phase.should_skip():
                phase.done("YARA scanning skipped.")
            else:
                phase.done(f"Scanned {results['scanned']} files, {results['matched']} matches found.")

        return results

    def scan_directory(self, dir_path: str, phase=None) -> dict:
        """
        Scan all files in a directory.

        Args:
            dir_path: Path to directory to scan.
            phase: Optional PhaseHandle for progress tracking.

        Returns:
            Dictionary with scan results.
        """
        path = Path(dir_path)
        if not path.exists() or not path.is_dir():
            return {"error": f"Invalid directory: {dir_path}"}

        # Collect files
        files = list(path.rglob("*"))
        files = [f for f in files if f.is_file()]

        # Create carved-style list for scan_carved
        carved = [{"path": str(f)} for f in files]
        return self.scan_carved(carved, phase)


def scan_carved_files(carved: list[dict], rules_dirs: list[str] | None = None, phase=None) -> dict:
    """
    Convenience function to scan carved files.

    Args:
        carved: List of carved file dictionaries.
        rules_dirs: Optional list of YARA rule directories.
        phase: Optional PhaseHandle for progress.

    Returns:
        Scan results dictionary.
    """
    scanner = YARAScanner(rules_dirs)
    return scanner.scan_carved(carved, phase)
