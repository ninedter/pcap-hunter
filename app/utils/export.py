"""Export utilities for CSV and JSON formats."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any

# Characters that trigger formula execution in spreadsheet apps
_CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
_MAX_EXPORT_ROWS = 100000  # Prevent memory exhaustion


def _sanitize_csv_value(value: Any) -> str:
    """
    Sanitize a value to prevent CSV injection attacks.

    Dangerous prefixes (=, +, -, @, tab, newline) can trigger formula execution
    in spreadsheet applications like Excel, LibreOffice Calc, Google Sheets.

    Args:
        value: Any value to sanitize

    Returns:
        Sanitized string safe for CSV export
    """
    if value is None:
        return ""

    str_value = str(value)

    # Neutralize dangerous prefixes by prepending a single quote
    if str_value and str_value[0] in _CSV_DANGEROUS_PREFIXES:
        return f"'{str_value}"

    return str_value


def export_to_csv(data: list[dict], filename: str | None = None) -> bytes:
    """
    Convert list of dicts to CSV bytes with injection protection.

    Args:
        data: List of dictionaries to export
        filename: Optional filename (not used, for API consistency)

    Returns:
        UTF-8 encoded CSV bytes

    Raises:
        ValueError: If data exceeds maximum row limit
    """
    if not data:
        return b""

    # Prevent memory exhaustion
    if len(data) > _MAX_EXPORT_ROWS:
        raise ValueError(f"Export exceeds maximum row limit ({_MAX_EXPORT_ROWS})")

    output = io.StringIO()

    # Flatten nested dicts for CSV
    flat_data = [_flatten_dict(row) for row in data]

    # Sanitize all values to prevent CSV injection
    sanitized_data = []
    for row in flat_data:
        sanitized_row = {k: _sanitize_csv_value(v) for k, v in row.items()}
        sanitized_data.append(sanitized_row)

    # Get all unique keys
    all_keys: list[str] = []
    for row in sanitized_data:
        for key in row.keys():
            if key not in all_keys:
                all_keys.append(key)

    writer = csv.DictWriter(output, fieldnames=all_keys, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(sanitized_data)

    return output.getvalue().encode("utf-8")


def export_to_json(data: Any, filename: str | None = None, indent: int = 2) -> bytes:
    """
    Convert data to formatted JSON bytes.

    Args:
        data: Data to export (list, dict, etc.)
        filename: Optional filename (not used, for API consistency)
        indent: JSON indentation level

    Returns:
        UTF-8 encoded JSON bytes
    """
    return json.dumps(data, indent=indent, default=_json_serializer, ensure_ascii=False).encode("utf-8")


def export_dataframe_to_csv(df, filename: str | None = None) -> bytes:
    """
    Export pandas DataFrame to CSV bytes with injection protection.

    Args:
        df: pandas DataFrame
        filename: Optional filename (not used, for API consistency)

    Returns:
        UTF-8 encoded CSV bytes
    """
    import pandas as pd

    if df is None or df.empty:
        return b""

    # Apply CSV injection sanitization to all string columns
    sanitized = df.copy()
    for col in sanitized.select_dtypes(include=["object"]).columns:
        sanitized[col] = sanitized[col].apply(
            lambda x: (
                _sanitize_csv_value(str(x))
                if not isinstance(x, (list, dict)) and pd.notna(x)
                else (_sanitize_csv_value(str(x)) if isinstance(x, (list, dict)) else x)
            )
        )
    buf = io.StringIO()
    sanitized.to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")


def export_dataframe_to_json(df, filename: str | None = None, indent: int = 2) -> bytes:
    """
    Export pandas DataFrame to JSON bytes.

    Args:
        df: pandas DataFrame
        filename: Optional filename (not used, for API consistency)
        indent: JSON indentation level

    Returns:
        UTF-8 encoded JSON bytes
    """
    if df is None or df.empty:
        return b"[]"
    return df.to_json(orient="records", indent=indent, force_ascii=False).encode("utf-8")


def generate_export_filename(prefix: str, extension: str) -> str:
    """
    Generate a timestamped filename for exports.

    Args:
        prefix: Filename prefix (e.g., "flows", "osint")
        extension: File extension (e.g., "csv", "json")

    Returns:
        Formatted filename like "flows_20250129_143052.csv"
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{extension}"


def _flatten_dict(d: dict, parent_key: str = "", sep: str = "_") -> dict:
    """Flatten nested dictionary for CSV export."""
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep).items())
        elif isinstance(v, list):
            # Convert lists to string representation
            items.append((new_key, "; ".join(str(x) for x in v) if v else ""))
        else:
            items.append((new_key, v))
    return dict(items)


def _json_serializer(obj: Any) -> Any:
    """Custom JSON serializer for non-standard types."""
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)
