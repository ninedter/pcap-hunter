"""Validation helpers for inbound API uploads."""

from __future__ import annotations

from app.utils.pcap_validation import PCAP_MAGICS, is_valid_pcap_magic

__all__ = ["PCAP_MAGICS", "is_valid_pcap_magic"]
