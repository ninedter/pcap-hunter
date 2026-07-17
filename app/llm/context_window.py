"""Context-window budgeting shared by every LLM provider.

The configured model window is intentionally split in half: at most 50% is
used for system instructions plus analysis evidence, leaving the other half
for generated output and tokenizer/provider variance. Exact tokenizers are
model-specific (especially for arbitrary LM Studio models), so the app uses a
conservative UTF-8 estimate consistently when fitting prompts.
"""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass

from app import config as C

_TRUNCATION_MARKER = "\n\n...[evidence truncated to the configured 50% input budget]...\n\n"


@dataclass(frozen=True)
class EvidenceLimits:
    """Maximum evidence rows to retain before final prompt fitting."""

    correlations: int
    osint_ips: int
    osint_domains: int
    beacons: int
    flows: int
    zeek_rows: int
    detail_items: int
    hosts: int
    sanitize_list: int


@dataclass(frozen=True)
class FittedPrompt:
    """A prompt fitted to the configured model input budget."""

    system: str
    user: str
    estimated_tokens: int
    max_input_tokens: int
    truncated: bool


def normalize_context_window(value: object) -> int:
    """Return a safe context-window value within the supported UI range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = C.LLM_CONTEXT_WINDOW_DEFAULT
    return min(C.LLM_CONTEXT_WINDOW_MAX, max(C.LLM_CONTEXT_WINDOW_MIN, parsed))


def input_token_budget(context_window_tokens: object) -> int:
    """Maximum estimated input tokens (50% of the selected context window)."""
    window = normalize_context_window(context_window_tokens)
    return int(window * C.LLM_INPUT_BUDGET_RATIO)


def output_token_budget(
    context_window_tokens: object, requested_tokens: int, *, unlimited_context: bool = False
) -> int:
    """Cap output to the reserved half-window unless unlimited mode is active."""
    if unlimited_context:
        return max(1, int(requested_tokens))
    window = normalize_context_window(context_window_tokens)
    return max(1, min(int(requested_tokens), window - input_token_budget(window)))


def estimate_tokens(text: str) -> int:
    """Estimate tokens conservatively without assuming a provider tokenizer.

    One token per three UTF-8 bytes is deliberately more cautious than the
    common English-language approximation of four characters per token, while
    also accounting for CJK and other multibyte text.
    """
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8")) / 3))


def estimate_messages(system: str, user: str) -> int:
    """Estimate a two-message chat request, including role framing overhead."""
    return estimate_tokens(system) + estimate_tokens(user) + 16


def evidence_limits(context_window_tokens: object, *, unlimited_context: bool = False) -> EvidenceLimits:
    """Scale evidence row limits with the selected context window.

    The existing report evidence sizes are the baseline at 32K. Selecting a
    larger window therefore includes proportionally more flows, IOCs, OSINT
    records, and protocol samples before the hard 50% prompt fit is applied.
    """
    if unlimited_context:
        unlimited = sys.maxsize
        return EvidenceLimits(
            correlations=unlimited,
            osint_ips=unlimited,
            osint_domains=unlimited,
            beacons=unlimited,
            flows=unlimited,
            zeek_rows=unlimited,
            detail_items=unlimited,
            hosts=unlimited,
            sanitize_list=unlimited,
        )

    window = normalize_context_window(context_window_tokens)
    scale = window / C.LLM_CONTEXT_WINDOW_DEFAULT

    def scaled(base: int) -> int:
        return max(1, math.ceil(base * scale))

    return EvidenceLimits(
        correlations=scaled(10),
        osint_ips=scaled(15),
        osint_domains=scaled(10),
        beacons=scaled(10),
        flows=scaled(10),
        zeek_rows=scaled(5),
        detail_items=scaled(5),
        hosts=scaled(10),
        sanitize_list=scaled(30),
    )


def _truncate_middle(text: str, token_budget: int) -> str:
    """Keep prompt instructions at both ends while removing excess evidence."""
    if token_budget <= estimate_tokens(_TRUNCATION_MARKER):
        return _TRUNCATION_MARKER.strip()
    if estimate_tokens(text) <= token_budget:
        return text

    low, high = 0, len(text)
    best = _TRUNCATION_MARKER.strip()
    while low <= high:
        keep = (low + high) // 2
        head = math.ceil(keep * 0.7)
        tail = keep - head
        candidate = text[:head] + _TRUNCATION_MARKER + (text[-tail:] if tail else "")
        if estimate_tokens(candidate) <= token_budget:
            best = candidate
            low = keep + 1
        else:
            high = keep - 1
    return best


def fit_prompt(
    system: str, user: str, context_window_tokens: object, *, unlimited_context: bool = False
) -> FittedPrompt:
    """Fit input to 50% of the window unless unlimited mode is active."""
    if unlimited_context:
        estimated = estimate_messages(system, user)
        return FittedPrompt(
            system=system,
            user=user,
            estimated_tokens=estimated,
            max_input_tokens=estimated,
            truncated=False,
        )

    max_input = input_token_budget(context_window_tokens)
    overhead = 16
    available_user = max(0, max_input - estimate_tokens(system) - overhead)
    fitted_user = _truncate_middle(user, available_user)
    estimated = estimate_messages(system, fitted_user)

    # The 10K minimum comfortably fits current system prompts. Keep this
    # fallback defensive in case those instructions grow substantially later.
    fitted_system = system
    if estimated > max_input:
        available_system = max(0, max_input - estimate_tokens(fitted_user) - overhead)
        fitted_system = _truncate_middle(system, available_system)
        estimated = estimate_messages(fitted_system, fitted_user)

    return FittedPrompt(
        system=fitted_system,
        user=fitted_user,
        estimated_tokens=estimated,
        max_input_tokens=max_input,
        truncated=fitted_system != system or fitted_user != user,
    )
