"""Tests for adjustable LLM context-window budgeting."""

import sys

from app import config as C
from app.llm.context_window import (
    estimate_messages,
    evidence_limits,
    fit_prompt,
    input_token_budget,
    normalize_context_window,
    output_token_budget,
)


def test_context_window_is_clamped_and_half_is_reserved_for_input():
    assert normalize_context_window(1) == C.LLM_CONTEXT_WINDOW_MIN
    assert normalize_context_window(2_000_000) == C.LLM_CONTEXT_WINDOW_MAX
    assert normalize_context_window("invalid") == C.LLM_CONTEXT_WINDOW_DEFAULT
    assert input_token_budget(100_000) == 50_000
    assert output_token_budget(10_000, 32_000) == 5_000


def test_evidence_limits_grow_with_selected_window():
    local = evidence_limits(10_000)
    frontier = evidence_limits(1_000_000)

    assert frontier.flows > local.flows
    assert frontier.osint_ips > local.osint_ips
    assert frontier.correlations > local.correlations
    assert frontier.zeek_rows > local.zeek_rows


def test_prompt_is_fitted_to_no_more_than_half_the_context_window():
    system = "System instructions. " * 100
    user = "START\n" + ("evidence-value," * 20_000) + "\nEND"

    fitted = fit_prompt(system, user, 10_000)

    assert fitted.truncated is True
    assert fitted.estimated_tokens <= 5_000
    assert estimate_messages(fitted.system, fitted.user) <= 5_000
    assert "START" in fitted.user
    assert "END" in fitted.user
    assert "evidence truncated" in fitted.user


def test_unlimited_mode_keeps_all_evidence_and_does_not_fit_prompt():
    limits = evidence_limits(10_000, unlimited_context=True)
    system = "System instructions."
    user = "START\n" + ("evidence-value," * 20_000) + "\nEND"

    fitted = fit_prompt(system, user, 10_000, unlimited_context=True)

    assert limits.flows == sys.maxsize
    assert limits.correlations == sys.maxsize
    assert fitted.user == user
    assert fitted.system == system
    assert fitted.truncated is False
    assert fitted.estimated_tokens > input_token_budget(10_000)
    assert output_token_budget(10_000, 32_000, unlimited_context=True) == 32_000
