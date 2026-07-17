"""API Key Management tab for Streamlit UI."""

from __future__ import annotations

import os
from datetime import date, datetime, timedelta

import pandas as pd
import streamlit as st

from app.api.auth import Scope
from app.api.key_models import APIKey, generate_api_key
from app.api.key_repository import KeyRepository


def _get_key_repo() -> KeyRepository:
    """Get or create KeyRepository singleton in session state."""
    if "key_repo" not in st.session_state:
        db_path = os.environ.get("PCAP_HUNTER_API_DB_PATH")
        st.session_state["key_repo"] = KeyRepository(db_path=db_path)
    return st.session_state["key_repo"]


def render_api_keys_tab():
    """Main entry point for the API Keys management tab."""
    st.markdown("### API Key Management")

    repo = _get_key_repo()

    # Dashboard metrics
    _render_metrics(repo)

    st.divider()

    # Environment keys (read-only display)
    _render_env_keys()

    st.divider()

    # Key list
    _render_key_list(repo)

    st.divider()

    # Create new key
    _render_create_key(repo)


def _render_metrics(repo: KeyRepository):
    """Render dashboard metric cards."""
    col1, col2, col3 = st.columns(3)

    active_count = repo.count_active_keys()
    expiring = repo.get_expiring_keys(within_days=7)

    # Get today's usage
    summary = repo.get_usage_summary(days=1)
    today_requests = 0
    today_str = date.today().isoformat()
    for entry in summary:
        if entry["date"] == today_str:
            today_requests = entry["requests"]

    col1.metric("Active Keys", active_count)
    col2.metric("Requests Today", today_requests)
    col3.metric("Expiring Soon (7d)", len(expiring))

    # Usage chart (last 30 days)
    usage_data = repo.get_usage_summary(days=30)
    if usage_data:
        df = pd.DataFrame(usage_data)
        df["date"] = pd.to_datetime(df["date"])
        df = df.set_index("date")
        st.bar_chart(df["requests"])


def _render_env_keys():
    """Show environment variable keys as read-only entries."""
    main_key = os.environ.get("PCAP_HUNTER_API_KEY")
    feed_key = os.environ.get("PCAP_HUNTER_FEED_KEY")

    if not main_key and not feed_key:
        return

    st.markdown("#### Environment Keys (read-only)")
    st.caption("These keys are set via environment variables and cannot be modified from the UI.")

    env_data = []
    if main_key:
        env_data.append(
            {
                "Name": "env:main",
                "Scope": "full",
                "Status": "Active",
                "Source": "PCAP_HUNTER_API_KEY",
            }
        )
    if feed_key:
        env_data.append(
            {
                "Name": "env:feed",
                "Scope": "feed",
                "Status": "Active",
                "Source": "PCAP_HUNTER_FEED_KEY",
            }
        )

    st.dataframe(pd.DataFrame(env_data), width="stretch", hide_index=True)


def _render_key_list(repo: KeyRepository):
    """Render the list of DB-backed API keys with actions."""
    st.markdown("#### Database Keys")

    show_revoked = st.checkbox("Show revoked keys", value=False)
    keys = repo.list_keys(include_revoked=show_revoked)

    if not keys:
        st.info("No API keys created yet. Use the form below to create one.")
        return

    # Build table data
    rows = []
    for k in keys:
        status_emoji = {
            "active": "\U0001f7e2",
            "expiring_soon": "\U0001f7e1",
            "expired": "\U0001f534",
            "revoked": "⊘",
        }.get(k.status, "?")

        rows.append(
            {
                "Name": k.name,
                "Prefix": k.key_prefix,
                "Scope": k.scope.value,
                "Status": f"{status_emoji} {k.status}",
                "Created": k.created_at.strftime("%Y-%m-%d") if k.created_at else "-",
                "Expires": k.expires_at.strftime("%Y-%m-%d") if k.expires_at else "Never",
                "Last Used": k.last_used_at.strftime("%Y-%m-%d %H:%M") if k.last_used_at else "Never",
                "Requests": k.total_requests,
                "Rate Limit": f"{k.rate_limit_rpm}/min" if k.rate_limit_rpm else "Unlimited",
                "ID": k.id,
            }
        )

    df = pd.DataFrame(rows)
    st.dataframe(df.drop(columns=["ID"]), width="stretch", hide_index=True)

    # Key actions (expand per key)
    st.markdown("##### Key Actions")
    selected_key_id = st.selectbox(
        "Select a key",
        options=[k.id for k in keys],
        format_func=lambda kid: next((k.name for k in keys if k.id == kid), kid),
    )

    if selected_key_id:
        selected_key = repo.get_key_by_id(selected_key_id)
        if selected_key:
            col_a, col_b = st.columns(2)

            with col_a:
                # Usage chart for selected key
                usage = repo.get_usage(selected_key_id, days=30)
                if usage:
                    st.markdown(f"**Usage (last 30 days) — {selected_key.name}**")
                    udf = pd.DataFrame(usage)
                    udf["date"] = pd.to_datetime(udf["date"])
                    udf = udf.set_index("date")
                    st.bar_chart(udf["requests"])
                else:
                    st.caption("No usage data yet.")

            with col_b:
                st.markdown("**Details**")
                st.text(f"ID: {selected_key.id}")
                st.text(f"Prefix: {selected_key.key_prefix}")
                st.text(f"Description: {selected_key.description or '(none)'}")
                st.text(f"Total requests: {selected_key.total_requests}")

                if selected_key.is_active:
                    if st.button("Revoke Key", type="secondary", key=f"revoke_{selected_key.id}"):
                        st.session_state[f"confirm_revoke_{selected_key.id}"] = True

                    if st.session_state.get(f"confirm_revoke_{selected_key.id}"):
                        st.warning(f"Are you sure you want to revoke **{selected_key.name}**? This cannot be undone.")
                        c1, c2 = st.columns(2)
                        if c1.button("Yes, revoke", key=f"yes_revoke_{selected_key.id}"):
                            repo.revoke_key(selected_key.id)
                            st.session_state.pop(f"confirm_revoke_{selected_key.id}", None)
                            st.success(f"Key **{selected_key.name}** has been revoked.")
                            st.rerun()
                        if c2.button("Cancel", key=f"cancel_revoke_{selected_key.id}"):
                            st.session_state.pop(f"confirm_revoke_{selected_key.id}", None)
                            st.rerun()


def _render_create_key(repo: KeyRepository):
    """Render the create key form."""
    st.markdown("#### Create New Key")

    with st.form("create_key_form", clear_on_submit=True):
        name = st.text_input("Key Name", max_chars=100, placeholder="e.g., Splunk production")
        scope = st.selectbox(
            "Scope",
            options=["feed", "full"],
            index=0,
            help="'feed' = read-only IOC access. 'full' = all API operations.",
        )
        description = st.text_area("Description (optional)", max_chars=500)

        col1, col2 = st.columns(2)
        with col1:
            rate_limit = st.number_input("Rate Limit (requests/min)", min_value=0, value=0, help="0 = unlimited")
        with col2:
            never_expires = st.checkbox("Never expires", value=True)
            expires_days = st.number_input("Expires in (days)", min_value=1, value=90, disabled=never_expires)

        submitted = st.form_submit_button("Create Key", type="primary")

    if submitted:
        if not name or not name.strip():
            st.error("Key name is required.")
            return

        raw_key, key_hash, key_prefix = generate_api_key()

        api_key = APIKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=name.strip(),
            scope=Scope(scope),
            description=description.strip(),
            created_at=datetime.now(),
            expires_at=None if never_expires else datetime.now() + timedelta(days=expires_days),
            rate_limit_rpm=rate_limit if rate_limit > 0 else None,
        )

        repo.create_key(api_key)

        st.success(f"Key **{name}** created successfully!")
        st.warning("Copy this key now. It will not be shown again.")
        st.code(raw_key, language=None)
