"""Case Management UI Tab for PCAP Hunter."""

from __future__ import annotations

import json
from datetime import datetime

import pandas as pd
import streamlit as st

from app.analysis.flow_aggregates import compute_flow_aggregates
from app.analysis.visibility import build_capture_metrics
from app.database import Analysis, Case, CaseRepository, CaseStatus, IOCType, Severity
from app.pipeline.batch import BatchProcessor, PCAPResult
from app.ui.colors import severity_color
from app.ui.mitre_page import build_attack_mapping
from app.utils.common import uniq_sorted
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Input validation constants
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 10000
MAX_NOTE_LENGTH = 10000
MAX_TAG_LENGTH = 50
MAX_SEARCH_LENGTH = 500


def _validate_length(value: str, max_length: int, field_name: str) -> str | None:
    """
    Validate string length.

    Args:
        value: The input string to validate.
        max_length: Maximum allowed length.
        field_name: Name of the field for error messages.

    Returns:
        Error message if validation fails, None if valid.
    """
    if len(value) > max_length:
        return f"{field_name} exceeds maximum length of {max_length} characters."
    return None


def _get_repo() -> CaseRepository:
    """Get or create case repository."""
    if "case_repo" not in st.session_state:
        st.session_state["case_repo"] = CaseRepository()
    return st.session_state["case_repo"]


def _restore_analysis_to_session(analysis: Analysis) -> None:
    """Load a saved analysis back into session state for the Dashboard/Results tabs.

    Mirrors the session keys the pipeline populates after a live run. Keys that
    are not persisted on Analysis (beacon_df, zeek_tables, carved files, JA3,
    correlation/anomaly results) are reset instead of leaving stale data from a
    previously analyzed capture. ATT&CK mapping and capture-quality metrics are
    persisted when the analysis was saved. Dashboard filters are cleared because
    they reference IPs/time ranges from the prior capture and would otherwise
    filter the restored flows down to nothing.

    Args:
        analysis: The saved analysis to load into the current session.
    """
    features = analysis.features or {}
    st.session_state["features"] = features
    st.session_state["__total_pkts"] = analysis.packet_count
    # Must match the dashboard fast path: top_n=10, weight="flows"
    # (see _precompute_dash_aggregates in app.main).
    st.session_state["dash_aggregates"] = compute_flow_aggregates(features.get("flows"), top_n=10, weight="flows")
    st.session_state["osint"] = analysis.osint or {}
    st.session_state["dns_analysis"] = analysis.dns_analysis
    st.session_state["tls_analysis"] = analysis.tls_analysis
    # Restore the evidence-backed mapping when available. Older cases without
    # the new column are handled by the dedicated page's lazy recomputation.
    st.session_state["attack_mapping"] = analysis.attack_mapping
    st.session_state["capture_metrics"] = analysis.capture_metrics
    session_artifacts = analysis.session_artifacts or {}
    st.session_state["pipeline_warnings"] = list(session_artifacts.get("pipeline_warnings") or [])
    st.session_state["pipeline_stages"] = list(session_artifacts.get("pipeline_stages") or [])
    st.session_state["yara_results"] = analysis.yara_results
    # Model default for report is "" but the app's no-report sentinel is None.
    st.session_state["report"] = analysis.report or None
    st.session_state["llm_status"] = "generated" if analysis.report else None
    # New durable background analyses persist the bounded UI evidence below.
    # Legacy cases have no session_artifacts column value and still take the
    # safe empty-state path instead of mixing in data from a previous capture.
    beacon_records = session_artifacts.get("beacon_records") or features.get("beacon_records") or []
    st.session_state["beacon_df"] = pd.DataFrame.from_records(beacon_records)
    st.session_state["ja3_df"] = pd.DataFrame()
    st.session_state["ja3_analysis"] = {}
    st.session_state["zeek_tables"] = {
        name: pd.DataFrame.from_records(records)
        for name, records in (session_artifacts.get("zeek_tables") or {}).items()
        if isinstance(records, list)
    }
    st.session_state["carved"] = list(session_artifacts.get("carved") or [])
    # None (not []) so empty-state rendering says "not available — re-run", rather
    # than a false "ran clean" for results that simply weren't persisted.
    st.session_state["correlations"] = None
    st.session_state["flow_asymmetry"] = None
    st.session_state["port_anomalies"] = None
    st.session_state["rdns_map"] = dict(session_artifacts.get("rdns_map") or {})
    st.session_state["__pcap_path"] = analysis.pcap_path
    st.session_state["__pcap_paths"] = [analysis.pcap_path] if analysis.pcap_path else []
    st.session_state["__batch_mode"] = False
    st.session_state["__batch_result"] = None
    st.session_state["filter_ips"] = set()
    st.session_state["filter_protos"] = set()
    st.session_state["filter_time"] = None
    st.session_state["restored_analysis_id"] = analysis.id
    st.session_state["restored_analysis_ids"] = [analysis.id]
    if session_artifacts:
        _restore_expensive_derived_state([analysis])
    logger.info("Restored analysis %s into session state", analysis.id)


def _analysis_to_pcap_result(analysis: Analysis) -> PCAPResult:
    """Convert a persisted analysis back to the production-shape batch result."""
    artifacts = analysis.session_artifacts or {}
    zeek_tables = {
        name: pd.DataFrame.from_records(records)
        for name, records in (artifacts.get("zeek_tables") or {}).items()
        if isinstance(records, list)
    }
    beacon_records = artifacts.get("beacon_records") or (analysis.features or {}).get("beacon_records") or []
    return PCAPResult(
        path=analysis.pcap_path,
        filename=analysis.pcap_path.rsplit("/", 1)[-1] or analysis.id,
        features=analysis.features or {},
        zeek_tables=zeek_tables,
        zeek_log_paths=dict(artifacts.get("zeek_log_paths") or {}),
        rdns_map=dict(artifacts.get("rdns_map") or {}),
        carved_items=list(artifacts.get("carved") or []),
        osint=analysis.osint or {},
        beacon_df=pd.DataFrame.from_records(beacon_records),
        dns_analysis=analysis.dns_analysis or {},
        tls_analysis=analysis.tls_analysis or {},
        packet_count=analysis.packet_count,
        duration_seconds=float(artifacts.get("duration_seconds") or 0),
        stages_run=list(artifacts.get("pipeline_stages") or []),
        warnings=list(artifacts.get("pipeline_warnings") or []),
    )


def _merge_yara_results(analyses: list[Analysis]) -> dict | None:
    per_file = []
    matches = []
    for analysis in analyses:
        if not analysis.yara_results:
            continue
        per_file.append({"pcap_path": analysis.pcap_path, "result": analysis.yara_results})
        if isinstance(analysis.yara_results, dict):
            matches.extend(analysis.yara_results.get("matches") or [])
    if not per_file:
        return None
    return {"matches": matches, "per_file": per_file}


def _current_session_artifacts() -> dict:
    """Capture the bounded evidence needed to reopen the current UI result."""
    zeek_tables = {}
    for name, table in (st.session_state.get("zeek_tables") or {}).items():
        if isinstance(table, pd.DataFrame):
            zeek_tables[name] = json.loads(table.to_json(orient="records", date_format="iso"))
    beacon_df = st.session_state.get("beacon_df")
    beacon_records = (
        json.loads(beacon_df.to_json(orient="records", date_format="iso"))
        if isinstance(beacon_df, pd.DataFrame)
        else []
    )
    return {
        "zeek_tables": zeek_tables,
        "zeek_log_paths": dict(st.session_state.get("zeek_log_paths") or {}),
        "carved": list(st.session_state.get("carved") or []),
        "beacon_records": beacon_records,
        "pipeline_warnings": list(st.session_state.get("pipeline_warnings") or []),
        "pipeline_stages": list(st.session_state.get("pipeline_stages") or []),
        "rdns_map": dict(st.session_state.get("rdns_map") or {}),
    }


def _restore_expensive_derived_state(analyses: list[Analysis]) -> None:
    """Rebuild inexpensive cross-links after durable evidence is restored."""
    features = st.session_state.get("features") or {}
    beacon_df = st.session_state.get("beacon_df")
    try:
        from app.analysis.correlation import correlate_indicators
        from app.analysis.flow_analysis import detect_flow_asymmetry, detect_port_anomalies

        st.session_state["correlations"] = correlate_indicators(
            features=features,
            osint=st.session_state.get("osint") or {},
            beacon_df=beacon_df if isinstance(beacon_df, pd.DataFrame) else pd.DataFrame(),
            dns_analysis=st.session_state.get("dns_analysis"),
            tls_analysis=st.session_state.get("tls_analysis"),
            yara_results=st.session_state.get("yara_results"),
        )
        flows = features.get("flows") or []
        if flows:
            st.session_state["flow_asymmetry"] = detect_flow_asymmetry(flows)
            st.session_state["port_anomalies"] = detect_port_anomalies(flows)
    except Exception as exc:
        logger.warning("Could not rebuild restored correlations: %s", exc)

    log_paths = [
        dict((analysis.session_artifacts or {}).get("zeek_log_paths") or {})
        for analysis in analyses
        if (analysis.session_artifacts or {}).get("zeek_log_paths")
    ]
    try:
        if len(log_paths) > 1:
            from app.pipeline.ja3 import extract_ja3_from_multiple_runs

            ja3_df, ja3_analysis = extract_ja3_from_multiple_runs(log_paths)
        elif log_paths:
            from app.pipeline.zeek import extract_ja3_from_zeek_tables

            ja3_df, ja3_analysis = extract_ja3_from_zeek_tables(log_paths[0])
        else:
            ja3_df, ja3_analysis = pd.DataFrame(), {}
        st.session_state["ja3_df"] = ja3_df
        st.session_state["ja3_analysis"] = ja3_analysis
    except Exception as exc:
        logger.warning("Could not rebuild restored JA3 state: %s", exc)


def restore_analyses_to_session(analyses: list[Analysis]) -> None:
    """Restore one or more completed background analyses into the workbench."""
    analyses = [analysis for analysis in analyses if analysis is not None]
    if not analyses:
        raise ValueError("No persisted analyses were available to restore.")
    if len(analyses) == 1:
        _restore_analysis_to_session(analyses[0])
        return

    processor = BatchProcessor([])
    for analysis in analyses:
        processor.add_result(_analysis_to_pcap_result(analysis))
    batch_result = processor.merge_all()

    artifact_values: dict[str, set] = {}
    all_flows: list[dict] = []
    for result in batch_result.pcap_results:
        all_flows.extend((result.features or {}).get("flows") or [])
        for key, values in ((result.features or {}).get("artifacts") or {}).items():
            if isinstance(values, list):
                artifact_values.setdefault(key, set()).update(values)

    st.session_state["features"] = {
        "flows": all_flows,
        "artifacts": {key: uniq_sorted(values) for key, values in artifact_values.items()},
    }
    st.session_state["dash_aggregates"] = compute_flow_aggregates(all_flows, top_n=10, weight="flows")
    st.session_state["zeek_tables"] = batch_result.merged_zeek
    st.session_state["osint"] = batch_result.merged_osint
    st.session_state["beacon_df"] = batch_result.merged_beacons
    st.session_state["dns_analysis"] = batch_result.aggregated_dns
    st.session_state["tls_analysis"] = batch_result.aggregated_tls
    st.session_state["yara_results"] = _merge_yara_results(analyses)
    st.session_state["carved"] = [item for result in batch_result.pcap_results for item in result.carved_items]
    st.session_state["__total_pkts"] = batch_result.correlation.total_packets
    st.session_state["pipeline_warnings"] = sorted(
        {warning for result in batch_result.pcap_results for warning in result.warnings}
    )
    st.session_state["pipeline_stages"] = sorted(
        {stage for result in batch_result.pcap_results for stage in result.stages_run}
    )
    st.session_state["rdns_map"] = {
        ip: hostname for result in batch_result.pcap_results for ip, hostname in result.rdns_map.items()
    }
    reports = [
        f"# {result.filename}\n\n{analysis.report}"
        for result, analysis in zip(batch_result.pcap_results, analyses)
        if analysis.report
    ]
    st.session_state["report"] = "\n\n---\n\n".join(reports) or None
    st.session_state["llm_status"] = "generated" if reports else None
    st.session_state["__pcap_path"] = analyses[0].pcap_path
    st.session_state["__pcap_paths"] = [analysis.pcap_path for analysis in analyses]
    st.session_state["__batch_mode"] = True
    st.session_state["__batch_result"] = batch_result
    st.session_state["filter_ips"] = set()
    st.session_state["filter_protos"] = set()
    st.session_state["filter_time"] = None

    _restore_expensive_derived_state(analyses)
    try:
        st.session_state["attack_mapping"] = build_attack_mapping(st.session_state)
        st.session_state["capture_metrics"] = build_capture_metrics(st.session_state)
    except Exception as exc:
        logger.warning("Could not rebuild restored ATT&CK state: %s", exc)
        st.session_state["attack_mapping"] = None
        st.session_state["capture_metrics"] = build_capture_metrics(st.session_state)
    st.session_state["restored_analysis_id"] = max(
        analyses, key=lambda analysis: analysis.analyzed_at or datetime.min
    ).id
    st.session_state["restored_analysis_ids"] = [analysis.id for analysis in analyses]


def render_cases_tab():
    """Main cases tab with list and detail views."""
    st.markdown("### Case Management")

    # Navigation
    if "cases_view" not in st.session_state:
        st.session_state["cases_view"] = "list"

    # View routing
    view = st.session_state["cases_view"]

    if view == "list":
        _render_case_list()
    elif view == "detail":
        case_id = st.session_state.get("selected_case_id")
        if case_id:
            _render_case_detail(case_id)
        else:
            st.session_state["cases_view"] = "list"
            st.rerun()
    elif view == "new":
        _render_case_form()
    elif view == "edit":
        case_id = st.session_state.get("selected_case_id")
        if case_id:
            _render_case_form(case_id)
        else:
            st.session_state["cases_view"] = "list"
            st.rerun()
    elif view == "ioc_search":
        _render_ioc_search()


def _render_case_list():
    """Case list with filters and search."""
    repo = _get_repo()

    # Action buttons
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        if st.button("New Case", type="primary"):
            st.session_state["cases_view"] = "new"
            st.rerun()
    with col2:
        if st.button("Search IOCs"):
            st.session_state["cases_view"] = "ioc_search"
            st.rerun()
    with col3:
        # Quick save current analysis
        if st.button("Save Current Analysis to New Case"):
            _quick_save_analysis()

    st.markdown("---")

    # Filters
    filter_col1, filter_col2, filter_col3 = st.columns([2, 1, 1])
    with filter_col1:
        search_term = st.text_input(
            "Search cases", placeholder="Search by title or description...", max_chars=MAX_SEARCH_LENGTH
        )
    with filter_col2:
        status_filter = st.selectbox("Status", ["All", "Open", "In Progress", "Closed"])
    with filter_col3:
        tags = repo.list_tags()
        tag_filter = st.multiselect("Tags", tags)

    # Convert status filter
    status = None
    if status_filter == "Open":
        status = CaseStatus.OPEN
    elif status_filter == "In Progress":
        status = CaseStatus.IN_PROGRESS
    elif status_filter == "Closed":
        status = CaseStatus.CLOSED

    # Get cases
    cases = repo.list_cases(
        status=status,
        tags=tag_filter if tag_filter else None,
        search=search_term if search_term else None,
    )

    # Display cases
    if not cases:
        st.info("No cases found. Create a new case to get started.")
        return

    # Statistics
    stats = repo.get_statistics()
    stat_cols = st.columns(4)
    with stat_cols[0]:
        st.metric("Total Cases", stats["total_cases"])
    with stat_cols[1]:
        st.metric("Total Analyses", stats["total_analyses"])
    with stat_cols[2]:
        st.metric("Total IOCs", stats["total_iocs"])
    with stat_cols[3]:
        open_count = stats.get("by_status", {}).get("open", 0)
        st.metric("Open Cases", open_count)

    st.markdown("---")

    # Case table
    rows = []
    for case in cases:
        rows.append(
            {
                "ID": case.id,
                "Title": case.title,
                "Status": case.status.value.title(),
                "Severity": case.severity.value.title(),
                "Analyses": len(case.analyses) if case.analyses else 0,
                "Tags": ", ".join(case.tags),
                "Updated": case.updated_at.strftime("%Y-%m-%d %H:%M") if case.updated_at else "",
            }
        )

    df = pd.DataFrame(rows)

    # Color-code by severity
    def highlight_severity(row):
        sev = row.get("Severity", "").lower()
        if sev in ("critical", "high"):
            return [f"background-color: {severity_color(sev, 'rgba')};"] * len(row)
        return [""] * len(row)

    styled_df = df.style.apply(highlight_severity, axis=1)

    # Selectable table
    event = st.dataframe(
        styled_df,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="cases_table",
    )

    # Handle selection
    if event.selection.rows:
        idx = event.selection.rows[0]
        selected_case_id = df.iloc[idx]["ID"]
        st.session_state["selected_case_id"] = selected_case_id
        st.session_state["cases_view"] = "detail"
        st.rerun()


def _render_case_detail(case_id: str):
    """Single case view with analyses, notes, IOCs."""
    repo = _get_repo()
    case = repo.get_case(case_id)

    if not case:
        st.error(f"Case not found: {case_id}")
        st.session_state["cases_view"] = "list"
        st.rerun()
        return

    # Restore the most recent analysis so the Dashboard/Results tabs show this
    # case. st.tabs renders every tab on each rerun, so the marker guard keeps
    # this a one-shot restore instead of clobbering session state repeatedly.
    # The rerun is needed because the Dashboard tab renders earlier in the
    # script pass and would otherwise show stale data until the next rerun.
    if case.analyses:
        latest = max(case.analyses, key=lambda a: a.analyzed_at or datetime.min)
        if st.session_state.get("restored_analysis_id") != latest.id:
            _restore_analysis_to_session(latest)
            st.rerun()

    # Back button
    if st.button("← Back to Cases"):
        st.session_state["cases_view"] = "list"
        st.rerun()

    # Header
    st.markdown(f"## {case.title}")

    # Status badge
    status_colors = {"open": "green", "in_progress": "orange", "closed": "red"}
    st.markdown(f"**Status:** :{status_colors.get(case.status.value, 'blue')}[{case.status.value.title()}]")

    # Metadata
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"**ID:** `{case.id}`")
    with col2:
        st.markdown(f"**Severity:** {case.severity.value.title()}")
    with col3:
        st.markdown(f"**Created:** {case.created_at.strftime('%Y-%m-%d')}")
    with col4:
        st.markdown(f"**Updated:** {case.updated_at.strftime('%Y-%m-%d %H:%M')}")

    # Tags
    if case.tags:
        st.markdown("**Tags:** " + " ".join([f"`{t}`" for t in case.tags]))

    # Description
    if case.description:
        with st.expander("Description", expanded=True):
            st.markdown(case.description)

    st.markdown("---")

    # Action buttons
    action_cols = st.columns(5)
    with action_cols[0]:
        if st.button("Edit Case"):
            st.session_state["cases_view"] = "edit"
            st.rerun()
    with action_cols[1]:
        if case.status != CaseStatus.CLOSED:
            if st.button("Close Case"):
                case.close()
                repo.update_case(case)
                st.success("Case closed.")
                st.rerun()
        else:
            if st.button("Reopen Case"):
                case.reopen()
                repo.update_case(case)
                st.success("Case reopened.")
                st.rerun()
    with action_cols[2]:
        if st.button("Add Current Analysis"):
            _add_current_analysis_to_case(case)
    with action_cols[3]:
        pass  # Reserved
    with action_cols[4]:
        if st.button("Delete Case", type="secondary"):
            if st.session_state.get("confirm_delete") == case_id:
                repo.delete_case(case_id)
                st.session_state["cases_view"] = "list"
                st.success("Case deleted.")
                st.rerun()
            else:
                st.session_state["confirm_delete"] = case_id
                st.warning("Click again to confirm deletion.")

    # Tabs for content
    tab_analyses, tab_notes, tab_iocs = st.tabs(["Analyses", "Notes", "IOCs"])

    with tab_analyses:
        _render_case_analyses(case, repo)

    with tab_notes:
        _render_case_notes(case, repo)

    with tab_iocs:
        _render_case_iocs(case)


def _render_case_analyses(case: Case, repo: CaseRepository):
    """Render analyses section."""
    if not case.analyses:
        st.info("No analyses linked to this case yet.")
        return

    for analysis in case.analyses:
        expander_title = f"Analysis: {analysis.id} ({analysis.analyzed_at.strftime('%Y-%m-%d %H:%M')})"
        with st.expander(expander_title, expanded=False):
            st.markdown(f"**PCAP:** `{analysis.pcap_path}`")
            st.markdown(f"**Hash:** `{analysis.pcap_hash}`")
            st.markdown(f"**Packets:** {analysis.packet_count}")

            if analysis.report:
                st.markdown("**Report Preview:**")
                st.markdown(analysis.report[:500] + "..." if len(analysis.report) > 500 else analysis.report)

            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**IOCs:** {len(analysis.iocs)}")
            with col2:
                st.markdown(f"**Flows:** {len(analysis.features.get('flows', []))}")

            if st.session_state.get("restored_analysis_id") == analysis.id:
                st.caption("Loaded — the Dashboard and Results tabs show this analysis.")
            elif st.button("Load into Dashboard", key=f"restore_{analysis.id}"):
                _restore_analysis_to_session(analysis)
                st.rerun()


def _render_case_notes(case: Case, repo: CaseRepository):
    """Render notes section."""
    # Add new note
    new_note = st.text_area("Add a note:", key="new_note_content")
    if st.button("Add Note") and new_note:
        if error := _validate_length(new_note, MAX_NOTE_LENGTH, "Note"):
            st.error(error)
        else:
            repo.add_note(case.id, new_note)
            st.success("Note added.")
            st.rerun()

    st.markdown("---")

    # Display existing notes
    if not case.notes:
        st.info("No notes yet.")
        return

    for note in case.notes:
        with st.container():
            st.markdown(f"**{note.created_at.strftime('%Y-%m-%d %H:%M')}**")
            st.markdown(note.content)
            if st.button("Delete", key=f"del_note_{note.id}"):
                repo.delete_note(note.id)
                st.rerun()
            st.markdown("---")


def _render_case_iocs(case: Case):
    """Render IOCs section."""
    all_iocs = []
    for analysis in case.analyses:
        for ioc in analysis.iocs:
            all_iocs.append(
                {
                    "Type": ioc.ioc_type.value.upper(),
                    "Value": ioc.value,
                    "Context": ioc.context,
                    "Severity": ioc.severity.value.title(),
                    "Analysis": analysis.id,
                }
            )

    if not all_iocs:
        st.info("No IOCs extracted from analyses.")
        return

    df = pd.DataFrame(all_iocs)

    # Export button
    csv = df.to_csv(index=False)
    st.download_button("Export IOCs (CSV)", csv, file_name=f"case_{case.id}_iocs.csv", mime="text/csv")

    st.dataframe(df, hide_index=True)


def _render_case_form(case_id: str | None = None):
    """Create/edit case form."""
    repo = _get_repo()

    existing_case = None
    if case_id:
        existing_case = repo.get_case(case_id)
        if not existing_case:
            st.error("Case not found.")
            st.session_state["cases_view"] = "list"
            st.rerun()
            return

    st.markdown("## " + ("Edit Case" if existing_case else "New Case"))

    # Back button
    if st.button("← Cancel"):
        st.session_state["cases_view"] = "list" if not existing_case else "detail"
        st.rerun()

    # Form
    title = st.text_input("Title", value=existing_case.title if existing_case else "")
    description = st.text_area("Description", value=existing_case.description if existing_case else "")

    col1, col2 = st.columns(2)
    with col1:
        status_options = ["Open", "In Progress", "Closed"]
        current_status = existing_case.status.value.replace("_", " ").title() if existing_case else "Open"
        status_idx = status_options.index(current_status) if current_status in status_options else 0
        status = st.selectbox("Status", status_options, index=status_idx)

    with col2:
        severity_options = ["Low", "Medium", "High", "Critical"]
        current_severity = existing_case.severity.value.title() if existing_case else "Medium"
        sev_idx = severity_options.index(current_severity) if current_severity in severity_options else 1
        severity = st.selectbox("Severity", severity_options, index=sev_idx)

    # Tags
    existing_tags = repo.list_tags()
    current_tags = existing_case.tags if existing_case else []
    tags = st.multiselect("Tags", existing_tags + [""], default=current_tags)

    # New tag
    new_tag = st.text_input("Add new tag")
    if new_tag and new_tag not in tags:
        tags.append(new_tag)

    # Save
    if st.button("Save", type="primary"):
        # Validate inputs
        errors = []

        # Strip whitespace for validation
        title = title.strip() if title else ""

        if not title:
            errors.append("Title is required.")
        elif error := _validate_length(title, MAX_TITLE_LENGTH, "Title"):
            errors.append(error)

        # Strip description
        description = description.strip() if description else ""

        if description and (error := _validate_length(description, MAX_DESCRIPTION_LENGTH, "Description")):
            errors.append(error)

        # Validate and clean tags (strip whitespace, remove empty)
        tags = [t.strip() for t in tags if t and t.strip()]
        for tag in tags:
            if error := _validate_length(tag, MAX_TAG_LENGTH, f"Tag '{tag}'"):
                errors.append(error)

        if errors:
            for error in errors:
                st.error(error)
        else:
            if existing_case:
                existing_case.title = title
                existing_case.description = description
                existing_case.status = CaseStatus(status.lower().replace(" ", "_"))
                existing_case.severity = Severity(severity.lower())
                existing_case.tags = tags
                repo.update_case(existing_case)
                st.success("Case updated.")
            else:
                new_case = Case(
                    title=title,
                    description=description,
                    status=CaseStatus(status.lower().replace(" ", "_")),
                    severity=Severity(severity.lower()),
                    tags=tags,
                )
                case_id = repo.create_case(new_case)
                st.session_state["selected_case_id"] = case_id
                st.success(f"Case created: {case_id}")

            st.session_state["cases_view"] = "detail" if existing_case else "list"
            st.rerun()


def _render_ioc_search():
    """Cross-case IOC search."""
    repo = _get_repo()

    st.markdown("### IOC Search")

    # Back button
    if st.button("← Back to Cases"):
        st.session_state["cases_view"] = "list"
        st.rerun()

    col1, col2 = st.columns([3, 1])
    with col1:
        search_value = st.text_input(
            "Search IOC value", placeholder="IP, domain, hash, JA3...", max_chars=MAX_SEARCH_LENGTH
        )
    with col2:
        ioc_types = ["All", "IP", "Domain", "Hash", "JA3", "URL"]
        ioc_type_filter = st.selectbox("Type", ioc_types)

    if search_value:
        ioc_type = None
        if ioc_type_filter != "All":
            ioc_type = IOCType.from_str(ioc_type_filter.lower())

        results = repo.search_iocs(search_value, ioc_type)

        if not results:
            st.info("No IOCs found matching your search.")
        else:
            st.success(f"Found {len(results)} matching IOCs")

            rows = []
            for ioc, case in results:
                rows.append(
                    {
                        "Value": ioc.value,
                        "Type": ioc.ioc_type.value.upper(),
                        "Context": ioc.context,
                        "Case": case.title,
                        "Case ID": case.id,
                    }
                )

            df = pd.DataFrame(rows)
            st.dataframe(df, hide_index=True)


def _quick_save_analysis():
    """Quick save current analysis to a new case."""
    features = st.session_state.get("features")
    if not features:
        st.warning("No analysis data available. Run analysis first.")
        return

    repo = _get_repo()
    attack_mapping = st.session_state.get("attack_mapping")
    if hasattr(attack_mapping, "to_dict"):
        attack_mapping = attack_mapping.to_dict()

    # Create case
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    case = Case(
        title=f"Analysis_{timestamp}",
        description="Auto-created from current analysis.",
    )
    case_id = repo.create_case(case)

    # Create analysis
    analysis = Analysis(
        case_id=case_id,
        pcap_path=st.session_state.get("__pcap_path", ""),
        packet_count=st.session_state.get("__total_pkts", 0),
        features=features,
        osint=st.session_state.get("osint") or {},
        report=st.session_state.get("report") or "",
        yara_results=st.session_state.get("yara_results"),
        dns_analysis=st.session_state.get("dns_analysis"),
        tls_analysis=st.session_state.get("tls_analysis"),
        attack_mapping=attack_mapping,
        capture_metrics=st.session_state.get("capture_metrics"),
        session_artifacts=_current_session_artifacts(),
    )

    # Extract IOCs
    analysis.iocs = repo.extract_iocs(analysis)
    repo.save_analysis(analysis)
    # the live session already holds this analysis — block the auto-restore from wiping non-persisted results
    st.session_state["restored_analysis_id"] = analysis.id

    st.success(f"Created case {case_id} with analysis.")
    st.session_state["selected_case_id"] = case_id
    st.session_state["cases_view"] = "detail"
    st.rerun()


def _add_current_analysis_to_case(case: Case):
    """Add current analysis to existing case."""
    features = st.session_state.get("features")
    if not features:
        st.warning("No analysis data available.")
        return

    repo = _get_repo()
    attack_mapping = st.session_state.get("attack_mapping")
    if hasattr(attack_mapping, "to_dict"):
        attack_mapping = attack_mapping.to_dict()

    analysis = Analysis(
        case_id=case.id,
        pcap_path=st.session_state.get("__pcap_path", ""),
        packet_count=st.session_state.get("__total_pkts", 0),
        features=features,
        osint=st.session_state.get("osint") or {},
        report=st.session_state.get("report") or "",
        yara_results=st.session_state.get("yara_results"),
        dns_analysis=st.session_state.get("dns_analysis"),
        tls_analysis=st.session_state.get("tls_analysis"),
        attack_mapping=attack_mapping,
        capture_metrics=st.session_state.get("capture_metrics"),
        session_artifacts=_current_session_artifacts(),
    )

    analysis.iocs = repo.extract_iocs(analysis)
    repo.save_analysis(analysis)
    # the live session already holds this analysis — block the auto-restore from wiping non-persisted results
    st.session_state["restored_analysis_id"] = analysis.id

    st.success(f"Added analysis to case {case.id}")
    st.rerun()
