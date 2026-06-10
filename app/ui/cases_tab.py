"""Case Management UI Tab for PCAP Hunter."""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import streamlit as st

from app.database import Analysis, Case, CaseRepository, CaseStatus, IOCType, Severity
from app.ui.colors import severity_color
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
    )

    # Extract IOCs
    analysis.iocs = repo.extract_iocs(analysis)
    repo.save_analysis(analysis)

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
    )

    analysis.iocs = repo.extract_iocs(analysis)
    repo.save_analysis(analysis)

    st.success(f"Added analysis to case {case.id}")
    st.rerun()
