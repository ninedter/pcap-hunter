import { useCallback, useEffect, useMemo, useState } from "react";

import { isPrivacyMode, sanitizeWorkbenchPayload } from "./privacy.js";

const emptyDashboard = {
  risk: "N/A",
  packets: 0,
  flows: 0,
  alerts: 0,
  beacons: 0,
  yara_issues: 0,
  cert_issues: 0,
  protocols: [],
  traffic: [],
  top_talkers: [],
  top_ips: [],
  top_domains: [],
  map_flows: [],
  evidence: [],
  packet_sizes: [],
  inter_arrivals: [],
  heatmap: [],
  sankey: { nodes: [], links: [] },
  network: [],
  attack_timeline: [],
  report: "",
  stages: [],
  warnings: [],
  raw_flows: [],
  attack_mapping: {},
  osint_rows: [],
  dns_analysis: {},
  tls_analysis: {},
  yara_results: {},
  home: { lat: 0, lon: 0, city: "Home", country: "", continent: "" },
};

const emptyState = {
  capture_count: 0,
  analysis_complete: false,
  active_case_id: null,
  active_case_title: null,
  active_analysis_id: null,
  dashboard: emptyDashboard,
  cases: [],
  jobs: [],
  config: {},
  system: { healthy: false, tools: [] },
};

async function responseJson(response) {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof payload.detail === "string" ? payload.detail : "The workbench could not complete that request.";
    throw new Error(message);
  }
  return payload;
}

export function useWorkbench() {
  const privacyMode = isPrivacyMode(typeof window === "undefined" ? "" : window.location.search);
  const [state, setState] = useState(emptyState);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const payload = await responseJson(await fetch("/api/ui/bootstrap", { cache: "no-store" }));
      const visiblePayload = privacyMode ? sanitizeWorkbenchPayload(payload) : payload;
      setState({ ...emptyState, ...visiblePayload, dashboard: { ...emptyDashboard, ...(visiblePayload.dashboard || {}) } });
      setError("");
      return payload;
    } catch (requestError) {
      setError(requestError.message);
      return null;
    } finally {
      setLoading(false);
    }
  }, [privacyMode]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const hasActiveJobs = useMemo(
    () => state.jobs.some((job) => job.status === "queued" || job.status === "running"),
    [state.jobs],
  );

  useEffect(() => {
    if (!hasActiveJobs) return undefined;
    const timer = window.setInterval(refresh, 1600);
    return () => window.clearInterval(timer);
  }, [hasActiveJobs, refresh]);

  const submitCaptures = useCallback(async (files, includeLlm) => {
    if (!files.length) throw new Error("Add at least one PCAP or PCAPNG file first.");
    const body = new FormData();
    files.forEach((file) => body.append("files", file));
    const payload = await responseJson(
      await fetch(`/api/ui/uploads?include_llm=${includeLlm ? "true" : "false"}`, { method: "POST", body }),
    );
    await refresh();
    return payload;
  }, [refresh]);

  const submitPaths = useCallback(async (paths, includeLlm) => {
    if (!paths.length) throw new Error("Add at least one allowed capture path first.");
    const payload = await responseJson(
      await fetch("/api/ui/paths", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ paths, include_llm: includeLlm }),
      }),
    );
    await refresh();
    return payload;
  }, [refresh]);

  const saveSettings = useCallback(async (settings) => {
    await responseJson(
      await fetch("/api/ui/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      }),
    );
    await refresh();
  }, [refresh]);

  const getGeoItems = useCallback(async (resource, params = {}) => {
    const query = new URLSearchParams(params);
    const suffix = query.size ? `?${query.toString()}` : "";
    const payload = await responseJson(await fetch(`/api/ui/geo/${resource}${suffix}`, { cache: "no-store" }));
    return payload.items || [];
  }, []);

  const resolveGeoLocation = useCallback(async (country, city) => {
    const query = new URLSearchParams({ country, city });
    return responseJson(await fetch(`/api/ui/geo/location?${query.toString()}`, { cache: "no-store" }));
  }, []);

  const lookupWhois = useCallback(async (target) => {
    const query = new URLSearchParams({ target });
    return responseJson(await fetch(`/api/ui/whois?${query.toString()}`, { cache: "no-store" }));
  }, []);

  const addNote = useCallback(async (caseId, content) => {
    await responseJson(
      await fetch(`/api/ui/cases/${caseId}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content }),
      }),
    );
    await refresh();
  }, [refresh]);

  const createCase = useCallback(async (title = "Untitled investigation") => {
    const payload = await responseJson(
      await fetch("/api/ui/cases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, severity: "low" }),
      }),
    );
    await refresh();
    return payload;
  }, [refresh]);

  return {
    ...state,
    loading,
    error,
    refresh,
    submitCaptures,
    submitPaths,
    saveSettings,
    getGeoItems,
    resolveGeoLocation,
    lookupWhois,
    addNote,
    createCase,
  };
}
