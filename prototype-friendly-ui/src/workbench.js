import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { isPrivacyMode, sanitizeWorkbenchPayload } from "./privacy.js";
import { collectEvidencePages } from "./evidenceExport.js";

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
  capture_summary: {
    packet_count: 0,
    flow_count: 0,
    endpoint_count: 0,
    parsed_traffic_bytes: 0,
    parsed_packet_count: 0,
    capture_file_bytes: 0,
    first_seen: null,
    last_seen: null,
    duration_seconds: 0,
    byte_coverage: "unknown",
  },
  protocol_distribution: [],
  endpoint_ranking: [],
  traffic_replay: {
    events: [],
    sampled_event_count: 0,
    returned_event_count: 0,
    max_events: 0,
    truncated: false,
    sampled_flow_count: 0,
    total_flow_count: 0,
    represented_packet_count: 0,
    total_packet_count: 0,
    first_seen: null,
    last_seen: null,
    coverage: "unavailable",
  },
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

export function buildLlmModelDiscoveryRequest({ provider, baseUrl, apiKey }) {
  const payload = { provider };
  const trimmedBaseUrl = String(baseUrl || "").trim();
  const trimmedApiKey = String(apiKey || "").trim();
  if (trimmedBaseUrl) payload.base_url = trimmedBaseUrl;
  if (trimmedApiKey) payload.api_key = trimmedApiKey;
  return payload;
}

export function normalizeDiscoveredLlmModels(payload) {
  const models = Array.isArray(payload?.models) ? payload.models : [];
  return [...new Set(models.map((model) => String(model || "").trim()).filter(Boolean))];
}

export function nextLlmDiscoveryGeneration(currentGeneration) {
  return Number(currentGeneration || 0) + 1;
}

export function acceptsLlmDiscoveryResponse(requestGeneration, currentGeneration) {
  return requestGeneration === currentGeneration;
}

export function getLlmModelPickerState({ models = [], selectedModel = "", customModelMode = false }) {
  const modelIsDiscovered = models.includes(selectedModel);
  const showCustomInput = Boolean(customModelMode) || (!modelIsDiscovered && Boolean(selectedModel));
  return {
    modelIsDiscovered,
    pickerValue: modelIsDiscovered && !customModelMode ? selectedModel : showCustomInput ? "__custom__" : "",
    showCustomInput,
  };
}

export function shouldSyncSettingsDraft(dirty) {
  return !dirty;
}

export function getLlmConnectionSignature(config = {}) {
  const provider = config.cfg_llm_provider || "lmstudio";
  const endpointKey = provider === "openai" ? "cfg_openai_base_url" : "cfg_llm_endpoint";
  return `${provider}\u0000${String(config[endpointKey] || "").trim()}`;
}

export function shouldResetLlmDiscoveryForConfigSync(previousSignature, nextSignature) {
  return Boolean(previousSignature) && previousSignature !== nextSignature;
}

export function useWorkbench() {
  const privacyMode = isPrivacyMode(typeof window === "undefined" ? "" : window.location.search);
  const [state, setState] = useState(emptyState);
  const resourceScope = useRef({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const selected = new URLSearchParams(window.location.search).get("analysis_id");
      const url = selected ? `/api/ui/bootstrap?analysis_id=${encodeURIComponent(selected)}` : "/api/ui/bootstrap";
      const payload = await responseJson(await fetch(url, { cache: "no-store" }));
      resourceScope.current = payload;
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

  const discoverLlmModels = useCallback(async ({ provider, baseUrl, apiKey }) => {
    const payload = await responseJson(
      await fetch("/api/ui/llm/models", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildLlmModelDiscoveryRequest({ provider, baseUrl, apiKey })),
      }),
    );
    return normalizeDiscoveredLlmModels(payload);
  }, []);

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

  const exportEvidence = useCallback(async () => {
    const id = resourceScope.current.active_analysis_id;
    if (!id) throw new Error("Select a saved analysis first.");
    const collect = (kind, snapshotId) => collectEvidencePages(async ({ cursor, snapshotId: snapshot }) => {
      const params = new URLSearchParams({ kind, limit: "200" });
      if (cursor) params.set("cursor", cursor);
      if (snapshot) params.set("snapshot_id", snapshot);
      return responseJson(await fetch(`/api/ui/analyses/${encodeURIComponent(id)}/evidence?${params}`, { cache: "no-store" }));
    }, { snapshotId });
    const evidence = await collect("evidence");
    const flows = await collect("flows", evidence.snapshot_id);
    const payload = { ...evidence, raw_flows: flows.items, flow_count: flows.total_matching };
    return privacyMode ? sanitizeWorkbenchPayload(payload) : payload;
  }, [privacyMode]);

  const selectAnalysis = useCallback(async (id) => {
    const url = new URL(window.location.href);
    if (id) url.searchParams.set("analysis_id", id); else url.searchParams.delete("analysis_id");
    url.searchParams.delete("evidence_id"); url.searchParams.delete("snapshot_id");
    window.history.replaceState(window.history.state, "", url);
    return refresh();
  }, [refresh]);
  const analysisChoices = (resourceScope.current.cases || []).flatMap((item, caseIndex) =>
    (item.analyses || []).map((analysis, index) => ({ id: analysis.id,
      label: privacyMode ? `Case ${caseIndex + 1} · Capture ${index + 1}` : `${item.title} · ${analysis.name}` })));

  return {
    ...state,
    analysisChoices,
    activeResourceId: () => resourceScope.current.active_analysis_id,
    selectAnalysis,
    exportEvidence,
    loading,
    error,
    refresh,
    submitCaptures,
    submitPaths,
    saveSettings,
    discoverLlmModels,
    getGeoItems,
    resolveGeoLocation,
    lookupWhois,
    addNote,
    createCase,
  };
}
