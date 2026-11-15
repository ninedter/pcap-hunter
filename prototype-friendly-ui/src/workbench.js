import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { isPrivacyMode, sanitizeWorkbenchPayload } from "./privacy.js";
import { collectEvidencePages } from "./evidenceExport.js";
import { parseSettingsSaveResult } from "./settingsFeedback.js";

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
  evidence_total: 0,
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
    const error = new Error(message);
    // Callers that can show structured feedback (settings validation) read these.
    error.status = response.status;
    error.payload = payload;
    throw error;
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

/**
 * Orders overlapping bootstrap requests. Each request takes a generation when
 * it starts; only the newest generation may apply its response, so a slow
 * poll can never overwrite the result of a later explicit refresh.
 */
export function createRequestGate({ now = () => Date.now() } = {}) {
  let generation = 0;
  let inFlight = 0;
  let lastStartedAt = 0;
  return {
    begin() {
      generation += 1;
      inFlight += 1;
      lastStartedAt = now();
      return generation;
    },
    end() {
      inFlight = Math.max(0, inFlight - 1);
    },
    isCurrent(requestGeneration) {
      return requestGeneration === generation;
    },
    /** Generation of the newest request started so far (0 before the first). */
    current() {
      return generation;
    },
    /** True while a request is pending, unless the newest one has been pending longer than maxAgeMs. */
    isBusy(maxAgeMs = Infinity) {
      return inFlight > 0 && now() - lastStartedAt < maxAgeMs;
    },
  };
}

export const BOOTSTRAP_POLL_INTERVAL_MS = 1600;
// A poll tick waits for the pending request unless it has been stuck this long.
export const BOOTSTRAP_POLL_STALL_MS = 20000;
// With no active job, the job list is still checked at this cadence (visible
// tabs only) so runs submitted through the API or MCP appear without a refresh.
export const IDLE_JOBS_POLL_INTERVAL_MS = 15000;

const TERMINAL_JOB_STATUSES = new Set(["done", "failed", "cancelled"]);

export function isTerminalJobStatus(status) {
  return TERMINAL_JOB_STATUSES.has(status);
}

/**
 * Decide whether a job-list poll requires the full bootstrap payload.
 *
 * Progress ticks only change the jobs themselves. The dashboard, cases, and
 * counts change when a job reaches a terminal state, or when jobs appear or
 * disappear (a submission elsewhere, a deleted case).
 *
 * @param {Array<{id: string, status: string}>} previousJobs - jobs currently applied.
 * @param {Array<{id: string, status: string}>} nextJobs - jobs from the poll.
 * @returns {boolean} true when the bootstrap must be refetched.
 */
export function jobsNeedBootstrapRefresh(previousJobs, nextJobs) {
  const previous = new Map((Array.isArray(previousJobs) ? previousJobs : []).map((job) => [String(job?.id), job?.status]));
  const next = Array.isArray(nextJobs) ? nextJobs : [];
  const nextIds = new Set(next.map((job) => String(job?.id)));
  if (nextIds.size !== previous.size) return true;
  return next.some((job) => {
    const id = String(job?.id);
    if (!previous.has(id)) return true;
    return isTerminalJobStatus(job?.status) && previous.get(id) !== job.status;
  });
}

/**
 * What a poll tick should do: "skip" | "bootstrap" | "jobs".
 *
 * @param {object} input
 * @param {boolean} input.bootstrapBusy - a bootstrap request is pending and not yet stalled.
 * @param {boolean} input.bootstrapPending - a bootstrap request is pending at all.
 * @param {boolean} input.jobsBusy - a job-list request is pending and not yet stalled.
 * @param {boolean} input.jobsEndpointMissing - the server answered 404 for /api/ui/jobs.
 * @param {boolean} [input.idle] - no job is active (slow cadence).
 * @param {boolean} [input.visible] - the document is visible.
 * @param {boolean} [input.loaded] - a bootstrap response has been applied.
 */
export function planJobsPollTick({ bootstrapBusy, bootstrapPending, jobsBusy, jobsEndpointMissing, idle = false, visible = true, loaded = true }) {
  if (idle && (!visible || !loaded || jobsEndpointMissing)) return "skip";
  // Skip while a request is still pending so slow responses cannot stack.
  if (bootstrapBusy || jobsBusy) return "skip";
  // Older server, or a bootstrap stuck past the stall window: full refresh, as before.
  if (jobsEndpointMissing || bootstrapPending) return idle ? "skip" : "bootstrap";
  return "jobs";
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
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const requestGate = useRef(null);
  if (!requestGate.current) requestGate.current = createRequestGate();
  const jobsGate = useRef(null);
  if (!jobsGate.current) jobsGate.current = createRequestGate();
  const jobsEndpointMissing = useRef(false);
  const jobsPollFailed = useRef(false);

  // Resolves to the applied payload, or null when the request failed or was
  // superseded by a newer refresh (its response is then discarded).
  const refresh = useCallback(async () => {
    const gate = requestGate.current;
    const generation = gate.begin();
    try {
      const selected = new URLSearchParams(window.location.search).get("analysis_id");
      const url = selected ? `/api/ui/bootstrap?analysis_id=${encodeURIComponent(selected)}` : "/api/ui/bootstrap";
      const payload = await responseJson(await fetch(url, { cache: "no-store" }));
      if (!gate.isCurrent(generation)) return null;
      resourceScope.current = payload;
      const visiblePayload = privacyMode ? sanitizeWorkbenchPayload(payload) : payload;
      setState({ ...emptyState, ...visiblePayload, dashboard: { ...emptyDashboard, ...(visiblePayload.dashboard || {}) } });
      setError("");
      jobsPollFailed.current = false;
      setLoaded(true);
      return payload;
    } catch (requestError) {
      if (gate.isCurrent(generation)) setError(requestError.message);
      return null;
    } finally {
      gate.end();
      if (gate.isCurrent(generation)) setLoading(false);
    }
  }, [privacyMode]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const hasActiveJobs = useMemo(
    () => state.jobs.some((job) => job.status === "queued" || job.status === "running"),
    [state.jobs],
  );

  // Fetches only the job list. Progress updates touch just `jobs` in state; the
  // full bootstrap is refetched when a job finishes or the set of jobs changes.
  const pollJobs = useCallback(async ({ idle = false } = {}) => {
    const gate = requestGate.current;
    const plan = planJobsPollTick({
      bootstrapBusy: gate.isBusy(BOOTSTRAP_POLL_STALL_MS),
      bootstrapPending: gate.isBusy(),
      jobsBusy: jobsGate.current.isBusy(BOOTSTRAP_POLL_STALL_MS),
      jobsEndpointMissing: jobsEndpointMissing.current,
      idle,
      visible: typeof document === "undefined" || document.visibilityState === "visible",
      loaded: Boolean(resourceScope.current.jobs),
    });
    if (plan === "skip") return;
    if (plan === "bootstrap") { await refresh(); return; }

    const bootstrapGeneration = gate.current();
    const generation = jobsGate.current.begin();
    let needsBootstrap = false;
    try {
      const response = await fetch("/api/ui/jobs", { cache: "no-store" });
      if (response.status === 404) {
        // Older server without the job-list endpoint: keep polling the bootstrap.
        jobsEndpointMissing.current = true;
        needsBootstrap = !idle;
        return;
      }
      const payload = await responseJson(response);
      // Discard when a newer job poll or any bootstrap request started meanwhile.
      if (!jobsGate.current.isCurrent(generation) || gate.current() !== bootstrapGeneration) return;
      const nextJobs = Array.isArray(payload.jobs) ? payload.jobs : [];
      if (jobsPollFailed.current) { jobsPollFailed.current = false; setError(""); }
      if (jobsNeedBootstrapRefresh(resourceScope.current.jobs, nextJobs)) {
        // Leave the applied jobs untouched so a failed refresh is retried next tick.
        needsBootstrap = true;
        return;
      }
      resourceScope.current = { ...resourceScope.current, jobs: nextJobs };
      const visibleJobs = privacyMode ? sanitizeWorkbenchPayload({ jobs: nextJobs }).jobs : nextJobs;
      setState((current) => ({ ...current, jobs: visibleJobs }));
    } catch (requestError) {
      // A background check with nothing running stays quiet; an active run must not look alive when it is not.
      if (!idle && jobsGate.current.isCurrent(generation) && gate.current() === bootstrapGeneration) {
        jobsPollFailed.current = true;
        setError(requestError.message);
      }
    } finally {
      jobsGate.current.end();
      if (needsBootstrap) await refresh();
    }
  }, [privacyMode, refresh]);

  useEffect(() => {
    if (!hasActiveJobs) return undefined;
    const timer = window.setInterval(() => { pollJobs(); }, BOOTSTRAP_POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [hasActiveJobs, pollJobs]);

  useEffect(() => {
    if (hasActiveJobs || !loaded) return undefined;
    const check = () => { pollJobs({ idle: true }); };
    const onVisibility = () => { if (document.visibilityState === "visible") check(); };
    const timer = window.setInterval(check, IDLE_JOBS_POLL_INTERVAL_MS);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [hasActiveJobs, loaded, pollJobs]);

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

  // Resolves to { notice, clearedKeys }. A 422 rejects with an error carrying
  // `payload.errors`; see mapSettingsErrors in settingsFeedback.js.
  const saveSettings = useCallback(async (settings) => {
    const payload = await responseJson(
      await fetch("/api/ui/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      }),
    );
    await refresh();
    return parseSettingsSaveResult(payload);
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
    loaded,
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
