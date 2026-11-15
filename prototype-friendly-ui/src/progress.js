export const PIPELINE_STAGES = [
  "Packet counting",
  "Packet parsing",
  "Zeek processing",
  "DNS analysis",
  "TLS certificates",
  "Beaconing",
  "HTTP carving",
  "YARA scanning",
  "OSINT enrichment",
  "LLM report",
];

/**
 * Recorded stage key for each display label, in PIPELINE_STAGES order. The
 * runner records these keys in `stages_run`; a `<key>_skipped` entry means the
 * stage was reached but could not run. The LLM report is opt-in, so its
 * absence is not a visibility gap.
 */
export const PIPELINE_STAGE_KEYS = {
  "Packet counting": "pcap_count",
  "Packet parsing": "pyshark_pass",
  "Zeek processing": "zeek",
  "DNS analysis": "dns_analysis",
  "TLS certificates": "tls_certs",
  "Beaconing": "beacon",
  "HTTP carving": "carve",
  "YARA scanning": "yara_scan",
  "OSINT enrichment": "osint",
  "LLM report": "llm",
};

const OPTIONAL_STAGE_KEYS = new Set(["llm"]);

export const STAGE_COVERAGE_LABELS = {
  available: "Available",
  skipped: "Skipped",
  missing: "Not recorded",
  optional: "Not run · optional",
};

/**
 * Per-stage coverage from the recorded stage keys.
 *
 * @param {string[]} stages - `dashboard.stages` (recorded stage keys).
 * @returns {Array<{label: string, key: string, status: "available"|"skipped"|"missing"|"optional", gap: boolean}>}
 */
export function buildStageCoverage(stages) {
  const recorded = new Set((Array.isArray(stages) ? stages : []).map((stage) => String(stage || "").trim().toLowerCase()));
  return PIPELINE_STAGES.map((label) => {
    const key = PIPELINE_STAGE_KEYS[label];
    let status = "missing";
    if (recorded.has(key)) status = "available";
    else if (recorded.has(`${key}_skipped`)) status = "skipped";
    else if (OPTIONAL_STAGE_KEYS.has(key)) status = "optional";
    return { label, key, status, gap: status === "skipped" || status === "missing" };
  });
}

/** Counts for the coverage metrics: stages that ran, and detector stages with no result. */
export function summarizeStageCoverage(stages) {
  const coverage = buildStageCoverage(stages);
  return {
    total: coverage.length,
    available: coverage.filter((item) => item.status === "available").length,
    gaps: coverage.filter((item) => item.gap).length,
  };
}

const STAGE_PATTERNS = [
  /packet count/i,
  /parsing packets|packet parsing|pyshark/i,
  /zeek/i,
  /dns/i,
  /tls|certificate/i,
  /beacon/i,
  /http|carv/i,
  /yara/i,
  /osint/i,
  /llm|threat narrative|report/i,
];

const clampPercent = (value) => Math.max(0, Math.min(Number(value) || 0, 100));

export function pipelineStageIndex(title) {
  const normalized = String(title || "").trim();
  return normalized ? STAGE_PATTERNS.findIndex((pattern) => pattern.test(normalized)) : -1;
}

export function normalizeJobProgress(job) {
  const totalStages = Math.max(Number(job.total_stages) || PIPELINE_STAGES.length, 1);
  if (job.status === "done") {
    return {
      activeStageIndex: -1,
      completedStages: totalStages,
      displayStage: "Complete",
      overallProgress: 100,
      stageProgress: 100,
    };
  }

  const activeStageIndex = pipelineStageIndex(job.stage);
  const stopped = job.status === "failed" || job.status === "cancelled";
  const recordedCompleted = Math.max(Number(job.completed_stages) || 0, 0);
  const completedStages = Math.min(
    Math.max(recordedCompleted, activeStageIndex >= 0 ? activeStageIndex : 0),
    totalStages,
  );
  const stageProgress = job.status === "running" ? clampPercent(job.stage_progress) : 0;
  const fractionalCompleted = completedStages + (job.status === "running" ? stageProgress / 100 : 0);
  const overallProgress = Math.floor(Math.min(fractionalCompleted / totalStages, 1) * 100);

  return {
    activeStageIndex,
    completedStages,
    displayStage: stopped
      ? `${job.status === "failed" ? "Failed" : "Cancelled"}${activeStageIndex >= 0 ? ` during ${PIPELINE_STAGES[activeStageIndex]}` : ""}`
      : activeStageIndex >= 0 ? PIPELINE_STAGES[activeStageIndex] : job.stage || job.status,
    overallProgress,
    stageProgress,
  };
}

const ACTIVE_STATUSES = new Set(["queued", "running"]);

export function isActiveJob(job) {
  return ACTIVE_STATUSES.has(job?.status);
}

/** Text shown on a failed or cancelled run-queue row; empty for other states. */
export function jobOutcomeMessage(job) {
  const detail = String(job?.error || "").trim();
  if (job?.status === "failed") return detail || "The analysis failed and the worker did not record a reason.";
  if (job?.status === "cancelled") return detail || "The analysis was cancelled before it finished.";
  return "";
}

/**
 * Batch-level run-queue state.
 * state: empty | running | complete | failed | cancelled | partial
 */
export function summarizeRunQueue(jobs = []) {
  const counts = { total: jobs.length, active: 0, done: 0, failed: 0, cancelled: 0 };
  for (const job of jobs) {
    if (isActiveJob(job)) counts.active += 1;
    else if (job.status === "done") counts.done += 1;
    else if (job.status === "failed") counts.failed += 1;
    else if (job.status === "cancelled") counts.cancelled += 1;
  }
  const captures = (value) => `${value} ${value === 1 ? "capture" : "captures"}`;
  const stopped = counts.failed + counts.cancelled;
  const stoppedCopy = [counts.failed && `${counts.failed} failed`, counts.cancelled && `${counts.cancelled} cancelled`].filter(Boolean).join(" and ");

  if (!counts.total) return { state: "empty", counts, label: "Ready", caption: "No active analysis is running." };
  if (counts.active) {
    return {
      state: "running",
      counts,
      label: "Running safely in background",
      caption: `You can leave this page. The worker and autosave continue independently.${stopped ? ` ${stoppedCopy} so far.` : ""}`,
    };
  }
  if (counts.done === counts.total) {
    return { state: "complete", counts, label: "Complete", caption: "All evidence is ready across Findings, Investigate, Reports, and Cases." };
  }
  if (counts.done) {
    return {
      state: "partial",
      counts,
      label: "Finished with problems",
      caption: `${counts.done} of ${captures(counts.total)} completed; ${stoppedCopy}. Findings cover only the completed captures.`,
    };
  }
  if (counts.failed) {
    return {
      state: "failed",
      counts,
      label: "Failed",
      caption: `${counts.cancelled ? `Nothing completed: ${stoppedCopy}` : "The analysis failed"}. No results were saved for ${counts.total === 1 ? "this capture" : "these captures"}; see the reason below.`,
    };
  }
  if (counts.cancelled) {
    return { state: "cancelled", counts, label: "Cancelled", caption: `${captures(counts.cancelled)} cancelled before finishing. No results were saved.` };
  }
  return { state: "empty", counts, label: "Ready", caption: "No active analysis is running." };
}
