// Pure presentation logic for the Findings verdict, indicator counts, and
// report evidence coverage. Everything here is derived from the bootstrap
// payload so the UI never asserts a result the analysis did not produce.

const RISK_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3 };
const BEACON_ELEVATED_THRESHOLD = 3;

const count = (value) => Math.max(0, Math.floor(Number(value) || 0));
const plural = (value, singular, pluralForm = `${singular}s`) => `${value.toLocaleString()} ${value === 1 ? singular : pluralForm}`;

function normalizeRisk(value) {
  const risk = String(value || "").trim().toUpperCase();
  return RISK_RANK[risk] ? risk : "";
}

/**
 * Decide what the Findings verdict banner should say.
 *
 * @param {object} input
 * @param {boolean} input.loading - bootstrap request has not completed yet.
 * @param {boolean} input.loaded - at least one bootstrap response was applied.
 * @param {string} input.error - latest bootstrap error message, if any.
 * @param {boolean} input.hasAnalysis - a saved analysis backs the dashboard.
 * @param {object} input.dashboard - dashboard payload.
 * @returns {{ state: string, tone: string, title: string, detail: string, signals: string[], stale: boolean }}
 *   state: loading | error | empty | verdict; tone: neutral | error | low | medium | high.
 */
export function deriveFindingsVerdict({ loading = false, loaded = true, error = "", hasAnalysis = false, dashboard = {} } = {}) {
  if (error && !loaded) {
    return {
      state: "error",
      tone: "error",
      title: "Verdict unavailable",
      detail: `The analysis could not be loaded, so no risk assessment is shown. ${error}`.trim(),
      signals: [],
      stale: false,
    };
  }
  if (loading && !loaded) {
    return { state: "loading", tone: "neutral", title: "Loading analysis…", detail: "The verdict appears once the saved analysis has loaded.", signals: [], stale: false };
  }

  const serverRisk = normalizeRisk(dashboard.risk);
  if (!hasAnalysis || !serverRisk) {
    return {
      state: "empty",
      tone: "neutral",
      title: "No analysis yet",
      detail: "Analyze a capture to get a risk verdict. Nothing has been assessed, so this is not a clean result.",
      signals: [],
      stale: Boolean(error),
    };
  }

  const alerts = count(dashboard.alerts);
  const yara = count(dashboard.yara_issues);
  const beacons = count(dashboard.beacons);
  const certs = count(dashboard.cert_issues);
  const warnings = Array.isArray(dashboard.warnings) ? dashboard.warnings.length : 0;

  const derivedRisk = alerts || yara ? "HIGH" : beacons >= BEACON_ELEVATED_THRESHOLD || certs ? "MEDIUM" : "LOW";
  const risk = RISK_RANK[serverRisk] >= RISK_RANK[derivedRisk] ? serverRisk : derivedRisk;

  const signals = [];
  if (alerts) signals.push(plural(alerts, "high-severity indicator"));
  if (yara) signals.push(plural(yara, "YARA match", "YARA matches"));
  if (beacons) signals.push(plural(beacons, "beacon candidate"));
  if (certs) signals.push(plural(certs, "certificate issue"));

  const scope = `${count(dashboard.packets).toLocaleString()} packets and ${count(dashboard.flows).toLocaleString()} flows were analyzed.`;
  const caveats = [];
  if (warnings) caveats.push(`${plural(warnings, "pipeline warning")} recorded, so coverage is incomplete.`);
  if (error) caveats.push("The latest refresh failed; this is the last loaded result.");

  let title;
  let body;
  if (risk === "HIGH") {
    title = signals.length ? `High risk: ${signals.slice(0, 2).join(" and ")}` : "High risk reported for this analysis";
    body = signals.length ? `Signals: ${signals.join(", ")}. Review the evidence inventory and supporting traffic.` : "The analysis service rated this capture HIGH. Review the evidence inventory and supporting traffic.";
  } else if (risk === "MEDIUM") {
    title = signals.length ? `Medium risk: ${signals.slice(0, 2).join(" and ")}` : "Medium risk reported for this analysis";
    body = signals.length ? `Signals: ${signals.join(", ")}. Review them before treating this capture as clean.` : "The analysis service rated this capture MEDIUM. Review the supporting evidence.";
  } else {
    title = "No elevated risk detected";
    body = signals.length
      ? `Below the elevated threshold, but recorded: ${signals.join(", ")}.`
      : "No high-severity indicators, YARA matches, beacon candidates, or certificate issues were recorded by the stages that ran.";
  }

  return {
    state: "verdict",
    tone: risk.toLowerCase(),
    title,
    detail: [scope, body, ...caveats].join(" "),
    signals,
    stale: Boolean(error),
  };
}

/**
 * Describe how many indicators exist versus how many rows the dashboard loaded.
 * The bootstrap payload caps `evidence` but reports the true size in `evidence_total`.
 */
export function summarizeIndicatorCount(loadedRows, evidenceTotal) {
  const loaded = Array.isArray(loadedRows) ? loadedRows.length : count(loadedRows);
  const total = Math.max(loaded, count(evidenceTotal));
  const capped = total > loaded;
  return {
    loaded,
    total,
    capped,
    label: capped ? `${loaded.toLocaleString()} of ${total.toLocaleString()}` : total.toLocaleString(),
  };
}

export const MAP_DESTINATION_CAP = 50;

/**
 * Word the map destination counter honestly: the server sends only the top
 * destinations by packet volume and (currently) no total.
 */
export function describeMappedDestinations(visibleCount, loadedCount, total) {
  const visible = count(visibleCount);
  const loaded = count(loadedCount);
  const knownTotal = count(total);
  const noun = visible === 1 ? "destination" : "destinations";
  if (knownTotal > loaded) return `${visible.toLocaleString()} mapped ${noun} · top ${loaded.toLocaleString()} of ${knownTotal.toLocaleString()} by packets`;
  if (loaded >= MAP_DESTINATION_CAP) return `${visible.toLocaleString()} mapped ${noun} · top ${loaded.toLocaleString()} destinations by packets only`;
  return `${visible.toLocaleString()} mapped ${noun}`;
}

/**
 * Header status chip. Until a bootstrap response has been applied the
 * workbench does not know whether anything is ready, so it must not say so.
 *
 * @returns {{ state: "loading"|"error"|"complete"|"ready", label: string }}
 */
export function deriveHeaderStatus({ loaded = true, error = "", analysisComplete = false } = {}) {
  if (!loaded) {
    return error ? { state: "error", label: "Workbench unavailable" } : { state: "loading", label: "Loading workbench…" };
  }
  if (analysisComplete) return { state: "complete", label: "Analysis complete" };
  return { state: "ready", label: "Ready to analyze" };
}

const hasStage = (stages, pattern) => stages.some((stage) => pattern.test(stage));

/**
 * Report-sidebar evidence coverage, bound to the stages and data actually
 * present in the payload. Status is one of: included | partial | skipped | missing.
 */
export function buildEvidenceCoverage(dashboard = {}) {
  const stages = (Array.isArray(dashboard.stages) ? dashboard.stages : []).map((stage) => String(stage || "").toLowerCase());
  const mapping = dashboard.attack_mapping && typeof dashboard.attack_mapping === "object" ? dashboard.attack_mapping : {};
  const dns = hasStage(stages, /^dns/);
  const tls = hasStage(stages, /^tls/);
  const yaraRan = stages.some((stage) => /^yara/.test(stage) && !/skip/.test(stage));
  const yaraSkipped = hasStage(stages, /^yara.*skip/);
  const status = (included) => (included ? "included" : "missing");
  return [
    { label: "Traffic & flows", status: status(hasStage(stages, /^(pyshark|zeek)/) || count(dashboard.flows) > 0) },
    { label: "DNS & TLS", status: dns && tls ? "included" : dns || tls ? "partial" : "missing", note: dns && !tls ? "DNS only" : tls && !dns ? "TLS only" : "" },
    { label: "Beaconing", status: status(hasStage(stages, /^beacon/)) },
    { label: "YARA", status: yaraRan ? "included" : yaraSkipped ? "skipped" : "missing" },
    { label: "OSINT", status: status(hasStage(stages, /^osint/) || (Array.isArray(dashboard.osint_rows) && dashboard.osint_rows.length > 0)) },
    { label: "MITRE mapping", status: status(Array.isArray(mapping.techniques)) },
  ];
}

export const COVERAGE_STATUS_LABELS = {
  included: "Included",
  partial: "Partial",
  skipped: "Skipped",
  missing: "Not recorded",
};

const LLM_PROVIDER_LABELS = { lmstudio: "LM Studio", openai: "OpenAI", anthropic: "Anthropic" };

/**
 * Run-setup summary rows bound to the saved configuration. Rows whose value
 * cannot be derived from the config are omitted rather than guessed.
 */
export function describeRunSetup(config = {}, { includeLlm = true, totalStages = 10 } = {}) {
  const rows = [];
  if (config.cfg_pyshark_limit !== undefined && config.cfg_pyshark_limit !== null && config.cfg_pyshark_limit !== "") {
    const limit = count(config.cfg_pyshark_limit);
    const profile = limit === 0 ? "Deep inspection" : limit <= 50000 ? "Fast triage" : "Balanced";
    rows.push({ label: "Profile", value: `${profile} · ${limit === 0 ? "no packet limit" : `first ${limit.toLocaleString()} packets`}` });
  }
  rows.push({ label: "Pipeline", value: includeLlm ? `${totalStages} stages` : `${totalStages - 1} stages · AI report off` });
  if (config.cfg_osint_top_ips !== undefined && config.cfg_osint_top_ips !== null && config.cfg_osint_top_ips !== "") {
    const top = count(config.cfg_osint_top_ips);
    rows.push({ label: "OSINT", value: top === 0 ? "All public IPs" : `Top ${top.toLocaleString()} public IPs` });
  }
  rows.push({ label: "Output", value: "Autosave to case" });

  const provider = String(config.cfg_llm_provider || "");
  const model = provider === "openai" ? config.cfg_openai_model : provider === "anthropic" ? config.cfg_anthropic_model : config.cfg_llm_model;
  const llmHint = provider
    ? [LLM_PROVIDER_LABELS[provider] || provider, model, config.cfg_llm_language].filter(Boolean).join(" · ")
    : "Uses the provider saved in Settings";
  return { rows, llmHint };
}
