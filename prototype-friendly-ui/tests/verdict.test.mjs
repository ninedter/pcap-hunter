import assert from "node:assert/strict";
import test from "node:test";

import { buildEvidenceCoverage, deriveFindingsVerdict, deriveHeaderStatus, describeMappedDestinations, describeRunSetup, summarizeIndicatorCount } from "../src/verdict.js";

const clean = { risk: "LOW", packets: 1200, flows: 40, alerts: 0, beacons: 0, yara_issues: 0, cert_issues: 0, warnings: [] };
const verdict = (dashboard, extra = {}) => deriveFindingsVerdict({ loading: false, loaded: true, error: "", hasAnalysis: true, dashboard, ...extra });

test("verdict never shows a clean result before data has loaded", () => {
  const loading = deriveFindingsVerdict({ loading: true, loaded: false, dashboard: { risk: "N/A" } });
  assert.equal(loading.state, "loading");
  assert.equal(loading.tone, "neutral");

  const failed = deriveFindingsVerdict({ loading: false, loaded: false, error: "Service unavailable", dashboard: { risk: "N/A" } });
  assert.equal(failed.state, "error");
  assert.equal(failed.tone, "error");
  assert.match(failed.detail, /Service unavailable/);

  const empty = deriveFindingsVerdict({ loaded: true, hasAnalysis: false, dashboard: { risk: "N/A", alerts: 0 } });
  assert.equal(empty.state, "empty");
  assert.match(empty.detail, /not a clean result/);

  for (const result of [loading, failed, empty]) assert.doesNotMatch(result.title, /No elevated risk/);
  assert.equal(verdict({ ...clean, risk: "N/A" }).state, "empty");
});

test("verdict is low only when no signal is present", () => {
  const result = verdict(clean);
  assert.equal(result.state, "verdict");
  assert.equal(result.tone, "low");
  assert.equal(result.title, "No elevated risk detected");
  assert.match(result.detail, /1,200 packets and 40 flows/);
  assert.deepEqual(result.signals, []);
});

test("YARA matches and high-severity indicators raise the verdict to high", () => {
  const yaraOnly = verdict({ ...clean, risk: "HIGH", yara_issues: 2 });
  assert.equal(yaraOnly.tone, "high");
  assert.match(yaraOnly.title, /2 YARA matches/);

  const alerts = verdict({ ...clean, risk: "HIGH", alerts: 1, beacons: 4 });
  assert.equal(alerts.tone, "high");
  assert.match(alerts.title, /1 high-severity indicator/);
  assert.match(alerts.detail, /4 beacon candidates/);
});

test("beacons and certificate issues produce a medium verdict", () => {
  assert.equal(verdict({ ...clean, risk: "MEDIUM", beacons: 3 }).tone, "medium");
  const certs = verdict({ ...clean, risk: "MEDIUM", cert_issues: 1 });
  assert.equal(certs.tone, "medium");
  assert.match(certs.title, /1 certificate issue/);
});

test("verdict takes the more severe of the server rating and the signals in the payload", () => {
  assert.equal(verdict({ ...clean, risk: "LOW", yara_issues: 1 }).tone, "high");
  assert.equal(verdict({ ...clean, risk: "LOW", cert_issues: 2 }).tone, "medium");
  const serverOnly = verdict({ ...clean, risk: "HIGH" });
  assert.equal(serverOnly.tone, "high");
  assert.match(serverOnly.title, /High risk reported/);
});

test("sub-threshold signals, warnings, and stale data are disclosed", () => {
  const few = verdict({ ...clean, beacons: 2 });
  assert.equal(few.tone, "low");
  assert.match(few.detail, /2 beacon candidates/);

  const warned = verdict({ ...clean, warnings: ["yara_failed"] });
  assert.match(warned.detail, /1 pipeline warning recorded, so coverage is incomplete/);

  const stale = verdict(clean, { error: "Network error" });
  assert.equal(stale.state, "verdict");
  assert.equal(stale.stale, true);
  assert.match(stale.detail, /latest refresh failed/);
});

test("indicator counts expose the server total when the loaded list is capped", () => {
  const rows = Array.from({ length: 100 }, (_, index) => ({ value: index }));
  assert.deepEqual(summarizeIndicatorCount(rows, 1234), { loaded: 100, total: 1234, capped: true, label: "100 of 1,234" });
  assert.deepEqual(summarizeIndicatorCount(rows.slice(0, 7), 7), { loaded: 7, total: 7, capped: false, label: "7" });
  assert.equal(summarizeIndicatorCount(rows.slice(0, 7), undefined).total, 7);
  assert.equal(summarizeIndicatorCount(undefined, undefined).label, "0");
});

test("mapped destination count is qualified when the top-50 cap is hit", () => {
  assert.equal(describeMappedDestinations(12, 12), "12 mapped destinations");
  assert.equal(describeMappedDestinations(1, 12), "1 mapped destination");
  assert.equal(describeMappedDestinations(50, 50), "50 mapped destinations · top 50 destinations by packets only");
  assert.equal(describeMappedDestinations(8, 50), "8 mapped destinations · top 50 destinations by packets only");
  assert.equal(describeMappedDestinations(50, 50, 312), "50 mapped destinations · top 50 of 312 by packets");
});

test("evidence coverage reflects the specific stages that ran", () => {
  const status = (dashboard) => Object.fromEntries(buildEvidenceCoverage(dashboard).map((row) => [row.label, row.status]));

  assert.deepEqual(status({}), { "Traffic & flows": "missing", "DNS & TLS": "missing", Beaconing: "missing", YARA: "missing", OSINT: "missing", "MITRE mapping": "missing" });

  // Six stages recorded, but neither OSINT nor a real YARA scan: a positional check would call all six "Included".
  const partial = status({ stages: ["pcap_count", "pyshark_pass", "zeek", "dns_analysis", "beacon", "yara_scan_skipped"], flows: 12 });
  assert.deepEqual(partial, { "Traffic & flows": "included", "DNS & TLS": "partial", Beaconing: "included", YARA: "skipped", OSINT: "missing", "MITRE mapping": "missing" });
  assert.equal(buildEvidenceCoverage({ stages: ["dns_analysis"] })[1].note, "DNS only");

  const full = status({ stages: ["pcap_count", "pyshark_pass", "zeek", "dns_analysis", "tls_certs", "beacon", "carve", "yara_scan", "osint", "llm"], attack_mapping: { techniques: [] } });
  assert.deepEqual(new Set(Object.values(full)), new Set(["included"]));
});

test("run setup is bound to saved configuration and omits unknown values", () => {
  const unknown = describeRunSetup({}, { includeLlm: true });
  assert.deepEqual(unknown.rows.map((row) => row.label), ["Pipeline", "Output"]);
  assert.equal(unknown.llmHint, "Uses the provider saved in Settings");

  const saved = describeRunSetup({ cfg_pyshark_limit: 50000, cfg_osint_top_ips: 0, cfg_llm_provider: "anthropic", cfg_anthropic_model: "model-x", cfg_llm_language: "Japanese" }, { includeLlm: false });
  assert.deepEqual(saved.rows, [
    { label: "Profile", value: "Fast triage · first 50,000 packets" },
    { label: "Pipeline", value: "9 stages · AI report off" },
    { label: "OSINT", value: "All public IPs" },
    { label: "Output", value: "Autosave to case" },
  ]);
  assert.equal(saved.llmHint, "Anthropic · model-x · Japanese");
  assert.equal(describeRunSetup({ cfg_pyshark_limit: 0, cfg_osint_top_ips: 25 }).rows[0].value, "Deep inspection · no packet limit");
  assert.equal(describeRunSetup({ cfg_osint_top_ips: 25 }).rows[1].value, "Top 25 public IPs");
});

test("the header never claims readiness before the bootstrap has loaded", () => {
  assert.deepEqual(deriveHeaderStatus({ loading: true, loaded: false, error: "" }), { state: "loading", label: "Loading workbench…" });
  assert.deepEqual(deriveHeaderStatus({ loading: false, loaded: false, error: "Service unavailable" }), { state: "error", label: "Workbench unavailable" });
  assert.deepEqual(deriveHeaderStatus({ loading: false, loaded: true, error: "", analysisComplete: false }), { state: "ready", label: "Ready to analyze" });
  assert.deepEqual(deriveHeaderStatus({ loading: false, loaded: true, error: "", analysisComplete: true }), { state: "complete", label: "Analysis complete" });
  // A failed background refresh after a successful load keeps the last known state; the global banner reports the error.
  assert.equal(deriveHeaderStatus({ loading: false, loaded: true, error: "Service unavailable", analysisComplete: true }).state, "complete");
});
