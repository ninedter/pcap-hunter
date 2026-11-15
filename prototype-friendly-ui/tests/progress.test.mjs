import test from "node:test";
import assert from "node:assert/strict";

import { PIPELINE_STAGES, PIPELINE_STAGE_KEYS, buildStageCoverage, isActiveJob, jobOutcomeMessage, normalizeJobProgress, pipelineStageIndex, summarizeRunQueue, summarizeStageCoverage } from "../src/progress.js";

test("maps worker stage names to the ten visible pipeline stages", () => {
  assert.equal(pipelineStageIndex("Packet counting (tshark)"), 0);
  assert.equal(pipelineStageIndex("Parsing Packets"), 1);
  assert.equal(pipelineStageIndex("TLS Certificate Analysis"), 4);
  assert.equal(pipelineStageIndex("HTTP carving (tshark)"), 6);
  assert.equal(pipelineStageIndex("OSINT enrichment"), 8);
  assert.equal(pipelineStageIndex("LLM report"), 9);
});

test("uses the active stage to repair a stale completed-stage counter", () => {
  const progress = normalizeJobProgress({
    status: "running",
    stage: "OSINT enrichment",
    completed_stages: 6,
    total_stages: 10,
    stage_progress: 5,
  });

  assert.equal(progress.activeStageIndex, 8);
  assert.equal(progress.completedStages, 8);
  assert.equal(progress.overallProgress, 80);
  assert.equal(progress.stageProgress, 5);
});

test("keeps the LLM stage, checklist, and overall percentage aligned", () => {
  const progress = normalizeJobProgress({
    status: "running",
    stage: "LLM report",
    completed_stages: 7,
    total_stages: 10,
    stage_progress: 50,
  });

  assert.equal(progress.activeStageIndex, 9);
  assert.equal(progress.completedStages, 9);
  assert.equal(progress.overallProgress, 95);
});

test("completed jobs always report full progress", () => {
  assert.deepEqual(normalizeJobProgress({ status: "done", total_stages: 10 }), {
    activeStageIndex: -1,
    completedStages: 10,
    displayStage: "Complete",
    overallProgress: 100,
    stageProgress: 100,
  });
});

test("failed and cancelled jobs keep their partial progress and name the outcome", () => {
  const failed = normalizeJobProgress({ status: "failed", stage: "Zeek processing", completed_stages: 2, total_stages: 10, stage_progress: 40, error: "zeek exited 1" });
  assert.equal(failed.displayStage, "Failed during Zeek processing");
  assert.equal(failed.completedStages, 2);
  assert.equal(failed.overallProgress, 20);
  assert.equal(failed.stageProgress, 0);

  const cancelled = normalizeJobProgress({ status: "cancelled", stage: "", completed_stages: 0, total_stages: 10 });
  assert.equal(cancelled.displayStage, "Cancelled");
  assert.equal(cancelled.overallProgress, 0);
});

test("job outcome text prefers the recorded error and is empty for healthy jobs", () => {
  assert.equal(jobOutcomeMessage({ status: "failed", error: " tshark not found " }), "tshark not found");
  assert.match(jobOutcomeMessage({ status: "failed", error: null }), /did not record a reason/);
  assert.match(jobOutcomeMessage({ status: "cancelled" }), /cancelled before it finished/);
  for (const status of ["queued", "running", "done"]) assert.equal(jobOutcomeMessage({ status, error: "stale" }), "");
  assert.equal(isActiveJob({ status: "queued" }), true);
  assert.equal(isActiveJob({ status: "failed" }), false);
});

test("run queue never reports a failed batch as ready or complete", () => {
  assert.equal(summarizeRunQueue([]).state, "empty");
  assert.equal(summarizeRunQueue([{ status: "running" }, { status: "failed" }]).state, "running");
  assert.match(summarizeRunQueue([{ status: "running" }, { status: "failed" }]).caption, /1 failed so far/);
  assert.equal(summarizeRunQueue([{ status: "done" }, { status: "done" }]).state, "complete");

  const failed = summarizeRunQueue([{ status: "failed" }]);
  assert.equal(failed.state, "failed");
  assert.equal(failed.label, "Failed");
  assert.doesNotMatch(failed.caption, /No active analysis/);

  const partial = summarizeRunQueue([{ status: "done" }, { status: "failed" }, { status: "cancelled" }]);
  assert.equal(partial.state, "partial");
  assert.deepEqual(partial.counts, { total: 3, active: 0, done: 1, failed: 1, cancelled: 1 });
  assert.match(partial.caption, /1 of 3 captures completed; 1 failed and 1 cancelled/);

  const cancelled = summarizeRunQueue([{ status: "cancelled" }, { status: "cancelled" }]);
  assert.equal(cancelled.state, "cancelled");
  assert.match(cancelled.caption, /2 captures cancelled/);
});

// Stage keys recorded by app/pipeline/runner.py and app/api/queue.py.
const FULL_RUN = ["pcap_count", "pyshark_pass", "zeek", "dns_analysis", "tls_certs", "beacon", "carve", "yara_scan", "osint", "llm"];
const coverageByLabel = (stages) => Object.fromEntries(buildStageCoverage(stages).map((item) => [item.label, item.status]));

test("every display stage has an explicit recorded stage key", () => {
  assert.deepEqual(Object.keys(PIPELINE_STAGE_KEYS), PIPELINE_STAGES);
  assert.deepEqual(Object.values(PIPELINE_STAGE_KEYS), FULL_RUN);
});

test("a full run marks all ten stages available with no visibility gaps", () => {
  assert.ok(buildStageCoverage(FULL_RUN).every((item) => item.status === "available"));
  assert.deepEqual(summarizeStageCoverage(FULL_RUN), { total: 10, available: 10, gaps: 0 });
});

test("packet counting, packet parsing, and HTTP carving match their recorded keys", () => {
  const coverage = coverageByLabel(["pcap_count", "pyshark_pass", "carve"]);
  assert.equal(coverage["Packet counting"], "available");
  assert.equal(coverage["Packet parsing"], "available");
  assert.equal(coverage["HTTP carving"], "available");
  assert.equal(coverage["Zeek processing"], "missing");
  // Only one of the two "Packet …" stages ran: the other must not match by its first word.
  assert.equal(coverageByLabel(["pcap_count"])["Packet parsing"], "missing");
});

test("a skipped YARA scan is reported as skipped, never as available", () => {
  const stages = ["pcap_count", "pyshark_pass", "zeek", "dns_analysis", "tls_certs", "beacon", "carve", "yara_scan_skipped", "osint"];
  const coverage = coverageByLabel(stages);
  assert.equal(coverage["YARA scanning"], "skipped");
  // The opt-in LLM report not running is not a detector visibility gap.
  assert.equal(coverage["LLM report"], "optional");
  assert.deepEqual(summarizeStageCoverage(stages), { total: 10, available: 8, gaps: 1 });
});

test("visibility gaps count missing and skipped detector stages, not list length", () => {
  // Failed DNS/TLS stages are dropped from stages_run; unknown extra entries must not hide gaps.
  const stages = ["pcap_count", "pyshark_pass", "zeek", "beacon", "yara_scan_skipped", "some_future_stage"];
  assert.deepEqual(summarizeStageCoverage(stages), { total: 10, available: 4, gaps: 5 });
  assert.deepEqual(summarizeStageCoverage([]), { total: 10, available: 0, gaps: 9 });
  assert.deepEqual(summarizeStageCoverage(undefined), { total: 10, available: 0, gaps: 9 });
  assert.equal(coverageByLabel([" DNS_Analysis ", null])["DNS analysis"], "available");
});
