import test from "node:test";
import assert from "node:assert/strict";

import { normalizeJobProgress, pipelineStageIndex } from "../src/progress.js";

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
