import assert from "node:assert/strict";
import test from "node:test";

import { createRequestGate, isTerminalJobStatus, jobsNeedBootstrapRefresh, planJobsPollTick } from "../src/workbench.js";

const job = (id, status, extra = {}) => ({ id, case_id: "case-1", name: `${id}.pcap`, status, stage: "Zeek processing", progress: 30, ...extra });

test("progress-only changes update jobs without a bootstrap refetch", () => {
  const previous = [job("a", "running", { progress: 30 }), job("b", "queued")];
  const next = [job("a", "running", { progress: 55, stage: "DNS Analysis" }), job("b", "queued")];
  assert.equal(jobsNeedBootstrapRefresh(previous, next), false);
  assert.equal(jobsNeedBootstrapRefresh(previous, [job("a", "running"), job("b", "running")]), false);
});

test("a job reaching any terminal state triggers a bootstrap refetch", () => {
  for (const status of ["done", "failed", "cancelled"]) {
    assert.equal(isTerminalJobStatus(status), true);
    assert.equal(jobsNeedBootstrapRefresh([job("a", "running")], [job("a", status)]), true, status);
    assert.equal(jobsNeedBootstrapRefresh([job("a", "queued")], [job("a", status)]), true, status);
  }
  assert.equal(isTerminalJobStatus("running"), false);
  assert.equal(isTerminalJobStatus("queued"), false);
});

test("jobs that were already terminal do not keep refetching", () => {
  const settled = [job("a", "done"), job("b", "failed")];
  assert.equal(jobsNeedBootstrapRefresh(settled, [job("a", "done"), job("b", "failed")]), false);
  // Reordering alone is not a change.
  assert.equal(jobsNeedBootstrapRefresh(settled, [job("b", "failed"), job("a", "done")]), false);
});

test("a changed set of job ids triggers a bootstrap refetch", () => {
  const previous = [job("a", "done")];
  assert.equal(jobsNeedBootstrapRefresh(previous, [job("a", "done"), job("b", "queued")]), true, "job submitted elsewhere");
  assert.equal(jobsNeedBootstrapRefresh(previous, []), true, "job removed");
  assert.equal(jobsNeedBootstrapRefresh(previous, [job("c", "done")]), true, "same count, different id");
  assert.equal(jobsNeedBootstrapRefresh([], [job("a", "done")]), true);
  assert.equal(jobsNeedBootstrapRefresh([], []), false);
  assert.equal(jobsNeedBootstrapRefresh(undefined, undefined), false);
});

test("an active-job tick polls jobs, skips while busy, and falls back to bootstrap", () => {
  const idleGates = { bootstrapBusy: false, bootstrapPending: false, jobsBusy: false, jobsEndpointMissing: false };
  assert.equal(planJobsPollTick(idleGates), "jobs");
  assert.equal(planJobsPollTick({ ...idleGates, bootstrapBusy: true, bootstrapPending: true }), "skip");
  assert.equal(planJobsPollTick({ ...idleGates, jobsBusy: true }), "skip");
  // A bootstrap stuck past the stall window is retried in full, as before.
  assert.equal(planJobsPollTick({ ...idleGates, bootstrapPending: true }), "bootstrap");
  // Older server without /api/ui/jobs: previous bootstrap polling.
  assert.equal(planJobsPollTick({ ...idleGates, jobsEndpointMissing: true }), "bootstrap");
  assert.equal(planJobsPollTick({ ...idleGates, jobsEndpointMissing: true, bootstrapBusy: true, bootstrapPending: true }), "skip");
});

test("the idle check runs only for a visible, loaded tab and never falls back to bootstrap", () => {
  const base = { bootstrapBusy: false, bootstrapPending: false, jobsBusy: false, jobsEndpointMissing: false, idle: true };
  assert.equal(planJobsPollTick({ ...base, visible: true, loaded: true }), "jobs");
  assert.equal(planJobsPollTick({ ...base, visible: false, loaded: true }), "skip");
  assert.equal(planJobsPollTick({ ...base, visible: true, loaded: false }), "skip");
  assert.equal(planJobsPollTick({ ...base, jobsEndpointMissing: true }), "skip");
  assert.equal(planJobsPollTick({ ...base, bootstrapPending: true }), "skip");
  assert.equal(planJobsPollTick({ ...base, jobsBusy: true }), "skip");
});

test("a job poll can tell that a bootstrap request started while it was pending", () => {
  const bootstrapGate = createRequestGate();
  assert.equal(bootstrapGate.current(), 0);
  const seen = bootstrapGate.current();
  const refresh = bootstrapGate.begin();
  assert.notEqual(bootstrapGate.current(), seen);
  assert.equal(bootstrapGate.current(), refresh);
  bootstrapGate.end();
  assert.equal(bootstrapGate.current(), refresh);
});
