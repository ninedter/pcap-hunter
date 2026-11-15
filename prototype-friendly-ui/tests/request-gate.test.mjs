import assert from "node:assert/strict";
import test from "node:test";

import { createRequestGate } from "../src/workbench.js";

test("only the newest request generation may apply its response", () => {
  const gate = createRequestGate();
  const poll = gate.begin();
  const selectAnalysis = gate.begin();
  assert.equal(gate.isCurrent(poll), false);
  assert.equal(gate.isCurrent(selectAnalysis), true);

  // The older poll resolving last must still be rejected.
  gate.end();
  gate.end();
  assert.equal(gate.isCurrent(poll), false);
  assert.equal(gate.isCurrent(selectAnalysis), true);
});

test("the gate is busy while any request is pending", () => {
  const gate = createRequestGate();
  assert.equal(gate.isBusy(), false);
  gate.begin();
  gate.begin();
  assert.equal(gate.isBusy(), true);
  gate.end();
  assert.equal(gate.isBusy(), true);
  gate.end();
  assert.equal(gate.isBusy(), false);
  gate.end();
  assert.equal(gate.isBusy(), false);
});

test("a stalled request stops blocking the poll after the stall window", () => {
  let clock = 1000;
  const gate = createRequestGate({ now: () => clock });
  gate.begin();
  clock += 1600;
  assert.equal(gate.isBusy(20000), true);
  clock += 20000;
  assert.equal(gate.isBusy(20000), false);
  const retry = gate.begin();
  assert.equal(gate.isBusy(20000), true);
  assert.equal(gate.isCurrent(retry), true);
});
