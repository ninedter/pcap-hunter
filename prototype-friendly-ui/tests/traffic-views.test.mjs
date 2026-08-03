import test from "node:test";
import assert from "node:assert/strict";

import { getDashboardViewForTarget, getTrafficViewTool, trafficViewTools } from "../src/trafficViews.js";

test("all additional traffic tools route to unique dashboard targets", () => {
  assert.equal(trafficViewTools.length, 8);
  assert.equal(new Set(trafficViewTools.map((tool) => tool.target)).size, 8);
  for (const tool of trafficViewTools) assert.equal(getTrafficViewTool(tool.target), tool);
});

test("deep-dive traffic tools select the correct dashboard visualization", () => {
  assert.equal(getDashboardViewForTarget("sankey-flow"), "paths");
  assert.equal(getDashboardViewForTarget("network-graph"), "network");
  assert.equal(getDashboardViewForTarget("attack-timeline"), "timeline");
  for (const target of ["packet-size-histogram", "inter-arrival-histogram", "traffic-heatmap"]) {
    assert.equal(getDashboardViewForTarget(target), "profile");
  }
});
