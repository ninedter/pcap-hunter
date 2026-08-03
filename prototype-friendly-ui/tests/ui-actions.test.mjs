import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAttackNavigatorLayer,
  buildIocCsv,
  getDashboardChartExport,
  isPrivateAddress,
} from "../src/uiActions.js";

test("IOC CSV escapes quotes and preserves all visible fields", () => {
  const csv = buildIocCsv([{
    value: "example.com",
    type: "Domain",
    context: 'Observed as "answer"',
    status: "Observed",
    source: "capture.pcap",
  }]);
  assert.match(csv, /^value,type,context,status,source\n/);
  assert.match(csv, /"Observed as ""answer"""/);
});

test("private-address filtering covers local IPv4 ranges", () => {
  for (const value of ["10.1.2.3", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.168.1.2", "100.64.1.1"]) {
    assert.equal(isPrivateAddress(value), true, value);
  }
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  assert.equal(isPrivateAddress("not-an-ip"), false);
});

test("dashboard chart export follows the selected visualization", () => {
  const result = getDashboardChartExport("profile", { packet_sizes: [{ bucket: "64", count: 2 }], inter_arrivals: [], heatmap: [1] });
  assert.equal(result.filename, "pcap-hunter-traffic-profile.json");
  assert.deepEqual(JSON.parse(result.content).data.heatmap, [1]);
});

test("ATT&CK Navigator export carries confidence, evidence, and limitations", () => {
  const layer = buildAttackNavigatorLayer({ techniques: [{
    technique_id: "T1071.001",
    tactic: "command-and-control",
    confidence: 0.91,
    evidence: ["Periodic TCP traffic"],
    limitations: ["Network-only hypothesis"],
  }] }, { caseId: "case-1", analysisId: "analysis-1" });
  assert.equal(layer.techniques[0].score, 91);
  assert.match(layer.techniques[0].comment, /Network-only hypothesis/);
  assert.equal(layer.metadata[0].value, "case-1");
});
