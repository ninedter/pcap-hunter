import assert from "node:assert/strict";
import test from "node:test";

import { isPrivacyMode, sanitizeWorkbenchPayload } from "../src/privacy.js";

test("privacy mode is explicit and opt-in", () => {
  assert.equal(isPrivacyMode("?privacy=1"), true);
  assert.equal(isPrivacyMode("?privacy=0"), false);
  assert.equal(isPrivacyMode(""), false);
});

test("privacy sanitizer removes capture-specific identifiers without mutating input", () => {
  const source = {
    active_case_id: "case-abc123",
    active_analysis_id: "d24ff712",
    active_case_title: "Customer incident",
    dashboard: {
      top_talkers: [
        { name: "10.1.2.3" },
        { name: "203.0.113.8" },
        { name: "10.1.2.3" },
      ],
      evidence: [{ value: "edge.customer.example", source: "customer-traffic.pcap" }],
      map_flows: [{ ip: "203.0.113.8", city: "Taipei", country: "Taiwan", continent: "Asia" }],
    },
    cases: [{ title: "Executive laptop", notes: [{ content: "Contact analyst@example.com" }] }],
    jobs: [{ name: "customer-traffic.pcap", error: "Read /Users/analyst/private/customer-traffic.pcap" }],
    config: { cfg_vt_key: "top-secret", cfg_home_lat: 25.03, cfg_home_lon: 121.56 },
  };

  const result = sanitizeWorkbenchPayload(source);
  const serialized = JSON.stringify(result);

  for (const sensitive of [
    "case-abc123",
    "d24ff712",
    "Customer incident",
    "10.1.2.3",
    "203.0.113.8",
    "edge.customer.example",
    "customer-traffic.pcap",
    "Executive laptop",
    "analyst@example.com",
    "/Users/analyst/private",
    "top-secret",
    "Taipei",
    "Taiwan",
  ]) assert.equal(serialized.includes(sensitive), false, sensitive);

  assert.equal(result.dashboard.top_talkers[0].name, result.dashboard.top_talkers[2].name);
  assert.notEqual(result.dashboard.top_talkers[0].name, result.dashboard.top_talkers[1].name);
  assert.equal(result.config.cfg_home_lat, 0);
  assert.equal(result.config.cfg_home_lon, 0);
  assert.equal(source.dashboard.top_talkers[0].name, "10.1.2.3");
});
