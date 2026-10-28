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
      endpoint_ranking: [{ ip: "198.51.100.33", bytes: 99 }],
      traffic_replay: { events: [{ src: "10.1.2.3", dst: "198.51.100.33", src_scope: "private 10.1.2.3", dst_scope: "public 198.51.100.33", flow_id: "flow-correlation-42" }, { src: "198.51.100.33", dst: "10.1.2.3", flow_id: "flow-correlation-42" }] },
    },
    cases: [{ title: "Executive laptop", notes: [{ content: "Contact analyst@example.com" }] }],
    jobs: [{ name: "customer-traffic.pcap", error: "Read /Users/analyst/private/customer-traffic.pcap" }],
    config: { cfg_vt_key: "top-secret", cfg_home_lat: 25.03, cfg_home_lon: 121.56 },
    ipv6_samples: ["2001:db8::1", "::1", "fe80::a00:27ff:fe4e:66a1", "2001:4860:4860::8888", "::ffff:192.0.2.128", "2001:db8::1"],
    timestamp: "2026-10-13T02:00:00Z",
    free_text: "Address 2001:db8::1. [2001:4860:4860::8888]:443, ::ffff:192.0.2.128/128",
    embedded_ipv6: ["x2001:db8::1", "prefix2001:db8::1"],
    ipv6_urls: ["https://[2001:db8::1]:8443/a?q=one", "http://[::1]/path", "wss://[::ffff:192.0.2.128]:443/socket"],
  };

  const result = sanitizeWorkbenchPayload(source);
  const serialized = JSON.stringify(result);

  for (const sensitive of [
    "case-abc123",
    "d24ff712",
    "Customer incident",
    "10.1.2.3",
    "203.0.113.8",
    "198.51.100.33",
    "flow-correlation-42",
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
  assert.equal(result.dashboard.traffic_replay.events[0].src, result.dashboard.top_talkers[0].name);
  assert.equal(result.dashboard.traffic_replay.events[0].dst, result.dashboard.endpoint_ranking[0].ip);
  assert.equal(result.dashboard.traffic_replay.events[0].dst.includes("198.51.100.33"), false);
  assert.equal(result.dashboard.traffic_replay.events[0].flow_id, result.dashboard.traffic_replay.events[1].flow_id);
  assert.match(result.dashboard.traffic_replay.events[0].flow_id, /^\[ID \d{2}\]$/);
  assert.equal(result.ipv6_samples[0], result.ipv6_samples[5]);
  assert.match(result.ipv6_samples[0], /^\[IP \d{2}\]$/);
  assert.match(result.ipv6_samples[4], /^\[IP \d{2}\]$/);
  assert.equal(result.timestamp, "2026-10-13T02:00:00Z");
  assert.equal(result.free_text.includes("2001:db8::1"), false);
  assert.equal(result.free_text.includes("2001:4860:4860::8888"), false);
  assert.equal(result.free_text.includes("::ffff:192.0.2.128"), false);
  assert.equal(result.free_text.includes(".0.2.128"), false);
  for (const value of result.embedded_ipv6) {
    assert.match(value, /^\[IP \d{2}\]$/);
    for (const fragment of ["2001:", "db8", "::1"]) assert.equal(value.includes(fragment), false);
  }
  for (const value of result.ipv6_urls) assert.match(value, /^\[URL \d{2}\]$/);
  assert.equal(result.dashboard.traffic_replay.events[0].src_scope.includes("10.1.2.3"), false);
});
