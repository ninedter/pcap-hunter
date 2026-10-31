import test from "node:test";
import assert from "node:assert/strict";
import { filterTrafficReplayEvents, formatExactReplayTimestamp, formatReplayBytes, formatReplayTime, getReplayLane, getReplayMarkerIndexes, getReplayPlaybackPlan, getReplayTimelinePosition, getReplayTimelinePositions, getTrafficReplayCoverage, getTrafficReplayControlState, normalizeTrafficReplayEvents, summarizeTrafficReplayEvents } from "../src/trafficReplay.js";

const raw = [
  { timestamp: "2026-10-13T02:00:00Z", flow_id: "later", src: "10.1.1.2", dst: "8.8.8.8", sport: 50000, dport: 53, protocol: "DNS", sampled_length: 72, src_scope: "private", dst_scope: "public" },
  { timestamp: "invalid", offset_seconds: 1.2, flow_id: "early", src: "10.1.1.2", dst: "224.0.0.251", sport: 5353, dport: 5353, protocol: "MDNS", sampled_length: 44, src_scope: "private", dst_scope: "multicast" },
];

test("normalizes the authoritative replay event schema and keeps timestamped events before malformed timestamp fallbacks", () => {
  const events = normalizeTrafficReplayEvents(raw);
  assert.equal(events[0].flow_id, "later");
  assert.equal(events[1].lane, "special");
  assert.equal(events[0].sourceLane, "internal");
  assert.equal(events[0].destinationLane, "external");
  assert.equal(events[0].destination_address, "8.8.8.8");
  assert.equal(events[0].bytes, 72);
});

test("scope lane helper places source and destination independently", () => {
  assert.equal(getReplayLane("private"), "internal");
  assert.equal(getReplayLane("public"), "external");
  assert.equal(getReplayLane("multicast"), "special");
  assert.equal(getReplayLane("unknown"), "special");
  assert.equal(getReplayLane(), "special");
});

test("missing sampled lengths stay unavailable and do not inflate scoped byte totals", () => {
  const events = normalizeTrafficReplayEvents([{ flow_id: "missing", sampled_length: null }, { flow_id: "zero", sampled_length: 0 }, { flow_id: "negative", sampled_length: -8, packets: -2 }]);
  assert.equal(events[0].bytes, null);
  assert.equal(events[1].bytes, 0);
  assert.equal(events[2].bytes, 0);
  assert.equal(events[2].packets, 0);
  assert.equal(formatReplayBytes(events[0].bytes), "Length unavailable");
  assert.equal(summarizeTrafficReplayEvents(events).totalBytes, 0);
  assert.equal(summarizeTrafficReplayEvents(events).packetCount, 2);
});

test("timeline positions use normalized capture time and dense marker selection is bounded", () => {
  const events = normalizeTrafficReplayEvents([{ timestamp: 100 }, { timestamp: 130 }]);
  assert.equal(getReplayTimelinePosition(events[0], events), 0);
  assert.equal(getReplayTimelinePosition(events[1], events), 100);
  assert.deepEqual(getReplayTimelinePositions(events), [0, 100]);
  const markers = getReplayMarkerIndexes(2000, 1337);
  assert.ok(markers.length <= 240);
  assert.deepEqual([markers.includes(0), markers.includes(1337), markers.includes(1999)], [true, true, true]);
});

test("mixed timestamp and offset rows use monotonic sorted-order positions", () => {
  const events = normalizeTrafficReplayEvents([{ timestamp: 100 }, { timestamp: "invalid", offset_seconds: 0.5 }]);
  assert.deepEqual(getReplayTimelinePositions(events), [0, 100]);
});

test("compressed playback keeps a bounded render cadence while advancing dense event sets", () => {
  const plan = getReplayPlaybackPlan(2000, 4);
  assert.ok(plan.cadenceMs >= 40 && plan.cadenceMs <= 60);
  assert.ok(plan.stepSize > 1);
  assert.deepEqual(getReplayPlaybackPlan(1, 1), { cadenceMs: 50, stepSize: 1 });
});

test("replay-only controls are inert without a stage and expose reset only for changed local state", () => {
  assert.deepEqual(getTrafficReplayControlState(), { hasVisibleEvents: false, canChangeProtocol: false, canChangeSpeed: false, canZoomOut: false, canZoomIn: false, canFit: false, canToggleGrid: false, canRestart: false });
  assert.deepEqual(getTrafficReplayControlState({ visibleEventCount: 2, protocolCount: 2, zoom: 0.75 }), { hasVisibleEvents: true, canChangeProtocol: true, canChangeSpeed: true, canZoomOut: false, canZoomIn: true, canFit: true, canToggleGrid: true, canRestart: true });
  assert.equal(getTrafficReplayControlState({ visibleEventCount: 2 }).canRestart, false);
});

test("filters normalized replay rows by endpoint and protocol without treating malformed times as matching a range", () => {
  const events = normalizeTrafficReplayEvents(raw);
  assert.equal(filterTrafficReplayEvents(events, { ip: "8.8", protocol: "DNS" }).length, 1);
  assert.equal(filterTrafficReplayEvents(events, { from: "2026-10-13T01:00:00Z" }).length, 1);
  assert.equal(filterTrafficReplayEvents(events, { excludePrivate: true }).length, 0);
});

test("an exact IP query does not collide with a prefix endpoint while partial search remains available", () => {
  const events = normalizeTrafficReplayEvents([{ src: "10.1.17.2", dst: "203.0.113.1" }, { src: "10.1.17.215", dst: "203.0.113.2" }]);
  assert.deepEqual(filterTrafficReplayEvents(events, { ip: "10.1.17.2" }).map((event) => event.source_address), ["10.1.17.2"]);
  assert.deepEqual(filterTrafficReplayEvents(events, { ip: "10.1.17" }).map((event) => event.source_address), ["10.1.17.2", "10.1.17.215"]);
});

test("scoped summaries aggregate endpoint send and receive bytes from filtered replay rows", () => {
  const summary = summarizeTrafficReplayEvents({ events: [
    { timestamp: 1760310000, flow_id: "f1", src: "198.51.100.1", dst: "198.51.100.2", protocol: "TCP", sampled_length: 100, packets: 2, src_scope: "public", dst_scope: "public" },
    { timestamp: 1760310001, flow_id: "f2", src: "198.51.100.2", dst: "198.51.100.3", protocol: "UDP", sampled_length: 50, packets: 1, src_scope: "public", dst_scope: "public" },
  ] }, { protocol: "All" });
  assert.equal(summary.totalBytes, 150);
  assert.equal(summary.packetCount, 3);
  assert.equal(summary.flowCount, 2);
  assert.equal(summary.endpointCount, 3);
  assert.deepEqual(summary.protocol_distribution.map(({ name, bytes, packets, flow_count, percent }) => ({ name, bytes, packets, flow_count, percent })), [{ name: "TCP", bytes: 100, packets: 2, flow_count: 1, percent: 66.67 }, { name: "UDP", bytes: 50, packets: 1, flow_count: 1, percent: 33.33 }]);
  assert.deepEqual(summary.endpoint_ranking[0], { ip: "198.51.100.2", bytes: 150, packets: 3, flow_count: 2, sent_bytes: 50, received_bytes: 100 });
});

test("coverage wording communicates truncation and time formatting degrades safely", () => {
  assert.match(getTrafficReplayCoverage({ returned_event_count: 20, sampled_event_count: 60, truncated: true }, 20), /truncated/);
  assert.equal(formatReplayTime(normalizeTrafficReplayEvents(raw)[1]), "Capture +1.200 s");
  assert.equal(formatExactReplayTimestamp(normalizeTrafficReplayEvents(raw)[1]), "Capture +1.200 s (timestamp unavailable)");
});

test("coverage labels retain sampled, complete, and unavailable evidence", () => {
  assert.equal(getTrafficReplayCoverage({ coverage: "sampled", returned_event_count: 4, sampled_event_count: 12, represented_packet_count: 100, total_packet_count: 400, sampled_flow_count: 2, total_flow_count: 8 }), "Sampled replay coverage: 4 returned events from 12 sampled events; 100 of 400 parsed packets belong to sampled flows; 2 of 8 flows sampled");
  assert.equal(getTrafficReplayCoverage({ coverage: "complete", returned_event_count: 4, represented_packet_count: 100, total_packet_count: 100, sampled_flow_count: 2, total_flow_count: 2 }), "Complete replay coverage: 4 replay events; 100 of 100 parsed packets belong to sampled flows; 2 of 2 flows represented");
  assert.equal(getTrafficReplayCoverage({ coverage: "unavailable", returned_event_count: 4 }), "Replay coverage unavailable; 4 replay events shown");
  assert.equal(getTrafficReplayCoverage({ coverage: "unavailable", returned_event_count: 4, sampled_flow_count: 0, total_flow_count: 3 }), "Replay coverage unavailable; 4 replay events shown; 0 of 3 flows sampled");
  assert.equal(getTrafficReplayCoverage({ coverage: "sampled", returned_event_count: 18, sampled_event_count: 30 }, 14), "14 match active filters; Sampled replay coverage: 18 returned events from 30 sampled events");
});

test("numeric epoch timestamps preserve chronological ordering and render a precise derived ISO timestamp", () => {
  const events = normalizeTrafficReplayEvents([{ timestamp: 1760310001.25, flow_id: "later" }, { timestamp: 1760310000.5, flow_id: "first" }]);
  assert.equal(events[0].flow_id, "first");
  assert.match(formatExactReplayTimestamp(events[0]), /^2025-10-12T.*Z \(capture timestamp: 1760310000\.5\)$/);
});
