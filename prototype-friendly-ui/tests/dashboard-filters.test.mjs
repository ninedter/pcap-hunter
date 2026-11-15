import assert from "node:assert/strict";
import test from "node:test";

import { buildDashboardViewRoute, buildScreenRoute, filterDashboardMapFlows, formatTimelineTick, formatTrafficBytes, isCurrentRoute, isMultiDayTimeline } from "../src/dashboardFilters.js";

const flows = [
  {
    ip: "8.8.8.8",
    city: "Mountain View",
    country: "United States",
    continent: "North America",
    packets: 18,
    byte_count: 3072,
    bytes: "3 KB",
    protocols: ["DNS", "TCP"],
    traffic_slices: [
      { protocol: "DNS", time: "12:01", packets: 4, bytes: 1024 },
      { protocol: "DNS", time: "12:02", packets: 6, bytes: 1024 },
      { protocol: "TCP", time: "12:02", packets: 8, bytes: 1024 },
    ],
  },
  {
    ip: "1.1.1.1",
    city: "Sydney",
    country: "Australia",
    continent: "Oceania",
    packets: 5,
    byte_count: 512,
    bytes: "1 KB",
    protocols: ["TCP"],
    traffic_slices: [{ protocol: "TCP", time: "12:01", packets: 5, bytes: 512 }],
  },
];

test("protocol selections recalculate map traffic instead of only hiding endpoints", () => {
  const filtered = filterDashboardMapFlows(flows, { protocol: "DNS" });

  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].ip, "8.8.8.8");
  assert.equal(filtered[0].packets, 10);
  assert.equal(filtered[0].bytes, "2.0 KiB");
  assert.deepEqual(filtered[0].protocols, ["DNS"]);
});

test("timeline and protocol selections share one intersection for the map", () => {
  const filtered = filterDashboardMapFlows(flows, { protocol: "DNS", time: "12:02" });

  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].packets, 6);
  assert.equal(filtered[0].bytes, "1.0 KiB");
});

test("search remains combined with visualization filters", () => {
  assert.equal(filterDashboardMapFlows(flows, { query: "sydney", protocol: "TCP" }).length, 1);
  assert.equal(filterDashboardMapFlows(flows, { query: "sydney", protocol: "DNS" }).length, 0);
});

test("traffic byte labels remain readable at map scale", () => {
  assert.equal(formatTrafficBytes(0), "0 B");
  assert.equal(formatTrafficBytes(512), "512 B");
  assert.equal(formatTrafficBytes(2_621_440), "2.5 MiB");
});

test("SPA routes preserve searches and avoid duplicate same-screen targets", () => {
  assert.equal(buildScreenRoute("dashboard", "?privacy=1"), "/dashboard?privacy=1");
  assert.equal(buildScreenRoute("investigate", "privacy=1&case=abc"), "/investigate?privacy=1&case=abc");
  assert.equal(buildDashboardViewRoute("traffic-replay", "?privacy=1"), "/dashboard?privacy=1#traffic-replay");
  assert.equal(isCurrentRoute("/dashboard", "?privacy=1", "/dashboard?privacy=1"), true);
  assert.equal(isCurrentRoute("/dashboard", "?privacy=1", "/dashboard"), false);
});

// Shapes from _traffic_rows/_map_flows in app/web/state.py for a capture that
// spans two UTC days: labels carry the date and every bucket has an ISO `ts`.
const multiDayTimeline = [
  { time: "2026-03-01 23:59", flows: 4, ts: "2026-03-01T23:59:00Z" },
  { time: "2026-03-02 00:01", flows: 2, ts: "2026-03-02T00:01:00Z" },
  { time: "2026-03-02 23:59", flows: 1, ts: "2026-03-02T23:59:00Z" },
];
const multiDayFlows = [{
  ip: "8.8.8.8", city: "Mountain View", country: "United States", continent: "North America",
  packets: 21, byte_count: 4096, bytes: "4 KB", protocols: ["DNS", "TCP"], status: "Expected", assessed: true, assessment: "Expected",
  traffic_slices: [
    { protocol: "DNS", time: "2026-03-01 23:59", packets: 4, bytes: 1024, ts: "2026-03-01T23:59:00Z" },
    { protocol: "DNS", time: "2026-03-02 23:59", packets: 9, bytes: 2048, ts: "2026-03-02T23:59:00Z" },
    { protocol: "TCP", time: "2026-03-02 23:59", packets: 8, bytes: 1024, ts: "2026-03-02T23:59:00Z" },
  ],
}];

test("multi-day timeline labels filter the map by the exact dated bucket", () => {
  const dayTwo = filterDashboardMapFlows(multiDayFlows, { time: multiDayTimeline[2].time });
  assert.equal(dayTwo.length, 1);
  assert.equal(dayTwo[0].packets, 17, "the same clock minute on day one must not be merged in");
  assert.deepEqual(dayTwo[0].protocols, ["DNS", "TCP"]);

  const dayOne = filterDashboardMapFlows(multiDayFlows, { time: "2026-03-01 23:59", protocol: "DNS" });
  assert.equal(dayOne[0].packets, 4);
  assert.equal(dayOne[0].bytes, "1.0 KiB");

  // A bare clock label no longer matches a dated capture, and a bucket with no traffic hides the endpoint.
  assert.equal(filterDashboardMapFlows(multiDayFlows, { time: "23:59" }).length, 0);
  assert.equal(filterDashboardMapFlows(multiDayFlows, { time: multiDayTimeline[1].time }).length, 0);
});

test("timeline ticks shorten dated labels and leave single-day labels alone", () => {
  assert.equal(isMultiDayTimeline(multiDayTimeline), true);
  assert.equal(isMultiDayTimeline([{ time: "12:01", flows: 3, ts: "2026-03-01T12:01:00Z" }]), false);
  assert.equal(isMultiDayTimeline([]), false);
  assert.equal(isMultiDayTimeline(undefined), false);
  assert.equal(formatTimelineTick("2026-03-02 00:01"), "03-02 00:01");
  assert.equal(formatTimelineTick("12:01"), "12:01");
  assert.equal(formatTimelineTick(""), "");
  assert.equal(formatTimelineTick(undefined), "");
});
