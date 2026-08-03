import assert from "node:assert/strict";
import test from "node:test";

import { filterDashboardMapFlows, formatTrafficBytes } from "../src/dashboardFilters.js";

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
  assert.equal(filtered[0].bytes, "2 KB");
  assert.deepEqual(filtered[0].protocols, ["DNS"]);
});

test("timeline and protocol selections share one intersection for the map", () => {
  const filtered = filterDashboardMapFlows(flows, { protocol: "DNS", time: "12:02" });

  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].packets, 6);
  assert.equal(filtered[0].bytes, "1 KB");
});

test("search remains combined with visualization filters", () => {
  assert.equal(filterDashboardMapFlows(flows, { query: "sydney", protocol: "TCP" }).length, 1);
  assert.equal(filterDashboardMapFlows(flows, { query: "sydney", protocol: "DNS" }).length, 0);
});

test("traffic byte labels remain readable at map scale", () => {
  assert.equal(formatTrafficBytes(512), "1 KB");
  assert.equal(formatTrafficBytes(2_621_440), "2.5 MB");
});
