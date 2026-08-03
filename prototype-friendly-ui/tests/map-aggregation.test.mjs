import assert from "node:assert/strict";
import test from "node:test";

import { aggregateMapFlows, buildMapFlowHierarchy, getMapAggregationLevel } from "../src/mapAggregation.js";

const flows = [
  { ip: "1", city: "Seattle", country: "United States", continent: "North America", coordinates: [-122.33, 47.61], packets: 120, protocols: ["TCP"], status: "Expected" },
  { ip: "4", city: "Seattle", country: "United States", continent: "North America", coordinates: [-122.34, 47.62], packets: 40, protocols: ["TLS"], status: "Expected" },
  { ip: "2", city: "Mountain View", country: "United States", continent: "North America", coordinates: [-122.08, 37.39], packets: 80, protocols: ["UDP"], status: "Review" },
  { ip: "3", city: "Frankfurt", country: "Germany", continent: "Europe", coordinates: [8.68, 50.11], packets: 60, protocols: ["TCP"], status: "Expected" },
];

test("map detail progresses from continents to countries to cities", () => {
  assert.equal(getMapAggregationLevel(1), "continent");
  assert.equal(getMapAggregationLevel(2), "country");
  assert.equal(getMapAggregationLevel(3), "city");
});

test("continent groups retain aggregate traffic and underlying endpoints", () => {
  const groups = aggregateMapFlows(flows, "continent");
  const northAmerica = groups.find((group) => group.label === "North America");

  assert.equal(groups.length, 2);
  assert.equal(northAmerica.endpointCount, 3);
  assert.equal(northAmerica.packets, 240);
  assert.deepEqual(northAmerica.protocols, ["TCP", "TLS", "UDP"]);
  assert.equal(northAmerica.status, "Review");
  assert.deepEqual(northAmerica.members.map((flow) => flow.ip), ["1", "4", "2"]);
});

test("country groups split into city groups while shared-city endpoints stay together", () => {
  const countries = aggregateMapFlows(flows, "country");
  const cities = aggregateMapFlows(flows, "city");

  assert.equal(countries.length, 2);
  assert.equal(countries.find((group) => group.label === "United States").endpointCount, 3);
  assert.equal(cities.length, 3);
  assert.deepEqual(cities.map((item) => item.label), ["Seattle", "Mountain View", "Frankfurt"]);
  const seattle = cities.find((item) => item.label === "Seattle");
  assert.equal(seattle.endpointCount, 2);
  assert.equal(seattle.packets, 160);
  assert.deepEqual(seattle.protocols, ["TCP", "TLS"]);
});

test("destination hierarchy preserves every IP without rendering a flat list", () => {
  const hierarchy = buildMapFlowHierarchy(flows);
  const northAmerica = hierarchy.find((group) => group.label === "North America");
  const unitedStates = northAmerica.countries.find((group) => group.label === "United States");
  const seattle = unitedStates.cities.find((group) => group.label === "Seattle");

  assert.equal(hierarchy.length, 2);
  assert.equal(northAmerica.endpointCount, 3);
  assert.equal(unitedStates.endpointCount, 3);
  assert.equal(seattle.endpointCount, 2);
  assert.deepEqual(seattle.members.map((flow) => flow.ip), ["1", "4"]);
});
