import assert from "node:assert/strict";
import test from "node:test";

import { MAP_ASSESSMENT_COLORS, aggregateMapFlows, buildMapFlowHierarchy, getFlowAssessment, getFlowAssessmentColor, getMapAggregationLevel, summarizeGroupAssessment } from "../src/mapAggregation.js";

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

// Shape produced by _map_flows in app/web/state.py once assessed/assessment exist.
const assessedFlow = (ip, city, overrides = {}) => ({
  ip, city, country: "United States", continent: "North America", coordinates: [-122.3, 47.6], packets: 10, byte_count: 2048, bytes: "2 KB",
  protocols: ["TCP"], traffic_slices: [], status: "Expected", color: "#47a8ff", assessed: true, assessment: "Expected", ...overrides,
});
const unassessed = { assessed: false, assessment: "Not assessed" };
const review = { status: "Review", color: "#ffbd59", assessed: true, assessment: "Review" };

test("a single destination reads Review, Expected, or Not assessed", () => {
  assert.equal(getFlowAssessment(assessedFlow("1", "Seattle")), "Expected");
  assert.equal(getFlowAssessment(assessedFlow("1", "Seattle", unassessed)), "Not assessed");
  assert.equal(getFlowAssessment(assessedFlow("1", "Seattle", review)), "Review");
  // A high score is a Review even if no provider key marked it assessed.
  assert.equal(getFlowAssessment(assessedFlow("1", "Seattle", { status: "Review", assessed: false, assessment: "Review" })), "Review");
  assert.equal(getFlowAssessmentColor(assessedFlow("1", "Seattle", unassessed)), MAP_ASSESSMENT_COLORS["Not assessed"]);
  assert.notEqual(MAP_ASSESSMENT_COLORS["Not assessed"], MAP_ASSESSMENT_COLORS.Expected);
});

test("older payloads without assessment fields keep the two-way reading", () => {
  assert.equal(getFlowAssessment({ status: "Expected" }), "Expected");
  assert.equal(getFlowAssessment({ status: "Review" }), "Review");
  assert.equal(getFlowAssessment({}), "Expected");
  // The legacy fixture at the top of this file has no assessed/assessment fields.
  const groups = aggregateMapFlows(flows, "country");
  assert.equal(groups.find((group) => group.label === "Germany").assessment, "Expected");
  assert.equal(groups.find((group) => group.label === "Germany").color, "#47a8ff");
  assert.equal(groups.find((group) => group.label === "United States").assessment, "Review");
  assert.equal(groups.find((group) => group.label === "United States").color, "#ffbd59");
});

test("group assessment: Review first, Expected only when every member is assessed", () => {
  const allExpected = [assessedFlow("1", "Seattle"), assessedFlow("2", "Seattle")];
  const noneAssessed = [assessedFlow("1", "Seattle", unassessed), assessedFlow("2", "Seattle", unassessed)];
  const mixed = [assessedFlow("1", "Seattle"), assessedFlow("2", "Seattle", unassessed)];
  const withReview = [...mixed, assessedFlow("3", "Seattle", review)];

  assert.equal(summarizeGroupAssessment(allExpected).assessment, "Expected");
  assert.equal(summarizeGroupAssessment(noneAssessed).assessment, "Not assessed");
  assert.equal(summarizeGroupAssessment(mixed).assessment, "Partly assessed");
  assert.equal(summarizeGroupAssessment(withReview).assessment, "Review");
  assert.equal(summarizeGroupAssessment([]).assessment, "Not assessed");
  assert.deepEqual(
    { assessed: summarizeGroupAssessment(withReview).assessedCount, review: summarizeGroupAssessment(withReview).reviewCount },
    { assessed: 2, review: 1 },
  );
});

test("aggregated groups carry the assessment and a neutral colour when unverified", () => {
  const [mixedCity] = aggregateMapFlows([assessedFlow("1", "Seattle"), assessedFlow("2", "Seattle", unassessed)], "city");
  assert.equal(mixedCity.assessment, "Partly assessed");
  assert.equal(mixedCity.assessedCount, 1);
  assert.equal(mixedCity.color, MAP_ASSESSMENT_COLORS["Partly assessed"]);
  // `status` keeps its historical two values for existing consumers.
  assert.equal(mixedCity.status, "Expected");

  const [unassessedCity] = aggregateMapFlows([assessedFlow("1", "Seattle", unassessed)], "city");
  assert.equal(unassessedCity.assessment, "Not assessed");
  assert.equal(unassessedCity.color, "#8b96aa");

  const hierarchy = buildMapFlowHierarchy([assessedFlow("1", "Seattle"), assessedFlow("2", "Portland", unassessed), assessedFlow("3", "Denver", review)]);
  assert.equal(hierarchy[0].assessment, "Review");
  const cities = hierarchy[0].countries[0].cities;
  assert.deepEqual(Object.fromEntries(cities.map((city) => [city.label, city.assessment])), { Seattle: "Expected", Portland: "Not assessed", Denver: "Review" });
});
