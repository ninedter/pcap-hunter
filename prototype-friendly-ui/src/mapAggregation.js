const COUNTRY_CONTINENTS = new Map([
  ["Australia", "Oceania"],
  ["Brazil", "South America"],
  ["Canada", "North America"],
  ["China", "Asia"],
  ["France", "Europe"],
  ["Germany", "Europe"],
  ["India", "Asia"],
  ["Indonesia", "Asia"],
  ["Ireland", "Europe"],
  ["Japan", "Asia"],
  ["Mexico", "North America"],
  ["Netherlands", "Europe"],
  ["New Zealand", "Oceania"],
  ["Russia", "Europe"],
  ["Singapore", "Asia"],
  ["South Africa", "Africa"],
  ["South Korea", "Asia"],
  ["Taiwan", "Asia"],
  ["United Kingdom", "Europe"],
  ["United States", "North America"],
]);

function flowCoordinates(flow) {
  const coordinates = Array.isArray(flow?.coordinates) ? flow.coordinates : [0, 0];
  return [Number(coordinates[0]) || 0, Number(coordinates[1]) || 0];
}

export function inferFlowContinent(flow) {
  if (flow?.continent && flow.continent !== "Unknown") return flow.continent;
  if (COUNTRY_CONTINENTS.has(flow?.country)) return COUNTRY_CONTINENTS.get(flow.country);

  const [longitude, latitude] = flowCoordinates(flow);
  if (longitude >= 110 && latitude < 0) return "Oceania";
  if (longitude >= 25 && latitude >= 0) return "Asia";
  if (longitude >= -30 && longitude < 60 && latitude >= 34) return "Europe";
  if (longitude >= -25 && longitude < 60 && latitude < 34) return "Africa";
  if (longitude < -30 && latitude < 12) return "South America";
  if (longitude < -30) return "North America";
  return "Other regions";
}

export function getMapAggregationLevel(zoom) {
  if (zoom < 1.65) return "continent";
  if (zoom < 2.75) return "country";
  return "city";
}

export function getMapAggregationLabel(level) {
  if (level === "continent") return "Grouped by continent";
  if (level === "country") return "Grouped by country";
  return "Grouped by city";
}

export function getNextMapZoom(level) {
  if (level === "continent") return 1.9;
  if (level === "country") return 3.05;
  return 3.05;
}

function weightedGeographicCenter(flows) {
  const vector = flows.reduce((total, flow) => {
    const [longitude, latitude] = flowCoordinates(flow);
    const longitudeRadians = longitude * Math.PI / 180;
    const latitudeRadians = latitude * Math.PI / 180;
    const weight = Math.max(1, Math.sqrt(Number(flow.packets) || 1));
    total.x += Math.cos(latitudeRadians) * Math.cos(longitudeRadians) * weight;
    total.y += Math.cos(latitudeRadians) * Math.sin(longitudeRadians) * weight;
    total.z += Math.sin(latitudeRadians) * weight;
    return total;
  }, { x: 0, y: 0, z: 0 });

  const longitude = Math.atan2(vector.y, vector.x) * 180 / Math.PI;
  const hypotenuse = Math.sqrt(vector.x ** 2 + vector.y ** 2);
  const latitude = Math.atan2(vector.z, hypotenuse) * 180 / Math.PI;
  return [longitude, latitude];
}

export const MAP_ASSESSMENT_COLORS = {
  Review: "#ffbd59",
  Expected: "#47a8ff",
  "Not assessed": "#8b96aa",
  "Partly assessed": "#8b96aa",
};

/**
 * Assessment of one destination: "Review" | "Expected" | "Not assessed".
 *
 * `status` only says the score was low; it reads "Expected" even when no
 * reputation provider answered. Newer payloads add `assessed`/`assessment`.
 * Payloads saved before those fields existed keep the old two-way reading.
 */
export function getFlowAssessment(flow) {
  if (flow?.status === "Review" || flow?.assessment === "Review") return "Review";
  if (typeof flow?.assessed === "boolean") return flow.assessed ? "Expected" : "Not assessed";
  if (flow?.assessment === "Expected" || flow?.assessment === "Not assessed") return flow.assessment;
  return "Expected";
}

/**
 * Assessment of a group of destinations. "Review" wins; "Expected" requires
 * every member to be assessed and expected; otherwise the group is
 * "Not assessed" (none assessed) or "Partly assessed" (some assessed).
 */
export function summarizeGroupAssessment(members) {
  const assessments = (members || []).map(getFlowAssessment);
  const assessedCount = assessments.filter((item) => item !== "Not assessed").length;
  const reviewCount = assessments.filter((item) => item === "Review").length;
  let assessment = "Not assessed";
  if (reviewCount) assessment = "Review";
  else if (assessments.length && assessedCount === assessments.length) assessment = "Expected";
  else if (assessedCount) assessment = "Partly assessed";
  return { assessment, assessedCount, reviewCount, color: MAP_ASSESSMENT_COLORS[assessment] };
}

/** Marker/arc colour for a single destination. */
export function getFlowAssessmentColor(flow) {
  return MAP_ASSESSMENT_COLORS[getFlowAssessment(flow)];
}

export function aggregateMapFlows(flows, level) {
  const grouped = new Map();
  for (const flow of flows) {
    const continent = inferFlowContinent(flow);
    const [longitude, latitude] = flowCoordinates(flow);
    const unknownCountryCell = `Unknown near ${Math.round(latitude / 15) * 15}, ${Math.round(longitude / 15) * 15}`;
    const country = flow.country && flow.country !== "Unknown" ? flow.country : unknownCountryCell;
    const hasKnownCity = flow.city && flow.city !== "Unknown";
    const cityCell = `${Math.round(latitude / 2) * 2},${Math.round(longitude / 2) * 2}`;
    const label = level === "continent" ? continent : level === "country" ? country : (hasKnownCity ? flow.city : "Unknown city");
    const key = level === "city" ? `${level}:${country}:${hasKnownCity ? flow.city : cityCell}` : `${level}:${label}`;
    if (!grouped.has(key)) grouped.set(key, { key, label, members: [] });
    grouped.get(key).members.push(flow);
  }

  return Array.from(grouped.values()).map((group) => {
    const packets = group.members.reduce((sum, flow) => sum + (Number(flow.packets) || 0), 0);
    const protocols = Array.from(new Set(group.members.flatMap((flow) => flow.protocols || []))).sort();
    const countries = new Set(group.members.map((flow) => flow.country).filter((country) => country && country !== "Unknown"));
    // `status` keeps its two historical values; `assessment` is what the map shows.
    const status = group.members.some((flow) => flow.status === "Review") ? "Review" : "Expected";
    const { assessment, assessedCount, color } = summarizeGroupAssessment(group.members);
    const primaryFlow = [...group.members].sort((left, right) => (Number(right.packets) || 0) - (Number(left.packets) || 0))[0];
    return {
      ...group,
      coordinates: weightedGeographicCenter(group.members),
      packets,
      protocols,
      status,
      assessment,
      assessedCount,
      color,
      endpointCount: group.members.length,
      countryCount: countries.size,
      primaryFlow,
    };
  }).sort((left, right) => right.packets - left.packets);
}

export function buildMapFlowHierarchy(flows) {
  return aggregateMapFlows(flows, "continent").map((continent) => ({
    ...continent,
    countries: aggregateMapFlows(continent.members, "country").map((country) => ({
      ...country,
      cities: aggregateMapFlows(country.members, "city"),
    })),
  }));
}
