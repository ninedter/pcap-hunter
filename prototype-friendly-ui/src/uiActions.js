function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

export function buildIocCsv(rows = []) {
  const header = ["value", "type", "context", "status", "source"];
  return [
    header.join(","),
    ...rows.map((row) => header.map((key) => csvCell(row[key])).join(",")),
  ].join("\n");
}

export function isPrivateAddress(value = "") {
  const parts = String(value).split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second] = parts;
  return first === 10
    || first === 127
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168)
    || (first === 100 && second >= 64 && second <= 127);
}

export function getDashboardChartExport(view, data = {}) {
  const definitions = {
    paths: ["sankey-flow", data.sankey || { nodes: [], links: [] }],
    network: ["network-graph", data.network || []],
    profile: ["traffic-profile", {
      packet_sizes: data.packet_sizes || [],
      inter_arrivals: data.inter_arrivals || [],
      heatmap: data.heatmap || [],
    }],
    timeline: ["attack-timeline", data.attack_timeline || []],
  };
  const [name, visualization] = definitions[view] || definitions.paths;
  return {
    filename: `pcap-hunter-${name}.json`,
    content: JSON.stringify({ visualization: name, data: visualization }, null, 2),
  };
}

export function buildAttackNavigatorLayer(mapping = {}, metadata = {}) {
  const techniques = Array.isArray(mapping.techniques) ? mapping.techniques : [];
  return {
    name: "PCAP Hunter network hypotheses",
    versions: { navigator: "5.1.0", layer: "4.5" },
    domain: "enterprise-attack",
    description: "Network-derived ATT&CK hypotheses. Validate with endpoint telemetry before confirming a technique.",
    filters: { platforms: ["Network Devices"] },
    sorting: 3,
    layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregateScores: true },
    hideDisabled: false,
    techniques: techniques.map((item) => {
      const confidence = Number(item.confidence ?? item.score ?? 0);
      const score = Math.round(confidence <= 1 ? confidence * 100 : confidence);
      return {
        techniqueID: item.technique_id || item.id,
        score,
        color: score >= 80 ? "#ff8d8d" : score >= 50 ? "#ffd37a" : "#d8e9f7",
        comment: [...(item.evidence || []), ...(item.limitations || []).map((value) => `Limitation: ${value}`)].join("\n"),
        enabled: true,
        metadata: [
          { name: "Tactic", value: item.tactic || item.tactic_name || "Unspecified" },
          { name: "Disposition", value: item.disposition || "unreviewed" },
        ],
      };
    }).filter((item) => item.techniqueID),
    metadata: [
      { name: "Case", value: metadata.caseId || "Active analysis" },
      { name: "Analysis", value: metadata.analysisId || "Current" },
    ],
    gradient: { colors: ["#d8e9f7", "#ffd37a", "#ff8d8d"], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: "Lower confidence", color: "#d8e9f7" },
      { label: "Medium confidence", color: "#ffd37a" },
      { label: "High confidence", color: "#ff8d8d" },
    ],
    showTacticRowBackground: false,
    tacticRowBackground: "#dddddd",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  };
}
