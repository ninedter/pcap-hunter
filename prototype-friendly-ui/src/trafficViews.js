export const trafficViewTools = [
  { label: "World map", target: "world-flow-map", dashboardView: null },
  { label: "Top 10 IPs & domains", target: "top-10-analysis", dashboardView: null },
  { label: "Sankey flow", target: "sankey-flow", dashboardView: "paths" },
  { label: "Network graph", target: "network-graph", dashboardView: "network" },
  { label: "Attack timeline", target: "attack-timeline", dashboardView: "timeline" },
  { label: "Packet size histogram", target: "packet-size-histogram", dashboardView: "profile" },
  { label: "Inter-arrival histogram", target: "inter-arrival-histogram", dashboardView: "profile" },
  { label: "Traffic heatmap", target: "traffic-heatmap", dashboardView: "profile" },
];

export function getTrafficViewTool(target) {
  return trafficViewTools.find((tool) => tool.target === target) || null;
}

export function getDashboardViewForTarget(target) {
  return getTrafficViewTool(target)?.dashboardView || "paths";
}
