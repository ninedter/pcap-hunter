export const PIPELINE_STAGES = [
  "Packet counting",
  "Packet parsing",
  "Zeek processing",
  "DNS analysis",
  "TLS certificates",
  "Beaconing",
  "HTTP carving",
  "YARA scanning",
  "OSINT enrichment",
  "LLM report",
];

const STAGE_PATTERNS = [
  /packet count/i,
  /parsing packets|packet parsing|pyshark/i,
  /zeek/i,
  /dns/i,
  /tls|certificate/i,
  /beacon/i,
  /http|carv/i,
  /yara/i,
  /osint/i,
  /llm|threat narrative|report/i,
];

const clampPercent = (value) => Math.max(0, Math.min(Number(value) || 0, 100));

export function pipelineStageIndex(title) {
  const normalized = String(title || "").trim();
  return normalized ? STAGE_PATTERNS.findIndex((pattern) => pattern.test(normalized)) : -1;
}

export function normalizeJobProgress(job) {
  const totalStages = Math.max(Number(job.total_stages) || PIPELINE_STAGES.length, 1);
  if (job.status === "done") {
    return {
      activeStageIndex: -1,
      completedStages: totalStages,
      displayStage: "Complete",
      overallProgress: 100,
      stageProgress: 100,
    };
  }

  const activeStageIndex = pipelineStageIndex(job.stage);
  const recordedCompleted = Math.max(Number(job.completed_stages) || 0, 0);
  const completedStages = Math.min(
    Math.max(recordedCompleted, activeStageIndex >= 0 ? activeStageIndex : 0),
    totalStages,
  );
  const stageProgress = job.status === "running" ? clampPercent(job.stage_progress) : 0;
  const fractionalCompleted = completedStages + (job.status === "running" ? stageProgress / 100 : 0);
  const overallProgress = Math.floor(Math.min(fractionalCompleted / totalStages, 1) * 100);

  return {
    activeStageIndex,
    completedStages,
    displayStage: activeStageIndex >= 0 ? PIPELINE_STAGES[activeStageIndex] : job.stage || job.status,
    overallProgress,
    stageProgress,
  };
}
