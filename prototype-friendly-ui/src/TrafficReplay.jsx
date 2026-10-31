import { useEffect, useMemo, useState } from "react";
import { filterTrafficReplayEvents, formatExactReplayTimestamp, formatReplayBytes, formatReplayTime, getReplayMarkerIndexes, getReplayPlaybackPlan, getReplayTimelinePositions, getTrafficReplayCoverage, getTrafficReplayControlState, normalizeTrafficReplayEvents } from "./trafficReplay.js";
import "./trafficReplay.css";

const speeds = [0.5, 1, 2, 4];

export function TrafficReplay({ replay, communications = [], filters = {}, onFilterChange }) {
  const events = useMemo(() => normalizeTrafficReplayEvents(replay?.events ?? communications), [replay, communications]);
  const visibleEvents = useMemo(() => filterTrafficReplayEvents(events, filters), [events, filters]);
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [zoom, setZoom] = useState(1);
  const [grid, setGrid] = useState(true);
  const [hovered, setHovered] = useState(null);
  const [reducedMotion, setReducedMotion] = useState(false);
  const selected = visibleEvents[Math.min(cursor, Math.max(visibleEvents.length - 1, 0))];
  const protocols = [...new Set(events.map((event) => event.protocol))].sort();
  const markerIndexes = useMemo(() => new Set(getReplayMarkerIndexes(visibleEvents.length, cursor)), [visibleEvents.length, cursor]);
  const timelinePositions = useMemo(() => getReplayTimelinePositions(visibleEvents), [visibleEvents]);
  const playbackPlan = useMemo(() => getReplayPlaybackPlan(visibleEvents.length, speed), [visibleEvents.length, speed]);
  const controls = getTrafficReplayControlState({ visibleEventCount: visibleEvents.length, protocolCount: protocols.length, cursor, playing, speed, zoom, grid });

  useEffect(() => { setCursor((value) => Math.min(value, Math.max(visibleEvents.length - 1, 0))); }, [visibleEvents.length]);
  useEffect(() => {
    const media = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    const update = () => { const nextReducedMotion = Boolean(media?.matches); setReducedMotion(nextReducedMotion); if (nextReducedMotion) setPlaying(false); };
    update(); media?.addEventListener?.("change", update); return () => media?.removeEventListener?.("change", update);
  }, []);
  useEffect(() => {
    if (!playing || reducedMotion || visibleEvents.length < 2) return undefined;
    const timer = window.setInterval(() => setCursor((value) => (value + playbackPlan.stepSize) % visibleEvents.length), playbackPlan.cadenceMs);
    return () => window.clearInterval(timer);
  }, [playing, reducedMotion, visibleEvents.length, playbackPlan]);

  const choose = (index) => { setCursor(index); setPlaying(false); };
  const active = hovered ?? selected;
  const setProtocol = (protocol) => onFilterChange?.({ ...filters, protocol: protocol === "All" ? "" : protocol });
  const reset = () => { setCursor(0); setPlaying(false); setSpeed(1); setZoom(1); setGrid(true); };
  const onTimelineKeyDown = (event) => {
    if (event.key === "ArrowLeft") { event.preventDefault(); choose(Math.max(cursor - 1, 0)); }
    if (event.key === "ArrowRight") { event.preventDefault(); choose(Math.min(cursor + 1, visibleEvents.length - 1)); }
    if (event.key === " ") { event.preventDefault(); if (!reducedMotion) setPlaying((value) => !value); }
  };

  return <section className="traffic-replay" aria-label="Chronological communication replay">
    <header className="traffic-replay__head"><div><h2>Communication replay</h2><p>Compressed chronological timeline of sampled traffic. Endpoint lanes reflect parser-supplied address scope.</p></div><span className="traffic-replay__coverage" aria-live="polite">{getTrafficReplayCoverage(replay, visibleEvents.length)}</span></header>
    <div className="traffic-replay__controls" aria-label="Replay controls">
      <button type="button" onClick={() => setPlaying((value) => !value)} disabled={!visibleEvents.length || reducedMotion} aria-pressed={playing}>{playing ? "Pause" : "Play"}</button>
      <button type="button" onClick={() => choose(Math.max(cursor - 1, 0))} disabled={!visibleEvents.length || cursor === 0}>Previous</button>
      <button type="button" onClick={() => choose(Math.min(cursor + 1, visibleEvents.length - 1))} disabled={!visibleEvents.length || cursor >= visibleEvents.length - 1}>Next</button>
      <label>Speed <select value={speed} onChange={(event) => setSpeed(Number(event.target.value))} disabled={!controls.canChangeSpeed}>{speeds.map((value) => <option value={value} key={value}>{value}×</option>)}</select></label>
      <button type="button" onClick={() => setZoom((value) => Math.max(0.75, value - 0.25))} disabled={!controls.canZoomOut} aria-label="Zoom out">−</button><button type="button" onClick={() => setZoom((value) => Math.min(2, value + 0.25))} disabled={!controls.canZoomIn} aria-label="Zoom in">+</button><button type="button" onClick={() => setZoom(1)} disabled={!controls.canFit}>Fit</button>
      <button type="button" onClick={() => setGrid((value) => !value)} disabled={!controls.canToggleGrid} aria-pressed={grid}>Grid</button><button type="button" onClick={reset} disabled={!controls.canRestart}>Restart</button>
      <label className="traffic-replay__filter">Protocol <select value={filters.protocol || "All"} onChange={(event) => setProtocol(event.target.value)} disabled={!controls.canChangeProtocol}><option>All</option>{protocols.map((protocol) => <option key={protocol}>{protocol}</option>)}</select></label>
    </div>
    {reducedMotion && <p className="traffic-replay__motion-note">Reduced motion is enabled; playback remains paused.</p>}
    {!visibleEvents.length ? <div className="traffic-replay__empty" role="status">No replay events match the active filters.</div> : <>
      <div className={`traffic-replay__flow ${grid ? "is-grid" : ""}`} aria-label={`Selected communication path from ${selected.source_address} to ${selected.destination_address}`}>
        <div className="traffic-replay__flow-kicker">Selected sampled communication · parser-supplied scope lanes</div>
        <svg viewBox="0 0 1000 250" role="img" aria-label={`${selected.source_address} port ${selected.source_port ?? "unknown"} to ${selected.destination_address} port ${selected.destination_port ?? "unknown"}, ${selected.protocol}`}>
          <defs><marker id="traffic-replay-arrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" /></marker></defs>
          {["internal", "external", "special"].map((lane, index) => <g key={lane}><text x="35" y={45 + index * 82} className="traffic-replay__svg-lane">{lane}</text><line x1="155" y1={40 + index * 82} x2="960" y2={40 + index * 82} className="traffic-replay__svg-lane-line" /></g>)}
          <path d={`M220 ${40 + ["internal", "external", "special"].indexOf(selected.sourceLane) * 82} C 450 ${40 + ["internal", "external", "special"].indexOf(selected.sourceLane) * 82}, 590 ${40 + ["internal", "external", "special"].indexOf(selected.destinationLane) * 82}, 820 ${40 + ["internal", "external", "special"].indexOf(selected.destinationLane) * 82}`} className="traffic-replay__connector" markerEnd="url(#traffic-replay-arrow)" />
          <circle cx="220" cy={40 + ["internal", "external", "special"].indexOf(selected.sourceLane) * 82} r="15" className="traffic-replay__endpoint source" /><circle cx="820" cy={40 + ["internal", "external", "special"].indexOf(selected.destinationLane) * 82} r="15" className="traffic-replay__endpoint destination" />
          <circle cx="220" cy={40 + ["internal", "external", "special"].indexOf(selected.sourceLane) * 82} r="7" className={`traffic-replay__pulse ${playing && !reducedMotion ? "is-playing" : ""}`}><animateMotion dur={`${1 / speed}s`} repeatCount={playing && !reducedMotion ? "indefinite" : "0"} path={`M0 0 C 230 0, 370 ${["internal", "external", "special"].indexOf(selected.destinationLane) * 82 - ["internal", "external", "special"].indexOf(selected.sourceLane) * 82}, 600 ${["internal", "external", "special"].indexOf(selected.destinationLane) * 82 - ["internal", "external", "special"].indexOf(selected.sourceLane) * 82}`} /></circle>
          <text x="220" y={30 + ["internal", "external", "special"].indexOf(selected.sourceLane) * 82} textAnchor="middle" className="traffic-replay__endpoint-label">{selected.source_address}:{selected.source_port ?? "—"}</text><text x="820" y={30 + ["internal", "external", "special"].indexOf(selected.destinationLane) * 82} textAnchor="middle" className="traffic-replay__endpoint-label">{selected.destination_address}:{selected.destination_port ?? "—"}</text>
          <text x="520" y="232" textAnchor="middle" className="traffic-replay__protocol-label">{selected.protocol} · {formatReplayBytes(selected.bytes)} · {selected.packets.toLocaleString()} packet{selected.packets === 1 ? "" : "s"}</text>
        </svg>
      </div>
      <div className="traffic-replay__timeline-label">Compressed chronological timeline · select a dot to seek</div>
      <div className="traffic-replay__timeline-scroll"><div className={`traffic-replay__stage ${grid ? "is-grid" : ""}`} style={{ width: `${zoom * 100}%` }} role="list" tabIndex="0" onKeyDown={onTimelineKeyDown} aria-label={`${visibleEvents.length} chronological communication events. Use left and right arrows to step; space plays or pauses.`}>
        {["internal", "external", "special"].map((lane) => <div className="traffic-replay__lane" key={lane}><strong>{lane === "internal" ? "Internal addresses" : lane === "external" ? "External addresses" : "Group / special / unknown addresses"}</strong><div className="traffic-replay__track">{visibleEvents.map((event, index) => event.lane === lane && markerIndexes.has(index) && <button key={event.id} type="button" className={`traffic-replay__event ${index === cursor ? "is-selected" : ""}`} style={{ "--event-position": `${timelinePositions[index]}%` }} onClick={() => choose(index)} onMouseEnter={() => setHovered(event)} onMouseLeave={() => setHovered(null)} aria-label={`${formatReplayTime(event)}: ${event.source_address} port ${event.source_port ?? "unknown"} to ${event.destination_address} port ${event.destination_port ?? "unknown"}, ${event.protocol}`}><span /></button>)}</div></div>)}
      </div></div>
      <div className="traffic-replay__detail" aria-live={playing ? "off" : "polite"}><strong title={formatReplayTime(active)}>{formatExactReplayTimestamp(active)}</strong><span>{active.source_address}:{active.source_port ?? "—"} ({active.sourceLane}) → {active.destination_address}:{active.destination_port ?? "—"} ({active.destinationLane})</span><span>{active.protocol}{active.transport && active.transport !== active.protocol ? ` · ${active.transport}` : ""} · {formatReplayBytes(active.bytes)} · {active.packets.toLocaleString()} packet{active.packets === 1 ? "" : "s"}</span><code>Flow {active.flow_id}</code></div>
    </>}
  </section>;
}

export default TrafficReplay;
