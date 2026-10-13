import { useEffect, useRef } from "react";
import { VerdictMark } from "./ui.jsx";
import { DecisionView } from "./DecisionView.jsx";
import { formatClock, groupSessions } from "../traceUtils.js";

function TraceWorkspace({
  traces,
  activeTid,
  activeTrace,
  sessionKey,
  onSelectSession,
  onSelectTurn,
  earlier,
  redact,
  loading,
  error,
  onRetry,
  detailLoading,
}) {
  const selectedRef = useRef(null);
  const sessions = groupSessions(traces);
  const session = sessions.find((item) => item.key === sessionKey) || sessions[0];

  useEffect(() => {
    selectedRef.current?.scrollIntoView({ block: "nearest" });
  }, [activeTid, sessionKey]);

  return (
    <div className="trace-workspace">
      <div className="session-column">
        <div className="session-head">
          <h2>Sessions</h2>
          {loading ? <span className="muted">Loading</span> : null}
        </div>
        {error ? (
          <div className="banner error" role="alert">
            <p>{error}</p>
            {onRetry ? (
              <button className="button secondary" type="button" onClick={onRetry}>
                Retry
              </button>
            ) : null}
          </div>
        ) : null}
        {!traces.length && loading ? (
          <div className="skeleton" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
        ) : null}
        {!traces.length && !loading ? (
          <div className="empty-state">
            <h3>No session yet</h3>
            <p>When an agent calls AgentEnf, its turns appear here in time order.</p>
          </div>
        ) : null}
        <div className="session-list" role="listbox" aria-label="Sessions">
          {sessions.map((item) => (
            <button
              key={item.key}
              type="button"
              className={session?.key === item.key ? "session-button active" : "session-button"}
              onClick={() => onSelectSession(item.key)}
              aria-selected={session?.key === item.key}
              title={item.id || "Session not recorded"}
            >
              <strong>{item.id ? (item.id.length > 28 ? `${item.id.slice(0, 16)}…` : item.id) : "Session not recorded"}</strong>
              <span>{item.turns.length} turn{item.turns.length === 1 ? "" : "s"}</span>
            </button>
          ))}
        </div>
        {session ? (
          <ol className="turn-list">
            {session.turns.map((turn) => {
              const selected = turn.tid === activeTid;
              const fired = Array.isArray(turn.fired_predicates) ? turn.fired_predicates : [];
              const afterTool = String(turn.action || "").startsWith("tool_result");
              const summary = afterTool
                ? "Logged after the tool ran"
                : fired.length
                  ? fired.slice(0, 2).join(", ")
                  : "No matched predicate reported";
              return (
                <li key={`${turn.tid}:${turn.ts}`}>
                  <button
                    type="button"
                    ref={selected ? selectedRef : null}
                    className={selected ? "turn-button active" : "turn-button"}
                    onClick={() => onSelectTurn(turn.tid)}
                  >
                    <VerdictMark action={turn.action} size={16} />
                    <span className="turn-copy">
                      <strong>{turn.tool_name || `Turn ${turn.tid}`}</strong>
                      <span>{summary}</span>
                    </span>
                    <time>{formatClock(turn.ts) || `${turn.wall_ms || 0} ms`}</time>
                  </button>
                </li>
              );
            })}
          </ol>
        ) : null}
      </div>
      <div className="decision-column">
        {detailLoading && !activeTrace ? (
          <div className="skeleton" aria-hidden="true">
            <span />
            <span />
          </div>
        ) : null}
        {activeTrace ? (
          <DecisionView trace={activeTrace} earlier={earlier} redact={redact} />
        ) : !detailLoading ? (
          <div className="empty-state">
            <h3>Select a turn</h3>
            <p>The decision, predicate scores, and events for that turn open here.</p>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export { TraceWorkspace };
