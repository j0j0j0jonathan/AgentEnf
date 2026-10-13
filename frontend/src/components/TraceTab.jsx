import { useCallback, useEffect, useMemo, useState } from "react";
import { describeRequestError, getTrace, listTraces } from "../api.js";
import { fixtureKind, fixtureList, fixtureMode, fixtureTrace } from "../fixtures.js";
import { enforcerEventLog, eventsInOrder, formatClock, groupSessions, sessionIdOf } from "../traceUtils.js";
import { FixtureNotice } from "./ui.jsx";
import { TraceWorkspace } from "./TraceWorkspace.jsx";

function loadTraceList() {
  const kind = fixtureKind();
  if (kind === "error") return Promise.reject(new TypeError("Failed to fetch"));
  if (kind === "empty") return Promise.resolve({ traces: [] });
  if (kind === "1") return Promise.resolve(fixtureList());
  return listTraces(50);
}

function loadTraceDetail(tid) {
  return fixtureMode() ? Promise.resolve(fixtureTrace(tid)) : getTrace(tid);
}

function TraceTab() {
  const [traceList, setTraceList] = useState([]);
  const [activeTid, setActiveTid] = useState(
    () => Number(new URLSearchParams(window.location.search).get("turn")) || null,
  );
  const [sessionKey, setSessionKey] = useState("");
  const [activeTrace, setActiveTrace] = useState(null);
  const [detailCache, setDetailCache] = useState({});
  const [error, setError] = useState("");
  const [redact, setRedact] = useState(true);
  const [loadingList, setLoadingList] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);

  const refreshList = useCallback(async () => {
    setLoadingList(true);
    try {
      const result = await loadTraceList();
      const list = Array.isArray(result.traces) ? result.traces : [];
      setTraceList(list);
      setError("");
      if (!sessionKey && list[0]) {
        const chosen = list.find((item) => item.tid === activeTid) || list[0];
        setSessionKey(sessionIdOf(chosen) || "__unscoped__");
        if (activeTid == null) setActiveTid(chosen.tid);
      }
    } catch (err) {
      setError(describeRequestError(err, "Could not load traces."));
    } finally {
      setLoadingList(false);
    }
  }, [sessionKey]);

  useEffect(() => {
    refreshList();
  }, [refreshList]);

  const sessions = useMemo(() => groupSessions(traceList), [traceList]);
  const activeSession = sessions.find((item) => item.key === sessionKey) || sessions[0];
  const sessionTurns = activeSession?.turns || [];

  useEffect(() => {
    if (activeTid == null) return;
    if (sessionTurns.some((turn) => turn.tid === activeTid)) return;
    setActiveTid(sessionTurns.at(-1)?.tid ?? null);
    setActiveTrace(null);
  }, [activeTid, sessionTurns]);

  useEffect(() => {
    if (activeTid == null) {
      setActiveTrace(null);
      return undefined;
    }
    let cancelled = false;
    setDetailLoading(true);
    loadTraceDetail(activeTid)
      .then((result) => {
        if (cancelled) return;
        setActiveTrace(result);
        if (result) setDetailCache((current) => ({ ...current, [activeTid]: result }));
      })
      .catch((err) => {
        if (!cancelled) setError(describeRequestError(err, "Could not load this turn."));
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeTid]);

  const earlier = useMemo(() => {
    const index = sessionTurns.findIndex((turn) => turn.tid === activeTid);
    if (index <= 0) return [];
    return sessionTurns.slice(0, index).map((turn) => ({
      tid: turn.tid,
      action: turn.action,
      toolName: turn.tool_name || "",
      time: formatClock(turn.ts),
      log: detailCache[turn.tid] ? enforcerEventLog(detailCache[turn.tid]) : [],
      steps: detailCache[turn.tid] ? eventsInOrder(detailCache[turn.tid]) : [],
    }));
  }, [sessionTurns, activeTid, detailCache]);

  function selectSession(key) {
    setSessionKey(key);
    const group = sessions.find((item) => item.key === key);
    setActiveTid(group?.turns.at(-1)?.tid ?? null);
  }

  return (
    <section className="trace-tab">
      <FixtureNotice />
      <div className="trace-tab-bar">
        <h2>Trace</h2>
        <button
          type="button"
          className={`chip-btn${redact ? " on" : ""}`}
          onClick={() => setRedact((value) => !value)}
        >
          {redact ? "Content hidden" : "Content shown"}
        </button>
        <button className="button secondary" type="button" onClick={refreshList}>
          Refresh
        </button>
      </div>
      <TraceWorkspace
        traces={traceList}
        activeTid={activeTid}
        activeTrace={activeTrace}
        sessionKey={activeSession?.key || ""}
        onSelectSession={selectSession}
        onSelectTurn={setActiveTid}
        earlier={earlier}
        redact={redact}
        loading={loadingList}
        error={error}
        onRetry={refreshList}
        detailLoading={detailLoading}
      />
    </section>
  );
}

export { TraceTab };
