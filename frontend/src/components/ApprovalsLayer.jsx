import { useCallback, useEffect, useRef, useState } from "react";
import { describeRequestError, getPendingApprovals, resolveApproval } from "../api.js";
import { fixtureKind, fixtureMode, FIXTURE_PENDING } from "../fixtures.js";

const APPROVAL_POLL_MS = 2000;

function secondsLeft(entry, nowMs) {
  if (Number.isFinite(entry.created_ts) && Number.isFinite(entry.timeout_seconds)) {
    return ((entry.created_ts + entry.timeout_seconds) * 1000 - nowMs) / 1000;
  }
  return Number(entry.remaining_seconds) || 0;
}

function ApprovalsLayer({ setStatus }) {
  const [pending, setPending] = useState([]);
  const [journal, setJournal] = useState([]);
  const [approvalError, setApprovalError] = useState("");
  const [busyTid, setBusyTid] = useState(null);
  const intervalRef = useRef(null);
  const previous = useRef([]);
  const resolved = useRef(new Set());

  const refresh = useCallback(async () => {
    try {
      const result = fixtureMode()
        ? {
            pending:
              fixtureKind() === "1"
                ? FIXTURE_PENDING.filter((entry) => !resolved.current.has(entry.tid))
                : [],
          }
        : await getPendingApprovals();
      const next = (Array.isArray(result.pending) ? result.pending : []).filter(
        (entry) => !resolved.current.has(entry.tid),
      );
      const nextIds = new Set(next.map((entry) => entry.tid));
      const nowMs = Date.now();
      const departed = previous.current.filter(
        (entry) => !nextIds.has(entry.tid) && !resolved.current.has(entry.tid),
      );
      if (departed.length) {
        setJournal((current) =>
          [
            ...departed.map((entry) => ({
              tid: entry.tid,
              label: entry.label,
              status: secondsLeft(entry, nowMs) <= 0 ? "timed-out" : "left",
              onTimeout: entry.on_timeout,
              at: nowMs,
            })),
            ...current,
          ].slice(0, 6),
        );
      }
      previous.current = next;
      setPending(next);
      setApprovalError("");
    } catch (err) {
      setApprovalError(describeRequestError(err, "Could not load approval requests."));
    }
  }, []);

  useEffect(() => {
    refresh();
    intervalRef.current = window.setInterval(refresh, APPROVAL_POLL_MS);
    return () => {
      if (intervalRef.current) window.clearInterval(intervalRef.current);
    };
  }, [refresh]);

  // Local one-second clock so the countdown ticks smoothly between the slower
  // server polls. The deadline itself comes from the server (created_ts +
  // timeout_seconds), so the display stays accurate without drifting.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!pending.length) return undefined;
    const handle = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(handle);
  }, [pending.length]);

  async function decide(entry, decision) {
    setBusyTid(entry.tid);
    try {
      if (!fixtureMode()) await resolveApproval(entry.tid, decision);
      resolved.current.add(entry.tid);
      setPending((current) => current.filter((row) => row.tid !== entry.tid));
      previous.current = previous.current.filter((row) => row.tid !== entry.tid);
      setJournal((current) =>
        [{ tid: entry.tid, label: entry.label, status: "completed", decision, at: Date.now() }, ...current].slice(0, 6),
      );
      setStatus({ kind: "ok", text: `Turn ${entry.tid}: ${decision}` });
    } catch (err) {
      setJournal((current) =>
        [{ tid: entry.tid, label: entry.label, status: "failed", error: describeRequestError(err), at: Date.now() }, ...current].slice(0, 6),
      );
      setStatus({ kind: "error", text: describeRequestError(err) });
    } finally {
      setBusyTid(null);
    }
  }

  if (!pending.length && !journal.length && !approvalError) return null;
  return (
    <div className="approvals-layer">
      {approvalError ? (
        <div className="banner error" role="alert">
          <p>{approvalError}</p>
        </div>
      ) : null}
      {pending.map((entry) => {
        // Prefer a client-side deadline (created_ts + timeout_seconds) so the
        // countdown ticks every second. Fall back to the server's snapshot
        // value when the timing fields are missing.
        const hasDeadline =
          Number.isFinite(entry.created_ts) && Number.isFinite(entry.timeout_seconds);
        const deadlineMs = hasDeadline
          ? (entry.created_ts + entry.timeout_seconds) * 1000
          : null;
        const remaining = hasDeadline
          ? Math.max(0, Math.ceil((deadlineMs - now) / 1000))
          : Math.max(0, Number(entry.remaining_seconds) || 0);
        const urgent = remaining <= 10;
        const label = String(entry.label || "").trim();
        return (
          <div className="approval-card" key={entry.tid}>
            <div className="approval-header">
              <strong>Turn {entry.tid} needs a decision</strong>
              <span className="status-tag status-approval">Pending</span>
              <span className={urgent ? "approval-count urgent" : "approval-count"}>
                {remaining}s
              </span>
            </div>
            {label ? <p className="approval-action">{label}</p> : <p className="muted">No action preview provided.</p>}
            <div className="approval-actions">
              <button
                className="button secondary"
                type="button"
                disabled={busyTid === entry.tid}
                onClick={() => decide(entry, "deny")}
              >
                {entry.phase === "tool" ? "Block Tool Use" : "Deny"}
              </button>
              <button
                className="button primary"
                type="button"
                disabled={busyTid === entry.tid}
                onClick={() => decide(entry, "approve")}
              >
                {entry.phase === "tool" ? "Allow Tool Use" : "Approve"}
              </button>
            </div>
            <p className="approval-meta">
              {entry.phase ? <span className="approval-phase">{entry.phase}</span> : null}
              {entry.sid ? <span title={String(entry.sid)}>Session {String(entry.sid).length > 28 ? `${String(entry.sid).slice(0, 12)}…${String(entry.sid).slice(-6)}` : entry.sid}</span> : null}
              <span>If the deadline passes, the server applies {entry.on_timeout || "its timeout rule"}.</span>
            </p>
          </div>
        );
      })}
      {journal.map((entry) => (
        <div className={`approval-card journal journal-${entry.status}`} key={`${entry.tid}-${entry.at}`}>
          <div className="approval-header">
            <strong>Turn {entry.tid}</strong>
            <span className={`status-tag status-${entry.status}`}>
              {entry.status === "completed"
                ? `Completed · ${entry.decision}`
                : entry.status === "failed"
                  ? "Failed"
                  : entry.status === "timed-out"
                    ? "Timed out"
                    : "No longer pending"}
            </span>
          </div>
          {entry.label ? <p>{entry.label}</p> : null}
          {entry.status === "failed" ? <p>{entry.error}</p> : null}
          {entry.status === "timed-out" ? (
            <p>The deadline passed. The server applies {entry.onTimeout || "its timeout rule"}.</p>
          ) : null}
          {entry.status === "left" ? (
            <p>This request left the pending list. No timeout event was returned.</p>
          ) : null}
        </div>
      ))}
    </div>
  );
}

export { ApprovalsLayer };
