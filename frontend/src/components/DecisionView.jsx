import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { describeRequestError, overrideJudgeResult } from "../api.js";
import { fixtureMode } from "../fixtures.js";
import { VerdictMark } from "./ui.jsx";
import {
  classifierAccount,
  decisionAccount,
  enforcerEventLog,
  formatClock,
  phaseLabel,
  phaseTimingLabel,
  predicateMatched,
  shortText,
} from "../traceUtils.js";

function CopyButton({ value, disabled = false }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (disabled || !value) return;
    try {
      await navigator.clipboard.writeText(String(value));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  }

  return (
    <button className="copy-button" type="button" onClick={copy} disabled={disabled || !value}>
      {copied ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function Reveal({ label, value, redact }) {
  const text = String(value || "").trim();
  if (!text) return null;
  return (
    <details className="reveal">
      <summary>{label}</summary>
      {redact ? (
        <p className="muted">Hidden. Show content to read this value.</p>
      ) : (
        <>
          <div className="reveal-bar">
            <CopyButton value={text} />
          </div>
          <pre>{text}</pre>
        </>
      )}
    </details>
  );
}

function DecisionBand({ trace }) {
  const account = decisionAccount(trace);
  const effective = account.effective;
  return (
    <section className="decision-band" aria-label="Decision">
      <div className="decision-effective">
        <h3>Runtime decision</h3>
        <VerdictMark action={effective} size={16} />
      </div>
      <div className="decision-requested">
        <h3>Policy verdicts</h3>
        {account.requested.length ? (
          <ul>
            {account.requested.map((verdict, index) => (
              <li key={`${verdict.action}-${verdict.category}-${index}`}>
                <VerdictMark action={verdict.action} size={16} />
                <span className="verdict-copy">
                  {verdict.category ? <strong>{verdict.category}</strong> : null}
                  {verdict.reason ? <span className="verdict-reason">{verdict.reason}</span> : null}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p>No policy verdict was recorded for this turn.</p>
        )}
        {account.differs ? (
          <p className="decision-note">
            The policy verdict and the runtime decision differ. The runtime decision is what happened to the operation.
          </p>
        ) : null}
        {account.blockAfterTool ? (
          <p className="decision-note">
            A Block is on a tool-result record. The tool had already run. That verdict did not prevent the effect.
          </p>
        ) : null}
      </div>
    </section>
  );
}

function PredicateComparison({ trace, redact }) {
  const phases = Array.isArray(trace.phases) ? trace.phases : [];
  const rows = Array.isArray(trace.predicate_rows) ? trace.predicate_rows : [];
  if (!rows.length) return null;
  const phaseNames = [...new Set(rows.map((row) => row.phase || "phase"))];

  return (
    <section className="compare-section" aria-label="Predicate comparison">
      <h3>Predicate checks</h3>
      {phaseNames.map((phaseName) => {
        const phase = phases.find((item) => item.phase === phaseName);
        const phaseRows = rows.filter((row) => (row.phase || "phase") === phaseName);
        return (
          <div key={phaseName}>
            <div className="compare-phase">
              <strong>{phaseLabel(phaseName)}</strong>
              {phase ? <span>{phaseTimingLabel(phase)}</span> : null}
            </div>
            <div className="compare" role="table">
              <div className="compare-row compare-head" role="row">
                <span role="columnheader">Check</span>
                <span role="columnheader">Score</span>
                <span role="columnheader">Result</span>
              </div>
              {phaseRows.map((row, index) => (
                <PredicateLine key={`${row.predicate}-${index}`} tid={trace.tid} row={row} redact={redact} />
              ))}
            </div>
          </div>
        );
      })}
    </section>
  );
}

function FlagJudge({ tid, row }) {
  const [reason, setReason] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const marked = Number(row.score || 0) >= 0.5;
  const label = marked ? "false positive" : "false negative";
  if (fixtureMode()) return null;

  async function save(event) {
    event.preventDefault();
    setStatus("Saving the override.");
    setError("");
    try {
      await overrideJudgeResult({
        tid,
        predicate: row.predicate,
        phase: row.phase,
        content_preview: row.content_preview,
        raw_score: marked ? 0 : 1,
        reason: reason.trim() || label,
      });
      setStatus("Override saved for the next matching request.");
    } catch (err) {
      setStatus("");
      setError(describeRequestError(err, "Could not save the override."));
    }
  }

  return (
    <details className="reveal">
      <summary>Flag this check</summary>
      <form className="flag-form" onSubmit={save}>
        <p className="muted">Saves a cache override as a {label} and logs feedback.</p>
        <label>
          Reason
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Why this score should be overridden"
          />
        </label>
        <button className="button secondary" type="submit">Save override</button>
        {status ? <p>{status}</p> : null}
        {error ? <p className="error-text">{error}</p> : null}
      </form>
    </details>
  );
}

function predicateFacts(row, account, score) {
  const parts = [];
  if (account.state === "failed") parts.push(`Recorded ${score.toFixed(2)}`);
  if (row.threshold !== undefined && row.threshold !== "") {
    parts.push(`Threshold ${Number(row.threshold).toFixed(2)}`);
  }
  parts.push(row.judge_cache_hit ? "Cache hit" : `${row.latency_ms || 0} ms`);
  return parts.join(" · ");
}

function PredicateLine({ tid, row, redact }) {
  const account = classifierAccount(row);
  const matched = predicateMatched(row);
  const score = Number(row.raw_score || 0);
  const reasons = Array.isArray(row.reasons) ? row.reasons.filter(Boolean).join("\n") : "";
  const failed = account.state === "failed";
  return (
    <div className={`compare-row status-${account.state}`} role="row">
      <div className="check-cell" role="cell">
        <div className="check-title">
          <strong className="check-name">{row.predicate}</strong>
          <span className={failed ? "check-kind is-failed" : "check-kind"}>{account.label}</span>
        </div>
        <details className="reveal">
          <summary>Details</summary>
          <p className="check-kind">{predicateFacts(row, account, score)}</p>
          <Reveal label="Checked text" value={row.content_preview} redact={redact} />
          <Reveal label="Model prompt" value={row.judge_prompt} redact={redact} />
          <Reveal label="Model reply" value={row.judge_raw_reply} redact={redact} />
          <Reveal label="Reasons" value={reasons} redact={redact} />
          <FlagJudge tid={tid} row={row} />
        </details>
      </div>
      <div className="score-cell" role="cell">
        <span className="score">{failed ? "fallback" : score.toFixed(2)}</span>
      </div>
      <div className="result-cell" role="cell">
        <span className={matched ? "match-yes" : "match-no"}>{matched ? "Matched" : "Not matched"}</span>
        {row.reason ? <span className="check-reason">{row.reason}</span> : null}
      </div>
    </div>
  );
}

function EnforcerLog({ entries, redact }) {
  if (!entries.length) {
    return <p className="muted">No enforcer events were recorded for this turn.</p>;
  }
  return (
    <div className="event-log">
      {entries.map((entry, index) => {
        const full = entry.groups.flatMap((group) => (
          group.lines.filter((line) => line.full !== line.text).map((line) => line.full)
        ));
        return (
          <section className="event-point" key={`${entry.time}-${index}`}>
            <div className="event-point-head">
              <time>{entry.time || "Time not recorded"}</time>
              {entry.action ? <VerdictMark action={entry.action} size={15} /> : null}
            </div>
            {entry.groups.map((group) => (
              <div key={group.key}>
                <div className="event-group-label">{group.label}</div>
                <pre className="event-pre">{group.lines.map((line) => (
                  redact ? formatEventHidden(line) : line.text
                )).join("\n")}</pre>
              </div>
            ))}
            {!redact && full.length ? (
              <Reveal label="Full arguments" value={full.join("\n\n")} redact={false} />
            ) : null}
          </section>
        );
      })}
    </div>
  );
}

function formatEventHidden(line) {
  return line.text.replace(/"(?:[^"\\]|\\.){25,}"/g, "\"…\"");
}

function DecisionView({ trace, earlier = [], redact = false }) {
  if (!trace) return null;
  const eventLog = enforcerEventLog(trace);
  const stamp = formatClock(trace.session_records?.[0]?.ts || trace.ts);
  const sid = trace.sid || "";

  return (
    <article className="decision-view">
      <header className="decision-head">
        <div>
          <h2>Turn {trace.tid}</h2>
          <p className="decision-meta">
            {stamp ? <time>{stamp}</time> : null}
            {sid ? (
              <span className="identifier">
                <span className="field-label">Session</span>
                <code title={sid}>{sid.length > 28 ? `${sid.slice(0, 12)}…${sid.slice(-8)}` : sid}</code>
                <CopyButton value={sid} />
              </span>
            ) : (
              <span>Session not recorded on this turn</span>
            )}
          </p>
        </div>
      </header>
      <DecisionBand trace={trace} />
      <section className="event-section" aria-label="Enforcer events">
        <h3>Enforcer events</h3>
        <EnforcerLog entries={eventLog} redact={redact} />
      </section>
      <PredicateComparison trace={trace} redact={redact} />
      {earlier.length ? (
        <section className="event-section">
          <h3>Earlier in this session</h3>
          <p className="history-note">
            These turns are in time order. The trace does not say which of them satisfied a temporal rule.
          </p>
          <ol className="earlier-list">
            {earlier.map((turn) => (
              <li key={turn.tid}>
                <div className="event-main">
                  <VerdictMark action={turn.action} size={16} />
                  <strong>Turn {turn.tid}</strong>
                  {turn.toolName ? <span>{turn.toolName}</span> : null}
                  {turn.time ? <time>{turn.time}</time> : null}
                </div>
                {turn.log?.length ? (
                  <EnforcerLog entries={turn.log} redact={redact} />
                ) : turn.steps?.length ? (
                  <ul className="earlier-events">
                    {turn.steps.map((step, index) => (
                      <li key={`${turn.tid}-${index}`}>
                        <span>{step.pending ? "Pending" : step.title}</span>
                        {step.body && !redact ? <p className="muted">{shortText(step.body, 180)}</p> : null}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="muted">Open this turn for its events. The list above is only the recorded verdict.</p>
                )}
              </li>
            ))}
          </ol>
        </section>
      ) : null}
      <details className="reveal record-json">
        <summary>Trace record</summary>
        <div className="reveal-bar">
          <CopyButton value={JSON.stringify(trace, null, 2)} />
        </div>
        <pre>{JSON.stringify(trace, null, 2)}</pre>
      </details>
    </article>
  );
}

export { DecisionView };
