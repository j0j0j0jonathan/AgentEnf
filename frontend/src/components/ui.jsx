import { Ban, Check, Hand, TriangleAlert } from "lucide-react";
import { verdictKind, verdictLabel } from "../traceUtils.js";

const VERDICT_ICONS = {
  allow: Check,
  warn: TriangleAlert,
  approval: Hand,
  block: Ban,
};

function VerdictMark({ action, size = 18 }) {
  const text = String(action || "");
  if (!text) {
    return (
      <span className="verdict-pill none">
        <span>No verdict</span>
      </span>
    );
  }
  const kind = verdictKind(text);
  const Icon = VERDICT_ICONS[kind] || Check;
  return (
    <span className={`verdict-pill ${kind}`}>
      <Icon size={size} strokeWidth={2.25} aria-hidden="true" />
      <span>{verdictLabel(text)}</span>
    </span>
  );
}

function FixtureNotice() {
  const kind = new URLSearchParams(window.location.search).get("fixture");
  const text = {
    "1": "Showing labelled fixtures. Remove ?fixture=1 for the live proxy.",
    empty: "Showing the empty fixture. Remove ?fixture=empty for the live proxy.",
    error: "Showing the error fixture. Remove ?fixture=error for the live proxy.",
  }[kind];
  if (!text) return null;
  return (
    <div className="banner fixture" role="status">
      <p>{text}</p>
    </div>
  );
}

function StatusPill({ kind, text }) {
  return (
    <div className={`status ${kind}`}>
      <span>{text}</span>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function EnforcementModeControl({ value, onChange }) {
  return (
    <div className="mode-control" aria-label="Enforcement mode">
      {["audit", "warn", "enforce"].map((mode) => (
        <button
          key={mode}
          className={value === mode ? "active" : ""}
          type="button"
          onClick={() => onChange(mode)}
          title={`Set enforcement mode to ${mode}`}
        >
          {mode}
        </button>
      ))}
    </div>
  );
}

function ToggleControl({ checked, onChange, title, disabled = false }) {
  return (
    <button
      className={checked ? "switch on" : "switch"}
      type="button"
      onClick={() => onChange(!checked)}
      title={title}
      disabled={disabled}
      aria-pressed={checked}
    >
      <span className="switch-thumb" />
    </button>
  );
}

function SwitchMini({ entry, onChange }) {
  if (entry.kind === "boolean") {
    const enabled = String(entry.current).toLowerCase() === "true";
    return (
      <div className="switch-mini">
        <div className="switch-mini-label">
          <code>{entry.id}</code>
          {entry.label ? <span className="muted">{entry.label}</span> : null}
        </div>
        <ToggleControl checked={enabled} onChange={(next) => onChange(entry.id, next)} title={entry.label || entry.id} />
      </div>
    );
  }
  if (entry.kind === "choice") {
    return (
      <div className="switch-mini">
        <div className="switch-mini-label">
          <code>{entry.id}</code>
        </div>
        <select value={entry.current} onChange={(event) => onChange(entry.id, event.target.value)}>
          {(entry.options || []).map((option) => (
            <option key={option} value={option}>{option}</option>
          ))}
        </select>
      </div>
    );
  }
  // numeric: show value compactly (fine control lives in the Switches tab)
  return (
    <div className="switch-mini">
      <div className="switch-mini-label">
        <code>{entry.id}</code>
        {entry.label ? <span className="muted">{entry.label}</span> : null}
      </div>
      <span className="switch-mini-value">{entry.current}</span>
    </div>
  );
}

export { StatusPill, Metric, EnforcementModeControl, ToggleControl, SwitchMini, VerdictMark, FixtureNotice };
