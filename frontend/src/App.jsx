import { useCallback, useEffect, useMemo, useState } from "react";

import {
  deleteLivePolicy,
  describeRequestError,
  getPolicies,
  getSwitches,
  getTokenTotal,
  putPolicies,
  reloadRuntime,
  setDryRun,
  setSwitch,
  upsertLivePolicy,
} from "./api.js";
import { fixtureMode } from "./fixtures.js";
import {
  EnforcementModeControl,
  Metric,
  StatusPill,
} from "./components/ui.jsx";
import { ApprovalsLayer } from "./components/ApprovalsLayer.jsx";
import { LiveConsole } from "./components/LiveConsole.jsx";
import { PoliciesTab } from "./components/PoliciesTab.jsx";
import { SwitchesTab } from "./components/SwitchesTab.jsx";
import { TraceTab } from "./components/TraceTab.jsx";
import { FeedbackTab } from "./components/FeedbackTab.jsx";

const tabs = [
  { id: "live", label: "Live" },
  { id: "policies", label: "Policies" },
  { id: "switches", label: "Switches" },
  { id: "trace", label: "Trace" },
  { id: "feedback", label: "Feedback" },
];

function queryParam(name) {
  return new URLSearchParams(window.location.search).get(name) || "";
}

function emptyPolicyState() {
  return {
    active: [],
    thresholds: {},
    policy_thresholds: {},
    model_blocklist: [],
    judge_fail_mode: "closed",
    judge_fail_modes: {},
    user_predicates: [],
    feedback: { enabled: true },
    human_approval: { enabled: false, timeout_seconds: 60, on_timeout: "block" },
    runtime: { judge_batching: "conservative", trace_assistant_content: true },
    policies: [],
  };
}

function App() {
  const sid = useMemo(() => queryParam("sid"), []);
  const [tab, setTab] = useState("live");
  const [policyState, setPolicyState] = useState(emptyPolicyState);
  const [policyDraft, setPolicyDraft] = useState(emptyPolicyState);
  const [tokens, setTokens] = useState(0);
  const [status, setStatus] = useState({ kind: "idle", text: "" });
  const [loading, setLoading] = useState(true);
  // Single source of truth for switches. The top-bar Live/Dry toggle and
  // the Switches tab both read and write this list, so changes from either
  // surface instantly in the other.
  const [switches, setSwitches] = useState([]);
  const [presentation, setPresentation] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("present") === "1") return true;
    return window.sessionStorage.getItem("agentenf_presentation") === "1";
  });
  const [reachable, setReachable] = useState(true);

  async function refreshPolicies() {
    const next = await getPolicies();
    const merged = { ...emptyPolicyState(), ...next };
    setPolicyState(merged);
    setPolicyDraft(merged);
    return merged;
  }

  const refreshSwitches = useCallback(async () => {
    try {
      const result = await getSwitches();
      setSwitches(Array.isArray(result.switches) ? result.switches : []);
    } catch (error) {
      if (!fixtureMode()) setStatus({ kind: "error", text: describeRequestError(error) });
    }
  }, []);

  const updateSwitch = useCallback(
    async (id, value) => {
      const result = await setSwitch(id, value);
      setSwitches((current) =>
        current.map((entry) => (entry.id === id ? { ...entry, current: result.value } : entry)),
      );
      return result;
    },
    [],
  );

  useEffect(() => {
    refreshPolicies()
      .catch((error) => {
        if (!fixtureMode()) setStatus({ kind: "error", text: describeRequestError(error) });
      })
      .finally(() => setLoading(false));
    if (!fixtureMode()) refreshSwitches();
  }, [refreshSwitches]);

  useEffect(() => {
    if (fixtureMode()) {
      setReachable(true);
      return undefined;
    }
    let cancelled = false;
    async function ping() {
      try {
        const response = await fetch("/health", { cache: "no-store" });
        const payload = await response.json().catch(() => null);
        const live = response.ok && payload && typeof payload.ok === "boolean";
        if (!cancelled) setReachable(live);
      } catch {
        if (!cancelled) setReachable(false);
      }
    }
    ping();
    const handle = window.setInterval(ping, 4000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, []);

  function togglePresentation() {
    setPresentation((current) => {
      const next = !current;
      window.sessionStorage.setItem("agentenf_presentation", next ? "1" : "0");
      return next;
    });
  }

  useEffect(() => {
    if (!sid) return undefined;
    let cancelled = false;
    async function refresh() {
      try {
        const result = await getTokenTotal(sid);
        if (!cancelled) setTokens(result.total_tokens || 0);
      } catch {
        if (!cancelled) setTokens(0);
      }
    }
    // Initial fetch on mount, then refresh on demand when the chat page
    // (or anything else) sends `enfguard:token_refresh`. No polling.
    refresh();
    function handleMessage(event) {
      const data = event && event.data;
      if (data && data.type === "enfguard:token_refresh") refresh();
    }
    window.addEventListener("message", handleMessage);
    return () => {
      cancelled = true;
      window.removeEventListener("message", handleMessage);
    };
  }, [sid]);

  async function savePolicyState(nextDraft = policyDraft) {
    try {
      const saved = await putPolicies(nextDraft);
      const merged = { ...emptyPolicyState(), ...saved };
      setPolicyState(merged);
      setPolicyDraft(merged);
      setStatus({ kind: "ok", text: "Policy state saved" });
      return merged;
    } catch (error) {
      setStatus({ kind: "error", text: describeRequestError(error) });
      throw error;
    }
  }

  // App-level policy toggle so the Live console can flip a pack on/off without
  // going through the Policies tab. Mirrors PoliciesTab.updateActive, then saves.
  async function togglePolicy(policyId, enabled) {
    const current = policyDraft || emptyPolicyState();
    const nextActive = enabled
      ? [...new Set([...(current.active || []), policyId])]
      : (current.active || []).filter((id) => id !== policyId);
    const nextPolicies = (Array.isArray(current.policies) ? current.policies : []).map((policy) =>
      policy.id === policyId ? { ...policy, enabled } : policy,
    );
    const nextDraft = { ...current, active: nextActive, policies: nextPolicies };
    setPolicyDraft(nextDraft);
    await savePolicyState(nextDraft);
  }

  async function reloadFromYaml() {
    try {
      const result = await reloadRuntime();
      const merged = { ...emptyPolicyState(), ...result };
      setPolicyState(merged);
      setPolicyDraft(merged);
      await refreshSwitches();
      setStatus({ kind: "ok", text: "YAML reloaded" });
    } catch (error) {
      setStatus({ kind: "error", text: describeRequestError(error) });
    }
  }

  async function installLivePolicy(policy) {
    try {
      const result = await upsertLivePolicy(policy);
      const merged = { ...emptyPolicyState(), ...result };
      setPolicyState(merged);
      setPolicyDraft(merged);
      await refreshSwitches();
      setStatus({ kind: "ok", text: "Live policy installed and runtime reloaded" });
      return merged;
    } catch (error) {
      setStatus({ kind: "error", text: describeRequestError(error) });
      throw error;
    }
  }

  async function removeLivePolicy(policyId) {
    try {
      const result = await deleteLivePolicy(policyId);
      const merged = { ...emptyPolicyState(), ...result };
      setPolicyState(merged);
      setPolicyDraft(merged);
      await refreshSwitches();
      setStatus({ kind: "ok", text: `Live policy ${policyId} removed` });
      return merged;
    } catch (error) {
      setStatus({ kind: "error", text: describeRequestError(error) });
      throw error;
    }
  }

  const enforcementModeSwitch = useMemo(
    () => switches.find((entry) => entry.id === "enforcement_mode"),
    [switches],
  );
  const enforcementMode = enforcementModeSwitch
    ? String(enforcementModeSwitch.current || enforcementModeSwitch.default || "enforce").toLowerCase()
    : "enforce";

  async function changeEnforcementMode(mode) {
    try {
      if (enforcementModeSwitch) {
        await updateSwitch("enforcement_mode", mode);
      } else {
        await setDryRun(mode !== "enforce");
        await refreshSwitches();
      }
      setStatus({ kind: "ok", text: `Enforcement mode: ${mode}` });
    } catch (error) {
      setStatus({ kind: "error", text: describeRequestError(error) });
    }
  }

  return (
    <div className={presentation ? "app-shell presentation" : "app-shell"}>
      <header className="topbar">
        <div className="brand">
          <h1>AgentEnf</h1>
          <p>Enforcement console</p>
        </div>
        <div className="top-actions">
          {!reachable ? (
            <StatusPill kind="error" text="Not reachable" />
          ) : (
            <StatusPill
              kind={status.kind}
              text={status.text || (loading ? "Loading" : "Ready")}
            />
          )}
          <span className="secondary-control">
            <Metric label="tokens" value={tokens} />
          </span>
          <EnforcementModeControl value={enforcementMode} onChange={changeEnforcementMode} />
          <button
            className={presentation ? "chip-btn on" : "chip-btn"}
            type="button"
            onClick={togglePresentation}
            aria-pressed={presentation}
          >
            Presentation
          </button>
        </div>
      </header>

      <nav className="tabs" role="tablist" aria-label="Enforcement sections">
        {tabs.map((item) => (
          <button
            className={tab === item.id ? "tab active" : "tab"}
            key={item.id}
            type="button"
            role="tab"
            aria-selected={tab === item.id}
            onClick={() => setTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <main className="content">
        <ApprovalsLayer setStatus={setStatus} />
        {tab === "live" ? (
          <LiveConsole
            policyState={policyDraft}
            switches={switches}
            reachable={reachable}
            onTogglePolicy={togglePolicy}
            onUpdateSwitch={updateSwitch}
            onReload={reloadFromYaml}
            setStatus={setStatus}
            onOpenPolicies={() => setTab("policies")}
            onOpenSwitches={() => setTab("switches")}
          />
        ) : null}
        {tab === "policies" ? (
          <PoliciesTab
            draft={policyDraft}
            setDraft={setPolicyDraft}
            onSave={savePolicyState}
            onRefresh={refreshPolicies}
            onReload={reloadFromYaml}
            onInstallLivePolicy={installLivePolicy}
            onRemoveLivePolicy={removeLivePolicy}
          />
        ) : null}
        {tab === "switches" ? (
          <SwitchesTab
            switches={switches}
            onRefresh={refreshSwitches}
            onUpdate={updateSwitch}
            setStatus={setStatus}
          />
        ) : null}
        {tab === "trace" ? <TraceTab /> : null}
        {tab === "feedback" ? (
          <FeedbackTab sid={sid} setStatus={setStatus} enabled={policyState.feedback?.enabled !== false} />
        ) : null}
      </main>
    </div>
  );
}

export default App;
