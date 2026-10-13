async function request(path, options = {}) {
  const adminToken = adminTokenHeader();
  const response = await fetch(path, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...adminToken,
      ...(options.headers || {}),
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.detail || payload.error || `${response.status} ${response.statusText}`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

export function describeRequestError(error, fallback = "Request failed.") {
  const status = Number(error?.status || 0);
  const message = String(error?.message || "");
  if (status === 401 || /invalid admin token/i.test(message)) {
    return "Admin token missing or rejected.";
  }
  if (status === 503 && /not configured/i.test(message)) {
    return "Admin token is not configured on the proxy.";
  }
  if (
    status === 502
    || status === 504
    || /failed to fetch|networkerror|load failed|bad gateway|gateway timeout/i.test(message)
  ) {
    return "AgentEnf is not reachable. The last view stays on screen.";
  }
  return message || fallback;
}

function readAdminToken() {
  const params = new URLSearchParams(window.location.search);
  const fromUrl = params.get("admin_token");
  if (fromUrl) {
    window.localStorage.setItem("enfguard_admin_token", fromUrl);
    params.delete("admin_token");
    const query = params.toString();
    const next = `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
    window.history.replaceState(null, "", next);
    return fromUrl;
  }
  return window.localStorage.getItem("enfguard_admin_token") || "";
}

function adminTokenHeader() {
  const token = readAdminToken();
  return token ? { "x-admin-token": token } : {};
}

export function getPolicies() {
  return request("/admin/policies");
}

export function putPolicies(state) {
  return request("/admin/policies", {
    method: "PUT",
    body: JSON.stringify(state),
  });
}

export function reloadRuntime() {
  return request("/admin/reload", { method: "POST" });
}

export function upsertLivePolicy(policy) {
  return request("/admin/live_policy", {
    method: "POST",
    body: JSON.stringify(policy),
  });
}

export function deleteLivePolicy(policyId) {
  return request(`/admin/live_policy/${encodeURIComponent(policyId)}`, {
    method: "DELETE",
  });
}

export function setDryRun(enabled) {
  return request(`/admin/dryrun/${enabled ? "on" : "off"}`, { method: "POST" });
}

export function getTrace(tid) {
  return request(`/trace/${encodeURIComponent(tid)}?_=${Date.now()}`);
}

export function sendFeedback(tid, kind, payload) {
  return request("/feedback", {
    method: "POST",
    body: JSON.stringify({ tid, kind, payload }),
  });
}

export function overrideJudgeResult(payload) {
  return request("/admin/judge_override", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getTokenTotal(sid) {
  return request(`/admin/session/${encodeURIComponent(sid)}/tokens`);
}

export function getSwitches() {
  return request("/switches");
}

export function setSwitch(id, value) {
  return request(`/switches/${encodeURIComponent(id)}`, {
    method: "POST",
    body: JSON.stringify({ value }),
  });
}

export function listTraces(limit = 50) {
  return request(`/traces?limit=${encodeURIComponent(limit)}&_=${Date.now()}`);
}

export function getPendingApprovals() {
  return request("/pending_approvals");
}

export function resolveApproval(tid, decision, payload = "") {
  // Approval decisions reuse the /feedback endpoint with kind=approve|deny.
  return request("/feedback", {
    method: "POST",
    body: JSON.stringify({ tid, kind: decision, payload }),
  });
}
