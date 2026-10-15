import { useCallback, useEffect, useRef, useState } from "react";

const API = import.meta.env.VITE_API_URL || "";
let currentToken = "";

export function setApiToken(token) {
  currentToken = token || "";
}

function formatDetail(detail) {
  if (!detail) return "";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
  return JSON.stringify(detail);
}

async function request(method, path, body, opts = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const token = opts.token !== undefined ? opts.token : currentToken;
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }
  if (!res.ok) {
    const err = new Error(formatDetail(data && data.detail) || `${res.status} ${path}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const api = {
  get: (path, opts) => request("GET", path, undefined, opts),
  post: (path, body, opts) => request("POST", path, body === undefined ? {} : body, opts),
  put: (path, body, opts) => request("PUT", path, body, opts),
  patch: (path, body, opts) => request("PATCH", path, body, opts),
  del: (path, body, opts) => request("DELETE", path, body, opts),
};

export async function mintDemoToken(subject, role) {
  const q = new URLSearchParams({ subject, role, agent_id: "sentinel-dashboard" });
  return request("POST", `/v1/demo/token?${q.toString()}`, undefined, { token: "" });
}

/** Fetch on mount / when deps change, optionally re-poll every `interval` ms. */
export function usePoll(fn, deps = [], interval = 0) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const reload = useCallback(async () => {
    try {
      const data = await fnRef.current();
      setState({ data, error: null, loading: false });
    } catch (e) {
      setState((s) => ({ ...s, error: e.message || String(e), loading: false }));
    }
  }, []);
  useEffect(() => {
    reload();
    if (!interval) return undefined;
    const id = setInterval(reload, interval);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, interval]);
  return { ...state, reload };
}

export function safeStorage() {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/** Fetch an authenticated file (e.g. a scan report) and either save it or open it in a new tab. */
export async function fetchFile(path, { filename, open } = {}) {
  const headers = {};
  if (currentToken) headers.Authorization = `Bearer ${currentToken}`;
  const res = await fetch(`${API}${path}`, { headers });
  if (!res.ok) throw new Error(`${res.status} ${path}`);
  const url = URL.createObjectURL(await res.blob());
  if (open) {
    window.open(url, "_blank", "noopener");
  } else {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || "download";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
