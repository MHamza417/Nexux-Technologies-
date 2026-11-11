const configuredApiBase = import.meta.env.VITE_API_URL || "";
const pointsToLocalApi = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(configuredApiBase);
export const API_BASE = (
  import.meta.env.DEV && pointsToLocalApi ? "" : configuredApiBase
).replace(/\/+$/, "");
const API_ROOT = `${API_BASE}/api`;
const ACCESS_KEY = "intellisecops.access";
const REFRESH_KEY = "intellisecops.refresh";
const PUBLIC_SCANS_KEY = "intellisecops.publicScans";

export class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

export function hasSession() {
  return Boolean(localStorage.getItem(ACCESS_KEY));
}

export function clearSession() {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

function responseMessage(data, fallback) {
  if (!data || typeof data !== "object") return fallback;
  if (typeof data.detail === "string") return data.detail;
  const firstError = Object.values(data).flat().find((value) => typeof value === "string");
  return firstError || fallback;
}

async function parseResponse(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { detail: text };
  }
}

async function refreshAccessToken() {
  const refresh = localStorage.getItem(REFRESH_KEY);
  if (!refresh) return false;
  const response = await fetch(`${API_ROOT}/auth/token/refresh/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh }),
  });
  const data = await parseResponse(response);
  if (!response.ok || !data?.access) {
    clearSession();
    return false;
  }
  localStorage.setItem(ACCESS_KEY, data.access);
  return true;
}

export async function apiRequest(path, options = {}) {
  const { auth = true, retryAuth = true, ...fetchOptions } = options;
  const headers = new Headers(fetchOptions.headers || {});
  if (fetchOptions.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (auth) {
    const access = localStorage.getItem(ACCESS_KEY);
    if (access) headers.set("Authorization", `Bearer ${access}`);
  }

  let response = await fetch(`${API_ROOT}${path}`, { ...fetchOptions, headers });
  if (response.status === 401 && auth && retryAuth && await refreshAccessToken()) {
    headers.set("Authorization", `Bearer ${localStorage.getItem(ACCESS_KEY)}`);
    response = await fetch(`${API_ROOT}${path}`, { ...fetchOptions, headers });
  }

  const data = await parseResponse(response);
  if (!response.ok) {
    if (response.status === 401 && auth) clearSession();
    throw new ApiError(
      responseMessage(data, `Request failed (${response.status}).`),
      response.status,
      data,
    );
  }
  return data;
}

export async function login(username, password) {
  const normalizedUsername = username.trim();
  if (!normalizedUsername) {
    throw new ApiError("Enter your username.", 400, { username: ["This field is required."] });
  }
  if (!password) {
    throw new ApiError("Enter your password.", 400, { password: ["This field is required."] });
  }

  const data = await apiRequest("/auth/token/", {
    method: "POST",
    auth: false,
    retryAuth: false,
    body: JSON.stringify({ username: normalizedUsername, password }),
  });
  if (typeof data?.access !== "string" || typeof data?.refresh !== "string") {
    throw new ApiError("The authentication server returned an invalid token response.", 502, data);
  }
  localStorage.setItem(ACCESS_KEY, data.access);
  localStorage.setItem(REFRESH_KEY, data.refresh);
  return data;
}

export async function loadDashboard() {
  return apiRequest("/dashboard/");
}

export async function loadHistory() {
  return apiRequest("/scans/history/?limit=50");
}

export async function submitScan(payload) {
  return apiRequest("/scans/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function loadScan(scanId) {
  return apiRequest(`/scans/${encodeURIComponent(scanId)}/`);
}

export async function loadReport(scanId) {
  return apiRequest(`/scans/${encodeURIComponent(scanId)}/report/`);
}

export async function loadWazuhVulnerabilities(agent = "default") {
  const query = agent && agent !== "default"
    ? `?agent=${encodeURIComponent(agent)}`
    : "";
  return apiRequest(`/wazuh/vulnerabilities/${query}`);
}

export function readPublicScans() {
  try {
    const parsed = JSON.parse(localStorage.getItem(PUBLIC_SCANS_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function rememberPublicScan(entry) {
  const next = [
    entry,
    ...readPublicScans().filter((item) => item.scan_id !== entry.scan_id),
  ].slice(0, 12);
  localStorage.setItem(PUBLIC_SCANS_KEY, JSON.stringify(next));
  return next;
}

export function tokenForScan(scanId) {
  return readPublicScans().find((item) => item.scan_id === scanId)?.access_token || "";
}

function publicHeaders(token) {
  return { "X-Scan-Access-Token": token };
}

export async function submitPublicScan(payload) {
  return apiRequest("/public/scans/", {
    method: "POST",
    auth: false,
    retryAuth: false,
    body: JSON.stringify(payload),
  });
}

export async function loadPublicScan(scanId, token) {
  return apiRequest(`/public/scans/${encodeURIComponent(scanId)}/`, {
    auth: false,
    retryAuth: false,
    headers: publicHeaders(token),
  });
}

export async function downloadPublicReport(scanId, token) {
  return apiRequest(`/public/scans/${encodeURIComponent(scanId)}/download/`, {
    auth: false,
    retryAuth: false,
    headers: publicHeaders(token),
  });
}
