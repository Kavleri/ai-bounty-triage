const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

function authHeaders(token) {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request(path, options = {}, token) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...authHeaders(token),
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Request failed");
  }

  return res.json();
}

export async function register(payload) {
  return request("/api/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function login(payload) {
  return request("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function fetchMe(token) {
  return request("/api/v1/auth/me", {}, token);
}

export async function fetchFindings(token) {
  return request("/api/v1/findings", {}, token);
}

export async function createFinding(payload, token) {
  return request("/api/v1/findings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  }, token);
}

export async function triageFinding(id, payload, token) {
  return request(`/api/v1/findings/${id}/triage`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  }, token);
}

export async function fetchAuditLogs(token) {
  return request("/api/v1/audit-logs", {}, token);
}
