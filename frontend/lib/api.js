// Small fetch wrapper plus the browser session (token kept in sessionStorage).
// sessionStorage is per tab, so closing the tab signs the analyst out.

const TOKEN_KEY = "threatlens.token";
const USER_KEY = "threatlens.user";

function storage() {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function getToken() {
  try {
    return storage()?.getItem(TOKEN_KEY) ?? null;
  } catch {
    return null;
  }
}

export function getUser() {
  try {
    const raw = storage()?.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function saveSession(login) {
  try {
    storage()?.setItem(TOKEN_KEY, login.token);
    storage()?.setItem(USER_KEY, JSON.stringify({ username: login.username, role: login.role }));
  } catch {
    // Storage blocked: the user will simply have to log in again on reload.
  }
}

export function clearSession() {
  try {
    storage()?.removeItem(TOKEN_KEY);
    storage()?.removeItem(USER_KEY);
  } catch {
    // ignore
  }
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/**
 * Calls the backend through the /api proxy. Throws ApiError with a readable message.
 * A 401 clears the session and sends the user to the login page.
 */
export async function api(path, { method = "GET", body } = {}) {
  const headers = { Accept: "application/json" };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  let res;
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "Cannot reach the backend. Is it running on port 8080?");
  }

  if (res.status === 401 && path !== "/auth/login") {
    clearSession();
    window.location.assign("/login");
    throw new ApiError(401, "Your session has expired. Please log in again.");
  }

  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!res.ok) {
    const message = data?.detail || data?.title || `Request failed (${res.status})`;
    throw new ApiError(res.status, message);
  }
  return data;
}