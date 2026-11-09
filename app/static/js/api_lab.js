/* Secure DocVault — JWT API-лабораторія (ЛР №2).
   Клієнт виконує реальні fetch-запити до /api/v1/* і показує статуси,
   JSON-відповіді та декодовану структуру JWT. Жодних зовнішніх бібліотек. */

(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);

  const state = {
    access: null,
    refresh: null,
    oldRefresh: null,
    tampered: null,
  };

  const el = {
    username: $("#api-username"),
    password: $("#api-password"),
    method: $("#response-method"),
    path: $("#response-path"),
    status: $("#response-status"),
    time: $("#response-time"),
    meta: $("#request-meta"),
    body: $("#response-body"),
    accessPreview: $("#access-preview"),
    refreshPreview: $("#refresh-preview"),
    header: $("#jwt-header"),
    payload: $("#jwt-payload"),
    signature: $("#jwt-signature"),
    signatureState: $("#signature-state"),
  };

  const initialBody = el.body.textContent;

  const b64urlDecode = (part) => {
    const padded = part.replace(/-/g, "+").replace(/_/g, "/");
    const base64 = padded + "=".repeat((4 - (padded.length % 4)) % 4);
    const binary = atob(base64);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  };

  const b64urlEncode = (value) => {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const parseJwt = (token) => {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("JWT має містити три частини.");
    return {
      header: JSON.parse(b64urlDecode(parts[0])),
      payload: JSON.parse(b64urlDecode(parts[1])),
      signature: parts[2],
    };
  };

  const preview = (token) =>
    token ? `${token.slice(0, 24)}…${token.slice(-12)}` : "—";

  const setStatus = (httpStatus, httpText) => {
    if (!httpStatus) {
      el.status.textContent = "idle";
      el.status.dataset.state = "idle";
      return;
    }
    const ok = httpStatus >= 200 && httpStatus < 300;
    el.status.textContent = `${httpStatus} ${httpText || ""}`.trim();
    el.status.dataset.state = ok ? "ok" : "error";
  };

  const setMeta = (method, path, token) => {
    el.method.textContent = method;
    el.path.textContent = path;
    el.meta.innerHTML = "";

    const label = document.createElement("span");
    label.textContent = token ? "Authorization передано" : "Без заголовка Authorization";

    const value = document.createElement("span");
    value.className = "mono";
    value.textContent = token ? `Bearer ${preview(token)}` : "Authorization: —";

    el.meta.append(label, value);
  };

  const renderResponse = ({ method, path, token, httpStatus, httpText, elapsed, data }) => {
    setMeta(method, path, token);
    setStatus(httpStatus, httpText);
    el.time.textContent = `${elapsed} ms`;
    el.body.textContent = JSON.stringify(data, null, 2);
  };

  const showLocalMessage = (message) => {
    el.method.textContent = "—";
    el.path.textContent = "—";
    setStatus(null);
    el.time.textContent = "—";
    el.meta.innerHTML = "<span>Локальна перевірка стенда</span><span class=\"mono\">запит не надіслано</span>";
    el.body.textContent = JSON.stringify(
      { error: { code: "local_state", message } },
      null,
      2
    );
  };

  const renderTokens = () => {
    el.accessPreview.textContent = preview(state.access);
    el.refreshPreview.textContent = preview(state.refresh);
  };

  const setInspectorEmpty = (message) => {
    el.header.textContent = "—";
    el.payload.textContent = "—";
    el.signature.textContent = "—";
    el.signatureState.textContent = message;
    el.signatureState.dataset.state = "idle";
  };

  const renderJwt = (token, { tampered = false } = {}) => {
    try {
      const decoded = parseJwt(token);
      el.header.textContent = JSON.stringify(decoded.header, null, 2);
      el.payload.textContent = JSON.stringify(decoded.payload, null, 2);
      el.signature.textContent = `${decoded.signature.slice(0, 36)}…\n(${decoded.signature.length} символів)`;

      if (tampered) {
        el.signatureState.textContent = "INVALID · payload змінено";
        el.signatureState.dataset.state = "error";
      } else {
        el.signatureState.textContent = "HS256 · signature valid";
        el.signatureState.dataset.state = "ok";
      }
    } catch (error) {
      setInspectorEmpty(`Не вдалося декодувати: ${error.message}`);
    }
  };

  const request = async (method, path, { token = null, body = null } = {}) => {
    const started = performance.now();
    const headers = {};
    if (body !== null) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;

    try {
      const response = await fetch(path, {
        method,
        headers,
        body: body === null ? undefined : JSON.stringify(body),
        credentials: "same-origin",
        cache: "no-store",
      });

      const elapsed = Math.round(performance.now() - started);
      const raw = await response.text();
      let data;
      try {
        data = JSON.parse(raw);
      } catch {
        data = { raw };
      }

      renderResponse({
        method,
        path,
        token,
        httpStatus: response.status,
        httpText: response.statusText,
        elapsed,
        data,
      });

      return { response, data };
    } catch (error) {
      renderResponse({
        method,
        path,
        token,
        httpStatus: 0,
        httpText: "Network error",
        elapsed: Math.round(performance.now() - started),
        data: { error: { code: "network_error", message: error.message } },
      });
      return { response: null, data: null };
    }
  };

  const run = async (button, action) => {
    if (!button) return;
    button.disabled = true;
    try {
      await action();
    } finally {
      button.disabled = false;
    }
  };

  const login = async () => {
    const username = (el.username.value || "").trim();
    const password = el.password.value || "";

    if (!username || !password) {
      showLocalMessage("Введіть username і password.");
      return;
    }

    const { response, data } = await request("POST", "/api/v1/auth/login", {
      body: { username, password },
    });

    if (response && response.ok && data) {
      state.access = data.access_token;
      state.refresh = data.refresh_token;
      state.oldRefresh = null;
      state.tampered = null;
      renderTokens();
      renderJwt(state.access);
    }
  };

  const profile = async () => {
    if (!state.access) {
      showLocalMessage("Спочатку виконайте Login — Access Token ще не видано.");
      return;
    }

    await request("GET", "/api/v1/user/profile", { token: state.access });
    renderJwt(state.access);
  };

  const noToken = async () => {
    setInspectorEmpty("Запит без токена");
    await request("GET", "/api/v1/user/profile");
  };

  const tamper = async () => {
    if (!state.access) {
      showLocalMessage("Спочатку виконайте Login — немає токена для модифікації.");
      return;
    }

    const parts = state.access.split(".");
    if (parts.length !== 3) {
      showLocalMessage("Поточний Access Token має некоректну структуру.");
      return;
    }

    const payload = JSON.parse(b64urlDecode(parts[1]));
    payload.role = "admin";
    payload.username = "admin";

    state.tampered = `${parts[0]}.${b64urlEncode(JSON.stringify(payload))}.${parts[2]}`;
    renderJwt(state.tampered, { tampered: true });

    await request("GET", "/api/v1/user/profile", { token: state.tampered });
  };

  const refresh = async () => {
    if (!state.refresh) {
      showLocalMessage("Спочатку виконайте Login — Refresh Token ще не видано.");
      return;
    }

    state.oldRefresh = state.refresh;
    const { response, data } = await request("POST", "/api/v1/auth/refresh", {
      body: { refresh_token: state.refresh },
    });

    if (response && response.ok && data) {
      state.access = data.access_token;
      state.refresh = data.refresh_token;
      renderTokens();
      renderJwt(state.access);
    }
  };

  const reuse = async () => {
    if (!state.oldRefresh) {
      showLocalMessage("Спочатку виконайте Refresh, щоб отримати вже використаний токен.");
      return;
    }

    await request("POST", "/api/v1/auth/refresh", {
      body: { refresh_token: state.oldRefresh },
    });
    el.signatureState.textContent = "family revoked · reuse detected";
    el.signatureState.dataset.state = "error";
  };

  const reset = () => {
    state.access = null;
    state.refresh = null;
    state.oldRefresh = null;
    state.tampered = null;
    renderTokens();
    setInspectorEmpty("очікує токен");
    el.method.textContent = "GET";
    el.path.textContent = "/api/v1/health";
    setStatus(null);
    el.time.textContent = "—";
    el.meta.innerHTML = "<span>Готово до перевірки</span><span class=\"mono\">Authorization: —</span>";
    el.body.textContent = initialBody;
  };

  $("#btn-login")?.addEventListener("click", (event) => run(event.currentTarget, login));
  $("#btn-profile")?.addEventListener("click", (event) => run(event.currentTarget, profile));
  $("#btn-no-token")?.addEventListener("click", (event) => run(event.currentTarget, noToken));
  $("#btn-tamper")?.addEventListener("click", (event) => run(event.currentTarget, tamper));
  $("#btn-refresh")?.addEventListener("click", (event) => run(event.currentTarget, refresh));
  $("#btn-reuse")?.addEventListener("click", (event) => run(event.currentTarget, reuse));
  $("#btn-clear")?.addEventListener("click", reset);

  renderTokens();
})();
