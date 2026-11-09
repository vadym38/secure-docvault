/* Secure DocVault — лабораторія WAF / Rate Limiting (ЛР №4).
   Жодного inline-коду: файл дозволений CSP `script-src 'self'`. */

(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);

  const makeCell = (tag, className, text) => {
    const cell = document.createElement(tag);
    if (className) cell.className = className;
    if (text !== undefined) cell.textContent = text;
    return cell;
  };

  const setPill = (element, text, state) => {
    if (!element) return;
    element.textContent = text;
    element.dataset.state = state;
  };

  const csrfToken = () => {
    const input = document.querySelector('#reset-form input[name="csrf_token"]');
    return input ? input.value : "";
  };

  const truncate = (value, size = 150) =>
    value.length > size ? `${value.slice(0, size)}…` : value;

  const readBody = async (response) => {
    const text = await response.text();
    try {
      const parsed = JSON.parse(text);
      if (parsed && parsed.error) {
        const parts = [parsed.error.code, parsed.error.message];
        if (parsed.error.rule) parts.push(`rule=${parsed.error.rule}`);
        return truncate(parts.filter(Boolean).join(" · "));
      }
      return truncate(JSON.stringify(parsed));
    } catch (_error) {
      return truncate(text || "(порожньо)");
    }
  };

  // ------------------------------------------------------------------
  // Стрес-тест login
  // ------------------------------------------------------------------

  const renderBurstRows = (rows) => {
    const body = $("#burst-results");
    if (!body) return;
    body.textContent = "";

    if (!rows.length) {
      const row = document.createElement("tr");
      row.appendChild(makeCell("td", "empty-cell", "Натисніть «Надіслати 10 запитів»."));
      row.firstChild.colSpan = 4;
      body.appendChild(row);
      return;
    }

    rows.forEach((item) => {
      const row = document.createElement("tr");
      row.appendChild(makeCell("td", "mono", String(item.index)));

      const codeCell = document.createElement("td");
      codeCell.appendChild(
        makeCell(
          "span",
          `http-code http-code--${item.status}`,
          `HTTP ${item.status}`
        )
      );
      row.appendChild(codeCell);

      row.appendChild(makeCell("td", "mono", item.retryAfter || "—"));
      row.appendChild(makeCell("td", "incident-detail", item.body));
      body.appendChild(row);
    });
  };

  const runBurst = async () => {
    const button = $("#btn-burst");
    const pill = $("#burst-status");
    if (button) button.disabled = true;
    setPill(pill, "виконується…", "pending");
    renderBurstRows([]);

    const rows = [];
    let limited = 0;

    for (let index = 1; index <= 10; index += 1) {
      try {
        const response = await fetch("/api/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          cache: "no-store",
          body: JSON.stringify({
            username: "bruteforce-probe",
            password: "wrong-password",
          }),
        });
        const body = await readBody(response);
        const retryAfter = response.headers.get("Retry-After") || "";
        if (response.status === 429) limited += 1;
        rows.push({
          index,
          status: response.status,
          retryAfter,
          body,
        });
      } catch (error) {
        rows.push({
          index,
          status: "ERR",
          retryAfter: "",
          body: String(error).slice(0, 120),
        });
      }
      renderBurstRows(rows);
    }

    setPill(
      pill,
      limited ? `${limited}/10 → 429` : "429 не досягнуто",
      limited ? "error" : "ok"
    );
    if (button) button.disabled = false;
    await refreshEvents();
  };

  // ------------------------------------------------------------------
  // WAF-атаки
  // ------------------------------------------------------------------

  const ATTACKS = {
    path: {
      title: "Path Traversal",
      url: "/api/v1/user/profile?file=../../etc/passwd",
    },
    sqli: {
      title: "SQL Injection",
      url: "/api/v1/user/profile?q=%27%20OR%20%271%27%3D%271",
    },
    cmd: {
      title: "Command Injection",
      url: "/api/v1/user/profile?cmd=%3B%20%2Fbin%2Fsh%20-c%20id",
    },
    xss: {
      title: "XSS Signature",
      url: "/api/v1/user/profile?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    },
  };

  const showResult = (title, lines, state) => {
    const panel = $("#waf-result");
    const pre = panel ? panel.querySelector("pre") : null;
    if (!panel || !pre) return;

    panel.dataset.state = state;
    const label = panel.querySelector(".attack-result__label");
    if (label) label.textContent = title;
    pre.textContent = lines.join("\n");
  };

  const runAttack = async (kind) => {
    const attack = ATTACKS[kind];
    if (!attack) return;

    const pill = $("#waf-status");
    setPill(pill, "перевірка…", "pending");

    try {
      const response = await fetch(attack.url, {
        method: "GET",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      const body = await readBody(response);
      const rule = response.headers.get("X-WAF-Rule") || "—";
      const action = response.headers.get("X-WAF-Action") || "—";
      const retry = response.headers.get("Retry-After") || "—";

      showResult(
        attack.title,
        [
          `request: GET ${attack.url}`,
          `HTTP: ${response.status}`,
          `X-WAF-Rule: ${rule}`,
          `X-WAF-Action: ${action}`,
          `Retry-After: ${retry}`,
          `body: ${body}`,
        ],
        response.status === 403 ? "error" : "ok"
      );
      setPill(
        pill,
        response.status === 403 ? `BLOCKED · ${rule}` : `HTTP ${response.status}`,
        response.status === 403 ? "error" : "ok"
      );
    } catch (error) {
      showResult(attack.title, [`fetch error: ${error}`], "error");
      setPill(pill, "fetch error", "error");
    }

    await refreshEvents();
  };

  const checkGreylist = async () => {
    const pill = $("#waf-status");
    setPill(pill, "перевірка Greylist…", "pending");
    try {
      const response = await fetch("/api/v1/health", {
        method: "GET",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      const body = await readBody(response);
      const retry = response.headers.get("Retry-After") || "—";
      showResult(
        "Greylist probe · GET /api/v1/health",
        [
          `HTTP: ${response.status}`,
          `Retry-After: ${retry}`,
          `body: ${body}`,
        ],
        response.status === 403 ? "error" : "ok"
      );
      setPill(
        pill,
        response.status === 403 ? "IP у Greylist" : `HTTP ${response.status}`,
        response.status === 403 ? "error" : "ok"
      );
    } catch (error) {
      showResult("Greylist probe", [`fetch error: ${error}`], "error");
    }
    await refreshEvents();
  };

  // ------------------------------------------------------------------
  // Журнал і Greylist
  // ------------------------------------------------------------------

  const renderIncidents = (incidents) => {
    const body = $("#incident-body");
    if (!body) return;
    body.textContent = "";

    if (!incidents.length) {
      const row = document.createElement("tr");
      const cell = makeCell(
        "td",
        "empty-cell",
        "Журнал порожній. Запустіть стрес-тест або WAF-атаку."
      );
      cell.colSpan = 7;
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }

    incidents.forEach((item) => {
      const row = document.createElement("tr");
      row.appendChild(makeCell("td", "mono", item.timestamp.slice(11, 19)));
      const kind = makeCell("span", `incident-kind incident-kind--${item.kind}`, item.kind);
      const kindCell = document.createElement("td");
      kindCell.appendChild(kind);
      row.appendChild(kindCell);
      row.appendChild(makeCell("td", "mono", item.ip));
      row.appendChild(
        makeCell("td", "mono incident-path", `${item.method} ${item.path}`)
      );
      row.appendChild(makeCell("td", "incident-detail", item.detail));
      row.appendChild(makeCell("td", "incident-action", item.action));
      const code = makeCell(
        "span",
        `http-code http-code--${item.status_code}`,
        String(item.status_code)
      );
      const codeCell = document.createElement("td");
      codeCell.appendChild(code);
      row.appendChild(codeCell);
      body.appendChild(row);
    });
  };

  const renderGreylist = (entries) => {
    const body = $("#greylist-body");
    if (!body) return;
    body.textContent = "";

    if (!entries.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state empty-state--inline";
      empty.textContent = "Активних блокувань немає.";
      body.appendChild(empty);
      return;
    }

    entries.forEach((item) => {
      const card = document.createElement("article");
      card.className = "greylist-item";

      const info = document.createElement("div");
      info.appendChild(makeCell("strong", "mono", item.ip));
      info.appendChild(
        makeCell("span", "", `${item.reason} · ${item.rule_id}`)
      );
      card.appendChild(info);
      card.appendChild(
        makeCell("span", "greylist-timer mono", `${item.remaining_seconds} с`)
      );
      body.appendChild(card);
    });
  };

  const refreshEvents = async () => {
    try {
      const response = await fetch("/waf-lab/events", {
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) return;
      const data = await response.json();
      renderIncidents(data.incidents || []);
      renderGreylist(data.greylist || []);

      const total = data.stats ? data.stats.incidents_total : 0;
      const count = $("#incident-count");
      const badge = $("#incident-badge");
      const grey = $("#greylist-count");
      if (count) count.textContent = String(total);
      if (badge) badge.textContent = `${total} подій`;
      if (grey) grey.textContent = String((data.greylist || []).length);
    } catch (_error) {
      /* журнал — допоміжний елемент; помилка мережі не ламає сторінку */
    }
  };

  const resetLab = async (event) => {
    event.preventDefault();
    const token = csrfToken();
    if (!token) return;

    try {
      await fetch("/waf-lab/reset", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-Requested-With": "fetch",
        },
        body: `csrf_token=${encodeURIComponent(token)}`,
      });
    } finally {
      window.location.reload();
    }
  };

  // ------------------------------------------------------------------
  // Ініціалізація
  // ------------------------------------------------------------------

  document.addEventListener("DOMContentLoaded", () => {
    const burst = $("#btn-burst");
    if (burst) burst.addEventListener("click", runBurst);

    document.querySelectorAll("[data-attack]").forEach((button) => {
      button.addEventListener("click", () => runAttack(button.dataset.attack));
    });

    const refresh = $("#btn-refresh");
    if (refresh) refresh.addEventListener("click", refreshEvents);

    const greylist = $("#btn-check-greylist");
    if (greylist) greylist.addEventListener("click", checkGreylist);

    const reset = $("#reset-form");
    if (reset) reset.addEventListener("submit", resetLab);
  });
})();
