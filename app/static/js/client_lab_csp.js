/* Secure DocVault — CSP-лабораторія (ЛР №3).
   Файл завантажується синхронно ДО навмисно вразливого inline-скрипта,
   тому встигає зареєструвати securitypolicyviolation listener. */

(() => {
  "use strict";

  const state = {
    violations: [],
    domAttempts: 0,
  };
  window.__lab3 = state;

  const consoleEl = () => document.getElementById("console-lines");
  const countEl = () => document.getElementById("console-count");
  const violationCountEl = () => document.getElementById("violation-count");
  const tableBody = () => document.getElementById("csp-events-body");

  const appendConsole = (line) => {
    const pre = consoleEl();
    if (!pre) return;

    if (pre.dataset.empty !== "false") {
      pre.textContent = "";
      pre.dataset.empty = "false";
    }
    pre.textContent += `${line}\n`;
  };

  const renderViolation = (violation) => {
    state.violations.push(violation);

    const pre = consoleEl();
    if (pre) {
      appendConsole(
        `[CSP] Refused to execute inline script because it violates the following Content Security Policy directive: "${violation.violatedDirective}".`
      );
      appendConsole(
        `      blockedURI: ${violation.blockedURI || "inline"} · source: ${violation.sourceFile || "inline"} · line: ${violation.lineNumber || "—"}`
      );
    }

    const count = countEl();
    if (count) count.textContent = String(state.violations.length);

    const badge = violationCountEl();
    if (badge) badge.textContent = `${state.violations.length} подій`;

    const body = tableBody();
    if (body) {
      if (body.querySelector(".empty-cell")) body.textContent = "";
      const row = document.createElement("tr");
      const values = [
        violation.violatedDirective || "—",
        violation.blockedURI || "inline",
        violation.sourceFile || "inline",
        violation.lineNumber ? String(violation.lineNumber) : "—",
      ];
      values.forEach((value) => {
        const cell = document.createElement("td");
        cell.className = "mono table-value";
        cell.textContent = value;
        row.appendChild(cell);
      });
      body.appendChild(row);
    }
  };

  document.addEventListener("securitypolicyviolation", (event) => {
    renderViolation({
      violatedDirective: event.violatedDirective,
      blockedURI: event.blockedURI,
      sourceFile: event.sourceFile,
      lineNumber: event.lineNumber,
      sample: event.sample,
    });
  });

  const setStatus = (id, text, stateName) => {
    const element = document.getElementById(id);
    if (!element) return;
    element.textContent = text;
    element.dataset.state = stateName;
  };

  const refreshStatuses = () => {
    const inlineRan = window.__xssExecuted === true || window.__inlineRan === true;
    const handlerRan = window.__xssExecuted === true || window.__handlerRan === true;

    setStatus(
      "inline-status",
      inlineRan ? "EXECUTED" : "BLOCKED",
      inlineRan ? "error" : "ok"
    );
    setStatus(
      "handler-status",
      handlerRan ? "EXECUTED" : "BLOCKED",
      handlerRan ? "error" : "ok"
    );
  };

  const injectDomScript = () => {
    state.domAttempts += 1;
    const attempts = document.getElementById("dom-attempts");
    if (attempts) attempts.textContent = `${state.domAttempts} спроб`;

    const script = document.createElement("script");
    script.textContent = "window.__xssExecuted = true; alert('DOM XSS');";
    document.body.appendChild(script);
    script.remove();

    window.setTimeout(() => {
      const executed = window.__xssExecuted === true;
      setStatus(
        "dom-status",
        executed ? "EXECUTED" : "BLOCKED",
        executed ? "error" : "ok"
      );
    }, 30);
  };

  document.addEventListener("DOMContentLoaded", () => {
    refreshStatuses();

    const button = document.getElementById("btn-dom-xss");
    if (button) button.addEventListener("click", injectDomScript);

    // Даємо браузеру час зафіксувати порушення від inline-скрипта.
    window.setTimeout(refreshStatuses, 50);
  });

  /* Використовується скриптом збору скриншотів: передає реальні
     повідомлення browser log у консольний блок. */
  window.__lab3.renderBrowserLogs = (messages) => {
    const pre = consoleEl();
    if (!pre) return;
    pre.dataset.empty = "false";
    pre.textContent = messages.length
      ? `${messages.join("\n")}\n`
      : "Повідомлень CSP не зафіксовано.";
    const count = countEl();
    if (count) count.textContent = String(messages.length);
  };
})();
