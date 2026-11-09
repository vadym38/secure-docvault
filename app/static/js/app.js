/* Secure DocVault — клієнтські покращення.
   Уся валідація тут є лише UX-підказкою; остаточне рішення ухвалює сервер. */

(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  /* Показати / приховати пароль ------------------------------------------- */
  $$("[data-reveal]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.reveal);
      if (!input) return;

      const isHidden = input.type === "password";
      input.type = isHidden ? "text" : "password";
      button.classList.toggle("is-on", isHidden);
      button.setAttribute("aria-label", isHidden ? "Приховати пароль" : "Показати пароль");
      input.focus({ preventScroll: true });
    });
  });

  /* Flash-повідомлення ----------------------------------------------------- */
  $$(".flash").forEach((flash, index) => {
    const close = $(".flash__close", flash);
    let dismissed = false;

    const dismiss = () => {
      if (dismissed) return;
      dismissed = true;
      flash.classList.add("is-leaving");
      window.setTimeout(() => flash.remove(), 240);
    };

    if (close) close.addEventListener("click", dismiss);
    window.setTimeout(dismiss, 10000 + index * 500);
  });

  /* Індикатор складності пароля ------------------------------------------- */
  const passwordInput = $("#password");
  const strengthMeter = $("[data-strength]");
  const strengthLabel = $("#strength-label");
  const ruleElements = $$("[data-rule]");

  if (passwordInput && strengthMeter) {
    const rules = {
      length: (value) => value.length >= 8,
      upper: (value) => /[A-ZА-ЯЄІЇҐ]/.test(value),
      lower: (value) => /[a-zа-яєіїґ]/.test(value),
      digit: (value) => /\d/.test(value),
      special: (value) => /[^A-Za-zА-Яа-яЄєІіЇїҐ0-9\s]/.test(value),
    };

    const labels = ["—", "Слабкий", "Середній", "Добрий", "Надійний"];

    const updateStrength = () => {
      const value = passwordInput.value;
      let passed = 0;

      ruleElements.forEach((element) => {
        const rule = rules[element.dataset.rule];
        const isOk = typeof rule === "function" ? rule(value) : false;
        element.classList.toggle("is-ok", isOk);
        if (isOk) passed += 1;
      });

      const level = value.length === 0
        ? 0
        : Math.max(1, Math.min(4, Math.ceil((passed * 4) / Object.keys(rules).length)));

      strengthMeter.dataset.level = String(level);
      $$("span", strengthMeter).forEach((bar, index) => {
        bar.classList.toggle("is-on", index < level);
      });

      if (strengthLabel) {
        strengthLabel.textContent = labels[level];
      }
    };

    passwordInput.addEventListener("input", updateStrength);
    updateStrength();
  }

  /* Пресети payload для SQLi-лабораторії ---------------------------------- */
  $$("[data-payload]").forEach((button) => {
    button.addEventListener("click", () => {
      const textarea = $("#payload");
      if (!textarea) return;
      textarea.value = button.dataset.payload || "";
      textarea.focus();
      textarea.setSelectionRange(textarea.value.length, textarea.value.length);
    });
  });
})();
