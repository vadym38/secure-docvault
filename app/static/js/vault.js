/* Secure DocVault — Cipher Vault UI (ЛР №5).
   Файл підключається зі static/ і дозволений CSP `script-src 'self'`. */

(() => {
  "use strict";

  const input = document.getElementById("document-file");
  const label = document.getElementById("file-name");

  if (input && label) {
    input.addEventListener("change", () => {
      const file = input.files && input.files[0];
      if (!file) {
        label.textContent = "Оберіть файл або перетягніть його сюди";
        return;
      }
      const sizeKb = (file.size / 1024).toFixed(1);
      label.textContent = `${file.name} · ${sizeKb} КБ`;
    });
  }

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const message = form.dataset.confirm || "Продовжити?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });
})();
