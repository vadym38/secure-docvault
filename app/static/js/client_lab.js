/* Secure DocVault — клієнтська лабораторія (ЛР №3).
   Заповнює форму швидкими XSS-payload. Жодного inline-коду: файл
   підключається зі static/ і дозволений CSP `script-src 'self'`. */

(() => {
  "use strict";

  const PAYLOADS = {
    script: {
      field: "description",
      value: "<script>alert('XSS')</script>Опис документа зі шкідливим скриптом",
    },
    img: {
      field: "filename",
      value: "contract<img src=x onerror=alert(1)>.pdf",
    },
    svg: {
      field: "comment",
      value: '"><svg onload=alert(1)>Коментар',
    },
  };

  document.querySelectorAll("[data-payload]").forEach((button) => {
    button.addEventListener("click", () => {
      const payload = PAYLOADS[button.dataset.payload];
      if (!payload) return;

      const field = document.querySelector(`[name="${payload.field}"]`);
      if (!field) return;

      field.value = payload.value;
      field.focus({ preventScroll: true });
    });
  });
})();
