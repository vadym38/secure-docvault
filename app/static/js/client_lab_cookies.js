/* Secure DocVault — Cookie Inspector (ЛР №3).
   Показує, що бачить JavaScript у document.cookie. HttpOnly-cookie
   фізично не потрапляють у цей рядок. */

(() => {
  "use strict";

  const render = () => {
    const target = document.getElementById("cookie-visible");
    if (!target) return;

    const raw = document.cookie || "";
    target.textContent = raw
      ? raw
      : "(порожньо — усі чутливі cookie мають HttpOnly)";

    const names = raw
      .split(";")
      .map((item) => item.split("=")[0].trim())
      .filter(Boolean);
    window.__lab3VisibleCookies = names;
  };

  document.addEventListener("DOMContentLoaded", render);
  window.__lab3RenderCookieView = render;
})();
