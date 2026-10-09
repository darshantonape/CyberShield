/* CyberShield theme switcher.
 *
 * Three preferences — "light", "dark", "system" — persisted in localStorage.
 * Whichever is chosen, this script resolves it to a CONCRETE theme and stamps
 * data-theme="light" or data-theme="dark" on <html>. The stylesheet therefore
 * only ever answers "which of the two?", with no media query racing an
 * attribute and no wrong-theme flash.
 *
 * The resolve-and-stamp half also runs inline in <head>, before first paint;
 * this file adds the interactive parts once the document is ready.
 */
(function () {
  "use strict";

  var KEY = "cybershield-theme";
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;

  function preference() {
    try {
      var stored = localStorage.getItem(KEY);
      if (stored === "light" || stored === "dark" || stored === "system") { return stored; }
    } catch (e) { /* private mode, blocked storage: fall through to the default */ }
    return "system";
  }

  function resolve(pref) {
    if (pref === "light" || pref === "dark") { return pref; }
    return media && media.matches ? "light" : "dark";
  }

  function apply(pref) {
    document.documentElement.setAttribute("data-theme", resolve(pref));
    document.documentElement.setAttribute("data-theme-pref", pref);
  }

  function store(pref) {
    try { localStorage.setItem(KEY, pref); } catch (e) { /* not fatal */ }
  }

  // Follow the OS while the preference is "system" — including a change made
  // while the page is open.
  if (media) {
    var onChange = function () { if (preference() === "system") { apply("system"); } };
    if (media.addEventListener) { media.addEventListener("change", onChange); }
    else if (media.addListener) { media.addListener(onChange); }
  }

  function ready(fn) {
    if (document.readyState !== "loading") { fn(); }
    else { document.addEventListener("DOMContentLoaded", fn); }
  }

  ready(function () {
    var current = preference();

    // Theme switcher: a radio group, so arrow keys and screen readers work.
    var radios = document.querySelectorAll('input[name="theme-pref"]');
    for (var i = 0; i < radios.length; i++) {
      radios[i].checked = radios[i].value === current;
      radios[i].addEventListener("change", function () {
        if (!this.checked) { return; }
        store(this.value);
        apply(this.value);
      });
    }

    // Off-canvas sidebar on narrow screens.
    var toggle = document.getElementById("nav-toggle");
    var scrim = document.getElementById("nav-scrim");
    function closeNav() {
      document.body.classList.remove("nav-open");
      if (toggle) { toggle.setAttribute("aria-expanded", "false"); }
    }
    if (toggle) {
      toggle.addEventListener("click", function () {
        var open = document.body.classList.toggle("nav-open");
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
    }
    if (scrim) { scrim.addEventListener("click", closeNav); }
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { closeNav(); }
    });

    // Clock in the top bar. Local time, from the browser — no server data is
    // invented for it, and it is hidden entirely on narrow screens.
    var clock = document.getElementById("clock");
    if (clock) {
      var tick = function () {
        var now = new Date();
        clock.textContent = now.toLocaleDateString(undefined, {
          month: "short", day: "numeric"
        }) + " · " + now.toLocaleTimeString(undefined, {
          hour: "2-digit", minute: "2-digit"
        });
      };
      tick();
      setInterval(tick, 30000);
    }
  });
})();
