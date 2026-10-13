/* NexaDesk progressive enhancement only. No secrets, no flags, no policy answers
   are embedded in client code. Server-side validation is authoritative (CWE-602). */
(function () {
  "use strict";

  // Dismissable alerts
  document.querySelectorAll(".alert").forEach(function (el) {
    if (el.dataset.dismiss !== undefined) {
      el.setAttribute("tabindex", "0");
      var btn = document.createElement("button");
      btn.className = "btn-secondary";
      btn.textContent = "Dismiss";
      btn.style.float = "right";
      btn.addEventListener("click", function () { el.remove(); });
      el.prepend(btn);
    }
  });

  // Advisory live feedback for password fields (NOT enforcement — server decides).
  var pw = document.querySelector("[data-policy-advisory]");
  if (pw && window.NEXADESK_POLICY) {
    var out = document.getElementById("policy-advice");
    var min = NEXADESK_POLICY.min_length || 4;
    pw.addEventListener("input", function () {
      if (!out) return;
      if (pw.value.length === 0) { out.textContent = ""; return; }
      if (pw.value.length < min) {
        out.textContent = "Advisory: current requirements ask for at least " + min + " characters.";
        out.className = "small alert-warn";
      } else {
        out.textContent = "Meets the advertised minimum. The server makes the final decision.";
        out.className = "small";
      }
    });
  }

  // Copy-to-clipboard helper for lab tokens/flags
  document.querySelectorAll("[data-copy-target]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var t = document.getElementById(btn.getAttribute("data-copy-target"));
      if (t && navigator.clipboard) { navigator.clipboard.writeText(t.textContent.trim()); }
    });
  });
})();
