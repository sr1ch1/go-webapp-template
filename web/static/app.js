// htmx: the CSP forbids eval, and the Alpine CSP build relies on this too.
htmx.config.allowEval = false;
// Cross-site requests never carry the app's own headers, so keeping htmx
// same-origin bounds the damage from injected hx-* attributes.
htmx.config.selfRequestsOnly = true;

document.addEventListener("alpine:init", function () {
  Alpine.data("dropdown", function () {
    return {
      open: false,
      toggle: function () {
        this.open = !this.open;
      },
    };
  });
});
