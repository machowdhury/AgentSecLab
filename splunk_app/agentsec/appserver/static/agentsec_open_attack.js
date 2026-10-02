/* Opens Attack Service on the hostname already in the browser address bar. */
(function () {
  "use strict";
  var params = new URLSearchParams(window.location.search);
  var path = params.get("path") || "/";
  if (path.charAt(0) !== "/") {
    path = "/" + path;
  }
  var target = window.location.protocol + "//" + window.location.hostname + ":5001" + path;
  var note = document.getElementById("agentsec-open-attack");
  if (note) {
    note.textContent = "Opening Attack Service at " + target;
  }
  window.location.replace(target);
})();
