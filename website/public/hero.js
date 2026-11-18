// Home page screenshot viewer: pick a platform, then use the arrows (or the left and
// right keys) to move through its screenshots one at a time. The platform card stays
// beside the screenshot and shows the count. Without this script the section stays a
// sideways filmstrip. Every text it shows comes from the translated page markup.
(function () {
  "use strict";

  var section = document.querySelector(".gallery");
  var strip = section && section.querySelector(".strip");
  if (!strip) return;
  var chips = [].slice.call(section.querySelectorAll(".dock a"));
  var groups = [].slice.call(strip.querySelectorAll(".group"));
  var prev = section.querySelector(".arrow.prev");
  var next = section.querySelector(".arrow.next");
  if (!groups.length || !prev || !next) return;
  var template = strip.getAttribute("data-count") || "{n} / {total}";
  var g = 0;
  var pos = groups.map(function () { return 0; });

  function shotsOf(group) { return group.querySelectorAll(".frame"); }

  function show() {
    groups.forEach(function (group, gi) {
      group.classList.toggle("on", gi === g);
      [].forEach.call(shotsOf(group), function (shot, si) {
        shot.classList.toggle("on", gi === g && si === pos[gi]);
      });
    });
    chips.forEach(function (a, i) {
      if (i === g) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current");
    });
    var group = groups[g];
    var shots = shotsOf(group);
    group.insertBefore(prev, shots[0]);
    group.appendChild(next);
    // Load the shown screenshot and its neighbours now, so an arrow press never shows an empty frame.
    [pos[g], pos[g] + 1, pos[g] - 1].forEach(function (i) {
      var img = shots[(i + shots.length) % shots.length].querySelector("img");
      if (img) img.loading = "eager";
    });
    var n = group.querySelector(".divider .n");
    if (n) {
      n.textContent = template
        .replace("{n}", String(pos[g] + 1))
        .replace("{total}", String(shots.length));
    }
  }

  function step(by) {
    var total = shotsOf(groups[g]).length;
    pos[g] = (pos[g] + by + total) % total;
    show();
  }

  chips.forEach(function (a, i) {
    a.addEventListener("click", function (e) { e.preventDefault(); g = i; show(); });
  });
  prev.addEventListener("click", function () { step(-1); });
  next.addEventListener("click", function () { step(1); });
  strip.addEventListener("keydown", function (e) {
    if (e.key === "ArrowLeft") { step(-1); e.preventDefault(); }
    if (e.key === "ArrowRight") { step(1); e.preventDefault(); }
  });
  var label = strip.getAttribute("data-viewer-label");
  if (label) strip.setAttribute("aria-label", label);
  section.classList.add("viewer");
  show();
})();

// Home page headline: put each short sentence on its own line. Without this script the
// headline wraps wherever it fits.
(function () {
  "use strict";

  var title = document.getElementById("hero-title");
  if (!title || title.children.length) return;
  var parts = (title.textContent || "").match(/[^.。]+[.。]?/g);
  if (!parts || parts.length < 2) return;
  title.textContent = "";
  parts.forEach(function (part, i) {
    var line = document.createElement("span");
    line.textContent = part.trim();
    if (i) title.appendChild(document.createTextNode(" "));
    title.appendChild(line);
  });
})();
