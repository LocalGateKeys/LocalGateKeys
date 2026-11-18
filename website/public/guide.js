// Get started and User guide: small helpers on top of pages that work without script.
// - Marks the step or topic being read in the side list (aria-current="location").
// - User guide on narrow screens: the "On this tab" list folds into one line and
//   folds again after a topic is picked; on wide screens it always stays open.
// - Keeps the selected platform tab in view inside the tab bar on phones.
// No network, no storage.
(function () {
  "use strict";

  document.documentElement.classList.add("js");

  var narrow = window.matchMedia ? window.matchMedia("(max-width: 860px)") : null;
  var boxes = Array.prototype.slice.call(document.querySelectorAll(".help-toc-box"));

  function fitBoxes() {
    var small = narrow && narrow.matches;
    boxes.forEach(function (box) { box.open = !small; });
  }
  if (boxes.length) {
    fitBoxes();
    if (narrow) {
      if (narrow.addEventListener) narrow.addEventListener("change", fitBoxes);
      else if (narrow.addListener) narrow.addListener(fitBoxes);
    }
    boxes.forEach(function (box) {
      box.addEventListener("click", function (e) {
        var link = e.target.closest ? e.target.closest("a") : null;
        if (link && narrow && narrow.matches) box.open = false;
      });
    });
  }

  // Side lists whose links point at sections on this page.
  var lists = Array.prototype.slice.call(document.querySelectorAll(".gs-rail, .help-toc")).map(function (nav) {
    var links = Array.prototype.slice.call(nav.querySelectorAll('a[href^="#"]'));
    return {
      nav: nav,
      items: links.map(function (a) {
        return { link: a, target: document.getElementById(a.getAttribute("href").slice(1)) };
      }).filter(function (item) { return item.target; })
    };
  });

  function spy() {
    var line = Math.min(window.innerHeight * 0.3, 180);
    lists.forEach(function (list) {
      if (!list.nav.offsetParent && getComputedStyle(list.nav).position !== "fixed") return;
      var current = null;
      list.items.forEach(function (item) {
        if (item.target.getBoundingClientRect().top <= line) current = item;
      });
      if (!current && list.items.length) current = list.items[0];
      list.items.forEach(function (item) {
        if (item === current) item.link.setAttribute("aria-current", "location");
        else item.link.removeAttribute("aria-current");
      });
    });
  }

  var queued = false;
  function queue() {
    if (queued) return;
    queued = true;
    window.requestAnimationFrame(function () { queued = false; spy(); });
  }

  // Platform tab bar: scroll the selected tab into view when it overflows (phones).
  var bar = document.querySelector(".help-tabs");
  function centreTab() {
    if (!bar || bar.scrollWidth <= bar.clientWidth) return;
    var panels = document.querySelectorAll(".help-panel");
    for (var i = 0; i < panels.length; i++) {
      if (getComputedStyle(panels[i]).display !== "none") {
        var tab = bar.querySelector('[data-tab="' + panels[i].id + '"]');
        if (tab) bar.scrollLeft = tab.offsetLeft - (bar.clientWidth - tab.offsetWidth) / 2;
        return;
      }
    }
  }

  if (lists.length) {
    window.addEventListener("scroll", queue, { passive: true });
    window.addEventListener("resize", queue);
  }
  window.addEventListener("hashchange", function () { centreTab(); queue(); });
  centreTab();
  spy();
})();
