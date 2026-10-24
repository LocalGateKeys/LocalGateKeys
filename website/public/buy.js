// Checkout for LocalGateKeys Pro (the only script on the site; see /buy and _headers).
//
// A random claim token is made in this browser and passed to Paddle as custom
// data (lgk_claim). The licence Worker stores the licence under that token, and
// Paddle sends the buyer to https://<licence host>/license/<token> after paying.
// The token never leaves this browser except to Paddle and the Worker.
//
// Paddle payment links (?_ptxn=txn_...) are refused: Paddle.js would open that
// transaction, whose custom data (and so the licence page) was chosen by
// whoever created it, not by this browser (audit 2026-10-24 M-2).
(function () {
  "use strict";

  var root = document.getElementById("buy");
  var button = document.getElementById("open-checkout");
  var statusLine = document.getElementById("checkout-status");
  var after = document.getElementById("after-purchase");
  var link = document.getElementById("licence-link");
  var KEY = "lgk_claim";
  var TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

  function setStatus(text) {
    statusLine.textContent = text;
  }

  // Must run before Paddle.Initialize, which opens ?_ptxn= checkouts itself.
  function stripPaymentLink() {
    var url;
    try { url = new URL(window.location.href); } catch (e) { return false; }
    if (!url.searchParams.has("_ptxn")) return false;
    url.searchParams.delete("_ptxn");
    try {
      window.history.replaceState(window.history.state, "", url.pathname + url.search + url.hash);
    } catch (e) {
      window.location.replace(url.pathname + url.search + url.hash);
    }
    return true;
  }

  var hadPaymentLink = stripPaymentLink();

  function newClaim() {
    var bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    var text = "";
    for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Keep one token per tab, so reopening the checkout after closing it still
  // leads to the same licence page. Forget it once a purchase completes.
  function claim() {
    var token = null;
    try { token = sessionStorage.getItem(KEY); } catch (e) { token = null; }
    if (!token || !TOKEN_RE.test(token)) {
      token = newClaim();
      try { sessionStorage.setItem(KEY, token); } catch (e) { /* private mode: token lives in memory only */ }
    }
    return token;
  }

  function forgetClaim() {
    try { sessionStorage.removeItem(KEY); } catch (e) { /* nothing stored */ }
  }

  var token = claim();
  var licenceUrl = root.dataset.licenceBase + token;

  function showLicenceLink() {
    link.href = licenceUrl;
    after.hidden = false;
  }

  if (!window.Paddle || !window.Paddle.Initialize) {
    setStatus("The checkout could not be loaded. Check that nothing is blocking cdn.paddle.com, reload the page, or email support@localgatekeys.app.");
    return;
  }

  window.Paddle.Initialize({
    token: root.dataset.paddleToken,
    eventCallback: function (event) {
      if (!event || !event.name) return;
      if (event.name === "checkout.completed") {
        var data = event.data || {};
        var paidClaim = data.custom_data ? data.custom_data.lgk_claim : (data.customData ? data.customData.lgk_claim : null);
        if (paidClaim !== token) {
          // Not the checkout this page opened: never link to a licence page
          // this browser did not choose.
          setStatus("Payment received, but not for the checkout opened on this page. Find your licence at https://licenses.localgatekeys.app/recover with the order number from your receipt, or email support@localgatekeys.app.");
          return;
        }
        showLicenceLink();
        forgetClaim();
        setStatus("Payment received. Taking you to your licence page...");
      } else if (event.name === "checkout.closed") {
        setStatus("Checkout closed. Nothing was charged unless you completed the payment.");
      } else if (event.name === "checkout.error") {
        setStatus("The checkout reported an error. Please try again, or email support@localgatekeys.app.");
      }
    }
  });

  function openCheckout() {
    window.Paddle.Checkout.open({
      items: [{ priceId: root.dataset.priceId, quantity: 1 }],
      customData: { lgk_claim: token },
      settings: {
        displayMode: "overlay",
        locale: "en",
        allowLogout: true,
        successUrl: licenceUrl
      }
    });
    setStatus("Checkout open.");
  }

  button.disabled = false;
  button.addEventListener("click", openCheckout);
  if (hadPaymentLink) {
    // Do not open anything automatically from a link someone sent.
    setStatus("Payment links are not used on this site. Use the Open secure checkout button to buy here.");
  } else {
    setStatus("Ready.");
    openCheckout();
  }
})();
