"use strict";
// chrome.i18n.getMessage backed by _locales/en/messages.json, so tests of the
// popup and content scripts see the same English text a real browser shows.
const fs = require("node:fs");
const path = require("node:path");

const MESSAGES = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "browser-extension", "_locales", "en", "messages.json"), "utf8"));

function getMessage(key, subs = []) {
  const entry = MESSAGES[key];
  if (!entry) return "";
  const list = Array.isArray(subs) ? subs : [subs];
  return entry.message.replace(/\$([A-Za-z0-9_@]+)\$/g, (_, name) => {
    const ph = entry.placeholders?.[name.toLowerCase()];
    return ph ? ph.content.replace(/\$([1-9])/g, (__, n) => list[Number(n) - 1] ?? "") : "";
  });
}

module.exports = { getMessage, MESSAGES };
