"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createPage } = require("./helpers.cjs");

function heuristics() {
  const p = createPage({ scripts: ["api.js", "heuristics.js"] });
  p.load();
  return p.H();
}

const samples = {
  en: { signIn: "Sign in", logout: "Log out", control: "Continue", failure: "Incorrect password, try again." },
  pl: { signIn: "Zaloguj się", logout: "Wyloguj", control: "Dalej", failure: "Nieprawidłowe hasło" },
  de: { signIn: "Anmelden", logout: "Abmelden", control: "Weiter", failure: "Ungültiges Passwort" },
  fr: { signIn: "Se connecter", logout: "Déconnexion", control: "Continuer", failure: "Mot de passe incorrect" },
  es: { signIn: "Iniciar sesión", logout: "Cerrar sesión", control: "Siguiente", failure: "Contraseña inválida" },
  it: { signIn: "Accedi", logout: "Esci", control: "Avanti", failure: "Password errata" },
  pt: { signIn: "Entrar", logout: "Terminar sessão", control: "Avançar", failure: "Senha inválida" },
  nl: { signIn: "Inloggen", logout: "Uitloggen", control: "Volgende", failure: "Ongeldig wachtwoord" },
  el: { signIn: "Σύνδεση", logout: "Αποσύνδεση", control: "Συνέχεια", failure: "Λανθασμένος κωδικός" },
};

test("dictionary covers the required languages", () => {
  const H = heuristics();
  assert.deepEqual([...H.languages].sort(), ["de", "el", "en", "es", "fr", "it", "nl", "pl", "pt"]);
  for (const [lang, s] of Object.entries(samples)) {
    assert.equal(H.isSignInLabel(s.signIn), true, `${lang} sign-in label`);
    assert.equal(H.isLogoutLabel(s.logout), true, `${lang} logout label`);
    assert.equal(H.isLoginControlLabel(s.control), true, `${lang} login control`);
    assert.equal(H.hasFailureText(s.failure), true, `${lang} failure text`);
  }
});

test("sign-in labels match exactly after cleaning, never by substring", () => {
  const H = heuristics();
  assert.equal(H.isSignInLabel("  LOG   IN  "), true);
  assert.equal(H.isSignInLabel("Sign in now"), false);
  assert.equal(H.isSignInLabel("Sign in with Google"), false);
  assert.equal(H.isSignInLabel("Create account"), false);
  assert.equal(H.isSignInLabel(""), false);
  assert.equal(H.isSignInLabel(null), false);
});

test("logout, login-control and failure phrases respect Unicode word boundaries", () => {
  const H = heuristics();
  assert.equal(H.isLogoutLabel("Logout"), true);
  assert.equal(H.isLogoutLabel("Sign out of all devices"), true);
  assert.equal(H.isLogoutLabel("blogout"), false);
  assert.equal(H.isLogoutLabel("catalogout"), false);
  assert.equal(H.isLogoutLabel("Wylogujemy"), false, "no suffix inflection for whole-word logout phrases");
  assert.equal(H.isLogoutLabel("ΑΠΟΣΎΝΔΕΣΗ"), true, "case-insensitive Greek");
  assert.equal(H.isLogoutHref("/account/logout?next=/"), true);
  assert.equal(H.isLogoutHref("/blog/catalog"), false);
  assert.equal(H.isLoginControlLabel("Dalej"), true);
  assert.equal(H.isLoginControlLabel("Dalejsze informacje"), false);
  assert.equal(H.isLoginControlLabel("Reset password"), false);
  assert.equal(H.hasFailureText("Ungültiges Passwort"), true, "stem matches an inflected suffix");
  assert.equal(H.hasFailureText("Unungültig"), false, "but never with a prefix");
  assert.equal(H.hasFailureText("Welcome back, you are signed in"), false);
  assert.equal(H.hasFailureText("An error occurred"), false, "generic 'error' alone is not a login failure");
  assert.equal(H.hasFailureText("Couldn’t sign you in"), true);
});
