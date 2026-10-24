"use strict";
// Localized label dictionaries for the conservative DOM heuristics used by
// login-safety.js and content.js. No DOM, network, or vault access here.
//
// Matching rules (deliberately strict):
//   - sign-in buttons: the whole cleaned label (lowercased, whitespace
//     collapsed, trimmed) must equal a dictionary entry.
//   - logout / login-control / failure phrases: a phrase must appear as a
//     whole word (letter/digit boundaries, Unicode aware); failure stems may
//     carry an inflectional suffix but never a prefix.
//
// Languages: English, Polish, German, French, Spanish, Italian, Portuguese,
// Dutch, Greek.
(() => {
  // Strict shape check: a page element with id="LGKHeuristics" is reachable
  // through named property access and must not suppress the module.
  if (typeof globalThis.LGKHeuristics?.isSignInLabel === "function") return;
  const languages = {
    en: {
      signIn: ["sign in", "signin", "log in", "login", "log on", "logon"],
      logout: ["log out", "logout", "sign out", "signout", "log off", "logoff"],
      loginControl: ["sign in", "log in", "login", "continue", "next", "submit", "connect", "authenticate"],
      failure: ["invalid", "incorrect", "wrong", "failed", "failure", "try again", "not recognized", "not recognised",
        "could not sign", "couldn't sign", "couldn’t sign", "unable to sign", "authentication error", "password expired"],
    },
    pl: {
      signIn: ["zaloguj", "zaloguj się", "logowanie"],
      logout: ["wyloguj", "wyloguj się", "wylogowanie"],
      loginControl: ["zaloguj", "zaloguj się", "dalej", "kontynuuj"],
      failure: ["nieprawidłow", "niepoprawn", "błędn", "spróbuj ponownie", "nie udało", "nie powiodło"],
    },
    de: {
      signIn: ["anmelden", "einloggen", "login", "jetzt anmelden"],
      logout: ["abmelden", "ausloggen", "logout"],
      loginControl: ["anmelden", "einloggen", "weiter", "fortfahren", "absenden"],
      failure: ["ungültig", "falsch", "fehlgeschlagen", "erneut versuchen", "nicht erkannt", "nicht korrekt"],
    },
    fr: {
      signIn: ["se connecter", "connexion", "connectez-vous", "s'identifier", "s’identifier", "me connecter"],
      logout: ["se déconnecter", "déconnexion", "déconnecter"],
      loginControl: ["se connecter", "connexion", "continuer", "suivant", "valider"],
      failure: ["invalide", "incorrect", "échec", "échoué", "réessayer", "réessayez", "non reconnu"],
    },
    es: {
      signIn: ["iniciar sesión", "acceder", "entrar", "ingresar", "identificarse"],
      logout: ["cerrar sesión", "salir", "desconectar"],
      loginControl: ["iniciar sesión", "acceder", "entrar", "ingresar", "continuar", "siguiente", "enviar"],
      failure: ["inválid", "incorrect", "erróne", "erroneo", "falló", "fallido", "inténtalo de nuevo", "intente de nuevo", "no reconocid"],
    },
    it: {
      signIn: ["accedi", "entra", "login", "accedere"],
      logout: ["esci", "disconnetti", "disconnettersi", "logout"],
      loginControl: ["accedi", "entra", "continua", "avanti", "invia"],
      failure: ["non valid", "errat", "fallit", "riprova", "non riconosciut"],
    },
    pt: {
      signIn: ["entrar", "iniciar sessão", "fazer login", "acessar", "aceder"],
      logout: ["sair", "terminar sessão", "encerrar sessão", "desconectar"],
      loginControl: ["entrar", "iniciar sessão", "continuar", "próximo", "seguinte", "avançar", "enviar"],
      failure: ["inválid", "incorret", "falhou", "falha", "tente novamente", "não reconhecid"],
    },
    nl: {
      signIn: ["inloggen", "aanmelden", "log in", "login"],
      logout: ["uitloggen", "afmelden", "log uit"],
      loginControl: ["inloggen", "aanmelden", "verder", "doorgaan", "volgende", "versturen"],
      failure: ["ongeldig", "onjuist", "mislukt", "probeer opnieuw", "verkeerd", "niet herkend"],
    },
    el: {
      signIn: ["σύνδεση", "είσοδος", "συνδεθείτε", "σύνδεσή"],
      logout: ["αποσύνδεση", "έξοδος", "αποσυνδεθείτε"],
      loginControl: ["σύνδεση", "είσοδος", "συνέχεια", "επόμενο", "υποβολή"],
      failure: ["λανθασμέν", "μη έγκυρ", "άκυρ", "απέτυχε", "αποτυχία", "προσπαθήστε ξανά", "δεν αναγνωρ"],
    },
  };
  // Path fragments that identify a logout link regardless of display language.
  const logoutHrefFragments = ["logout", "signout", "log-out", "sign-out", "log_out", "sign_out", "logoff", "wyloguj", "abmelden", "deconnexion", "cerrar-sesion", "uitloggen"];

  const clean = s => String(s || "").replace(/\s+/g, " ").trim().toLowerCase();
  const escape = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const collect = key => {
    const out = new Set();
    for (const lang of Object.values(languages)) for (const phrase of lang[key]) out.add(clean(phrase));
    return [...out].sort((a, b) => b.length - a.length);
  };
  // Phrase lists may contain spaces; allow any single whitespace run between words.
  const phrasePattern = phrases => phrases.map(p => escape(p).replace(/ /g, "\\s+")).join("|");
  // Unicode-aware word boundaries: `\b` only knows ASCII letters.
  const B0 = "(?<![\\p{L}\\p{N}])", B1 = "(?![\\p{L}\\p{N}])";
  const wholeWord = phrases => new RegExp(`${B0}(?:${phrasePattern(phrases)})${B1}`, "iu");
  // Failure stems: prefix boundary only, so "nieprawidłowe"/"ungültiges" match but "blog in" does not match "login".
  const stem = phrases => new RegExp(`${B0}(?:${phrasePattern(phrases)})`, "iu");

  const signInLabels = new Set(collect("signIn"));
  const logoutPattern = wholeWord(collect("logout"));
  const logoutHrefPattern = new RegExp(`(?:${logoutHrefFragments.map(escape).join("|")})`, "i");
  const loginControlPattern = wholeWord(collect("loginControl"));
  const failurePattern = stem(collect("failure"));

  const heuristics = {
    languages: Object.freeze(Object.keys(languages)),
    clean,
    isSignInLabel: label => signInLabels.has(clean(label)),
    isLogoutLabel: text => logoutPattern.test(String(text || "")),
    isLogoutHref: href => logoutHrefPattern.test(String(href || "")),
    isLoginControlLabel: label => loginControlPattern.test(String(label || "")),
    hasFailureText: text => failurePattern.test(String(text || "")),
  };
  // Own, non-writable property: shadows any same-named page element for good.
  Object.defineProperty(globalThis, "LGKHeuristics", { value: Object.freeze(heuristics), writable: false, configurable: false, enumerable: false });
})();
