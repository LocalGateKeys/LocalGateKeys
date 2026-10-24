"""Generate ``tests/vectors/password_strength/vectors.json`` from the desktop's strength estimate.

The phones port ``localvault.password_tools.estimate_strength`` (Android: lgk-core
``app.localgatekeys.core.password.StrengthEstimator``) and must give the same ``score`` for every
password here and a ``guesses_log10`` within a small tolerance. The password list is fixed
(hand-picked cases for every matcher plus a seeded random set), so the file only changes when the
estimator does.

Usage::

    python scripts/make_password_strength_vectors.py [OUT_FILE]

Read-only apart from OUT_FILE; it touches no vault or user data. Passwords for which the desktop
estimator itself raises (for example a float overflow on extremely long inputs) are left out and
listed under ``"desktop_raises"``.
"""

# ruff: noqa: S311  (the random generator only picks test inputs)

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from localvault import password_tools  # noqa: E402
from localvault.password_tools import WORDLIST, estimate_strength, load_wordlist  # noqa: E402

HAND_PICKED = [
    # empty, tiny, brute force
    "", "a", "ab", "Z9", "x7Q", "aB3$", "zK9#mQ2!", "qwxzvbnmlkjh", "Xk8#vQ2!mZ7@pL4&",
    "kd8Fj3Ls0Pq2", "9fj2K!a0Q#xZ", "uY7%tR4^eW1&qA",
    # the review's examples
    "Password123!", "P@ssw0rd2026", "Qwerty123456!", "Password1", "Welcome1", "Admin123",
    # common passwords, case, l33t, reversed
    "password", "PASSWORD", "Password", "pAssWord", "p@ssw0rd", "P4$$w0rd", "drowssap", "DROWSSAP", "dr0wss@p",
    "123456", "iloveyou", "1L0V3Y0U", "trustno1", "letmein", "monkey", "dragon", "sunshine1", "superman",
    "green day", "number one", "Tr0ub4dor&3", "trustno1trustno1",
    # dictionary words (the packaged list)
    "correct horse battery staple", "correcthorsebatterystaple", "CorrectHorseBatteryStaple",
    "correct horse battery staple 42", "horse", "battery", "maple orbit", "Maple-Orbit-7731",
    "acorn-actor-amber-anchor", "zephyr zinc zipper zone", "elephantgiraffe", "tigerlionbear",
    # sequences
    "abc", "abcdef", "abcdefghijklmnop", "zyxwvu", "ZYXWVU", "123456789", "987654321", "13579", "abcXYZ123",
    "ABCDEFG", "0123456789abcdef", "mnopqr12", "fedcba!!", "αβγδε", "абвгде",
    # repeats
    "aaa", "aaaaaaaaaaaa", "abcabcabc", "abcabcabcabc", "xyxyxyxyxy", "123123123", "hellohello",
    "Passw0rdPassw0rd", "!!!!!!!!", "zzzzzzzzzzzzzzzzzzzz", "ab\nab\nab\n", "a\na\na", "qwerqwerqwerqwer",
    # keyboard walks
    "qwerty", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsx", "1qaz2wsx", "QWERTY", "!QAZ@WSX",
    "poiuytrewq", "zaq12wsx", "plmokn", "1q2w3e4r5t", "asdfjkl;", "~!@#$%^&*()_+", "`1234567890-=",
    "qwertyuiopasdfghjkl", "mju7ygv", "QweRtyUio",
    # dates
    "1987", "2026", "1900", "2050", "1899", "2051", "13101987", "19871013", "10/13/1987", "13.10.87",
    "1987-10-13", "31-12-1999", "4/7/76", "2001_02_03", "8/31/2026", "120887", "091185", "11223344",
    "born1991", "march1987", "1234 5678", "0000", "9999", "2024-02-30", "1/1/1", "99.99.99",
    # mixed patterns
    "summer2026!", "Summer2026!", "Winter2025", "football1990", "michael1985", "jordan23", "qwerty2026",
    "admin@2026", "letmein123!", "ilovepizza", "MyDogIsCute", "monkey123monkey123", "batman!batman!",
    "sunshine-rainbow-unicorn", "Tr4ilT0wer!", "hunter2", "correct-horse", "abc123abc123", "pass1234word",
    # Unicode
    "pässwörd", "Ünïcödé-Pässwört-2026", "日本語のパスワード", "пароль", "Пароль123", "contraseña", "密码123456",
    "😀😀😀😀", "🔑🔒🗝️🔐 keys", "ǅungla", "İstanbul1923", "ΣΊΣΥΦΟΣ", "ß", "ﬀﬁﬂ", "①②③④", "²³¹", "١٢٣٤٥٦",
    "١٩٨٧", "  spaces  ", "tab\tseparated", "ééé",
    # separated dates with other digits and separators (Python's \d and \s are Unicode)
    "\u0661\u0663/\u0661\u0660/\u0661\u0669\u0668\u0667", "\u0661\u0669\u0668\u0667-\u0661\u0660-\u0661\u0663",
    "\uff11\uff13-\uff11\uff10-\uff11\uff19\uff18\uff17", "\uff11\uff19\uff18\uff17/\uff11\uff10/\uff11\uff13",
    "\u09e7\u09e9/\u09e7\u09e6/\u09e7\u09ef\u09ee\u09ed", "\u09e7\u09ef\u09ee\u09ed_\u09e7\u09e6_\u09e7\u09e9",
    "13\u00a010\u00a01987", "13\u300010\u30001987", "13\u202810\u20281987", "1987\u3000 10\u300013", "13\u001c10\u001c1987",
    "pass\u0661\u0663/\u0661\u0660/\u0661\u0669\u0668\u0667word", "\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18",
    # repeats split by a newline (Python's "." stops at one)
    "abc\nabc\nabc", "x\nx\nx\nx", "ab\nab", "\n\n\n\n", "hello\nhello\nhello\nhello", "aa\naa\naaaa",
    # long
    "a" * 120, "ab" * 70, "Xk8#vQ2!" * 15, "correcthorsebatterystaple" * 6, "1234567890" * 15,
    "The quick brown fox jumps over the lazy dog, then naps by the river until the sun goes down again!",
]


def random_passwords(count: int) -> list[str]:
    rng = random.Random(20261024)
    words = list(load_wordlist())
    alphabets = [
        "abcdefghijklmnopqrstuvwxyz",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}:,.?",
        "0123456789",
    ]
    out: list[str] = []
    for k in range(count):
        kind = k % 4
        if kind == 0:
            alphabet = alphabets[rng.randrange(len(alphabets))]
            out.append("".join(rng.choice(alphabet) for _ in range(rng.randint(4, 24))))
        elif kind == 1:
            sep = rng.choice(["-", " ", ".", "", "_"])
            out.append(sep.join(rng.choice(words) for _ in range(rng.randint(2, 6))))
        elif kind == 2:
            word = rng.choice(list(password_tools.COMMON_PASSWORDS))
            suffix = rng.choice(["", "1", "!", "123", "2026", "?", "@1", str(rng.randint(1950, 2030))])
            prefix = rng.choice(["", "", "My", "the", "!"])
            word = word.capitalize() if rng.random() < 0.4 else word
            out.append(prefix + word + suffix)
        else:
            parts = [rng.choice(words), str(rng.randint(0, 9999)), rng.choice(["qwerty", "asdf", "abc", "xyz", "zxcv", "!@#"]),
                     rng.choice(words).upper()]
            rng.shuffle(parts)
            out.append("".join(parts[: rng.randint(2, 4)]))
    return out


def main() -> int:
    out_file = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests" / "vectors" / "password_strength" / "vectors.json"
    seen: set[str] = set()
    vectors: list[dict[str, object]] = []
    raises: list[str] = []
    for password in HAND_PICKED + random_passwords(240):
        if password in seen:
            continue
        seen.add(password)
        try:
            estimate = estimate_strength(password)
        except (OverflowError, ValueError) as exc:
            raises.append(f"{password!r}: {type(exc).__name__}")
            continue
        vectors.append({"password": password, "score": estimate.score, "guesses_log10": round(estimate.guesses_log10, 6)})
    packaged = load_wordlist()
    doc = {
        "about": "Desktop localvault.password_tools.estimate_strength; generated by scripts/make_password_strength_vectors.py.",
        "dictionary": {
            "wordlist": "src/localvault/assets/eff_large_wordlist.txt (load_wordlist rules)",
            "wordlist_count": len(packaged),
            "extra_words": sorted(set(WORDLIST) - set(packaged)),
        },
        "desktop_raises": raises,
        "vectors": vectors,
    }
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(vectors)} vectors, {len(raises)} raised -> {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
