"""Local password generation and strength estimation.

Everything here runs offline.  Generation uses the operating system random
source through :mod:`secrets`.  Strength estimation follows the zxcvbn idea:
find the cheapest way an attacker could reproduce the string from known
patterns (dictionary words, l33t substitutions, sequences, repeats, keyboard
walks, dates) and report that guess count, never alphabet-size math.
"""
from __future__ import annotations

import hashlib
import math
import re
import secrets
import string
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from functools import lru_cache
from math import comb
from pathlib import Path
from typing import Any

from .i18n import t

DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?"
AMBIGUOUS = set("Il1O0o|`'\"")
# Display name -> separator character.  Keys are stable preference aliases.
SEPARATORS = {"dash": "-", "space": " ", "dot": ".", "underscore": "_", "none": ""}
WORDLIST_PATH = Path(__file__).resolve().parent / "assets" / "eff_large_wordlist.txt"

# Small built-in fallback used only when the packaged word list is missing.
WORDLIST = ('acorn', 'actor', 'amber', 'anchor', 'angel', 'apple', 'apron', 'arctic', 'arrow', 'artist', 'atlas', 'atom', 'autumn', 'badge', 'baker', 'bamboo', 'banana', 'banner', 'barrel', 'basket', 'beach', 'beacon', 'berry', 'bicycle', 'birch', 'blanket', 'blossom', 'boat', 'border', 'bottle', 'branch', 'breeze', 'bridge', 'bronze', 'bubble', 'bucket', 'butter', 'button', 'cabin', 'cactus', 'camera', 'candle', 'canyon', 'canvas', 'captain', 'carpet', 'castle', 'cedar', 'celery', 'chalk', 'cherry', 'chest', 'cherrywood', 'chess', 'circle', 'citrus', 'cloud', 'clover', 'cocoa', 'comet', 'compass', 'copper', 'coral', 'cotton', 'crane', 'creek', 'cricket', 'crystal', 'daisy', 'dawn', 'desert', 'diamond', 'dolphin', 'dragon', 'drawer', 'dream', 'drum', 'duck', 'eagle', 'earth', 'echo', 'elm', 'ember', 'engine', 'falcon', 'family', 'feather', 'fern', 'ferry', 'field', 'finch', 'fire', 'flame', 'flint', 'flower', 'flute', 'forest', 'fossil', 'fountain', 'fox', 'frame', 'frost', 'galaxy', 'garden', 'garlic', 'gate', 'gem', 'ginger', 'glacier', 'glass', 'globe', 'gold', 'goose', 'grape', 'grass', 'gravity', 'green', 'grove', 'guitar', 'harbor', 'harmony', 'harvest', 'hazel', 'hedge', 'helmet', 'heron', 'hill', 'honey', 'horse', 'ice', 'igloo', 'island', 'ivory', 'jacket', 'jade', 'jasmine', 'jelly', 'jewel', 'jigsaw', 'journal', 'journey', 'judge', 'jungle', 'juniper', 'kettle', 'kite', 'kitten', 'kiwi', 'ladder', 'lagoon', 'lake', 'lamb', 'lantern', 'lark', 'laurel', 'lavender', 'leaf', 'lemon', 'leopard', 'letter', 'lilac', 'lily', 'lime', 'linen', 'lion', 'lizard', 'log', 'lotus', 'lunar', 'maple', 'marble', 'meadow', 'melon', 'mercury', 'meteor', 'mint', 'mirror', 'mist', 'moon', 'moss', 'mountain', 'mouse', 'music', 'mustard', 'nebula', 'needle', 'nest', 'nickel', 'night', 'north', 'note', 'oak', 'oasis', 'ocean', 'olive', 'onyx', 'opal', 'orange', 'orbit', 'orchid', 'otter', 'owl', 'oyster', 'paddle', 'painter', 'palace', 'palm', 'panda', 'paper', 'parrot', 'pasture', 'peach', 'pearl', 'pebble', 'pelican', 'pepper', 'petal', 'piano', 'picnic', 'pigeon', 'pine', 'planet', 'plum', 'pocket', 'polar', 'pond', 'poppy', 'portal', 'potato', 'pottery', 'prairie', 'prism', 'pumpkin', 'quartz', 'queen', 'quill', 'quilt', 'rabbit', 'radar', 'radio', 'rain', 'rainbow', 'raven', 'reef', 'ribbon', 'river', 'robin', 'rocket', 'rose', 'ruby', 'saddle', 'saffron', 'sage', 'sailor', 'salmon', 'salt', 'sand', 'satin', 'school', 'seagull', 'seed', 'shadow', 'shell', 'shield', 'silver', 'sky', 'slate', 'snow', 'soap', 'solar', 'song', 'south', 'sparrow', 'spice', 'spider', 'spruce', 'squirrel', 'star', 'stone', 'storm', 'story', 'stream', 'stripe', 'sugar', 'summer', 'summit', 'sun', 'sunset', 'swan', 'table', 'tango', 'tea', 'temple', 'thorn', 'thunder', 'tide', 'tiger', 'timber', 'tin', 'toast', 'tomato', 'torch', 'tower', 'trail', 'train', 'tree', 'triangle', 'tulip', 'tunnel', 'turtle', 'umbrella', 'valley', 'vapor', 'velvet', 'vessel', 'violet', 'violin', 'walnut', 'water', 'wave', 'wheat', 'wheel', 'whisper', 'willow', 'wind', 'window', 'winter', 'wolf', 'wood', 'wool', 'world', 'wren', 'yellow', 'yogurt', 'zebra', 'zenith', 'zephyr', 'zinc', 'zipper', 'zone')

# Frequently used passwords, most common first.  Compiled offline from the
# well-known public "most used passwords" rankings (RockYou-derived and annual
# NordPass/SplashData style lists).  Order approximates popularity; the rank
# feeds the dictionary guess estimate.
COMMON_PASSWORDS: tuple[str, ...] = (
    "123456", "password", "123456789", "12345678", "12345", "1234567", "qwerty", "111111", "1234567890", "123123",
    "abc123", "1234", "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine",
    "princess", "letmein", "654321", "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop", "superman", "asdfghjkl",
    "password123", "admin", "welcome", "login", "football", "baseball", "master", "hello", "freedom", "whatever",
    "qazwsx", "trustno1", "starwars", "shadow", "michael", "jennifer", "jordan", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom1", "777777", "pass", "maggie", "159753", "aaaaaa", "ginger", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea", "biteme", "matthew", "access",
    "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor",
    "monitoring", "montana", "moon", "moscow", "william", "corvette", "hello123", "martin", "heather", "secret",
    "merlin", "diamond", "1234qwer", "gfhjkm", "hammer", "silver", "222222", "88888888", "anthony", "justin",
    "test", "bailey", "q1w2e3r4t5", "patrick", "internet", "scooter", "orange", "11111", "golfer", "cookie",
    "richard", "samantha", "bigdog", "guitar", "jackson", "whatever1", "anything", "google", "facebook", "liverpool",
    "chicken", "mustang", "midnight", "rainbow", "flower", "purple", "angel", "junior", "nathan", "arsenal",
    "chelsea1", "cowboys", "eagles", "steelers", "lakers", "rangers", "yellow", "camaro", "secret1", "dick",
    "falcon", "iceman", "tigers", "boomer", "miller", "nascar", "banana", "hotdog", "killer", "jasper",
    "zxcvbnm1", "asdfgh", "asdf1234", "a123456", "123qwe", "qwe123", "1q2w3e", "azerty", "loveme", "fuckyou",
    "pokemon", "696969", "kitten", "lol123", "snoopy", "123654", "abcd1234", "abcdef", "abcdefg", "abcdefgh",
    "passw0rd", "p@ssw0rd", "P@ssw0rd", "Password", "Password1", "Password123", "Welcome1", "welcome1", "Admin123", "admin123",
    "root", "toor", "changeme", "default", "guest", "letmein1", "qwerty1", "qwerty12", "qwerty1234", "1q2w3e4r5t",
    "123abc", "123456a", "123456789a", "12345678a", "1234561", "12345679", "1234554321", "123123123", "1234512345", "121212",
    "7777777", "666666", "999999", "888888", "333333", "444444", "123789", "456789", "147258369", "159357",
    "741852963", "963852741", "102030", "112112", "123000", "100200", "1q2w3e4r5t6y", "qwertyui", "qwertyu", "qweasdzxc",
    "asdasd", "asd123", "zxczxc", "qweqwe", "poiuyt", "mnbvcxz", "lkjhgfdsa", "ytrewq", "asdfasdf", "zxcvbnm",
    "iloveyou1", "iloveyou2", "iloveu", "lovely", "loveyou", "sweety", "babygirl", "baby", "angel1", "angels",
    "princess1", "flowers", "butterfly", "bubbles", "cupcake", "chocolate", "vanilla", "cookies", "pumpkin", "peanut",
    "jesus", "jesus1", "blessed", "heaven", "trinity", "faith", "hope", "grace", "peace", "forever",
    "friends", "family", "mother", "father", "brother", "sister", "daddy", "mommy", "grandma", "sunshine1",
    "spring", "winter", "autumn", "december", "november", "october", "september", "august", "july", "june",
    "january", "february", "march", "april", "monday", "friday", "saturday", "sunday", "tuesday", "thursday",
    "america", "canada", "london", "paris", "berlin", "madrid", "rome", "tokyo", "sydney", "boston",
    "newyork", "chicago", "houston", "denver", "phoenix", "seattle", "miami", "atlanta", "vegas", "texas",
    "florida", "california", "carolina", "georgia", "virginia", "mexico", "brazil", "italia", "espana", "france",
    "ferrari", "porsche", "mercedes", "toyota", "honda", "nissan", "yamaha", "harley1", "jaguar", "lincoln",
    "cowboy", "soldier", "warrior", "knight", "wizard", "ninja", "pirate", "samurai", "viking", "gladiator",
    "spider", "spiderman", "ironman", "hulk", "thor", "wolverine", "xmen", "avengers", "marvel", "gotham",
    "gandalf", "frodo", "legolas", "hobbit", "potter", "hermione", "voldemort", "dumbledore", "hogwarts", "gryffindor",
    "pikachu", "charizard", "bulbasaur", "squirtle", "mewtwo", "zelda", "mario", "luigi", "sonic", "pacman",
    "nintendo", "playstation", "xbox", "gamer", "gaming", "minecraft", "fortnite", "roblox", "halo", "doom",
    "metallica", "nirvana", "eminem", "beatles", "slipknot", "rockstar", "music", "guitar1", "drummer", "singer",
    "coffee", "pizza", "burger", "cheese1", "sugar", "candy", "honey", "apple", "cherry", "lemon",
    "tiger", "lion", "bear", "wolf", "eagle", "hawk", "shark", "dolphin", "panda", "koala",
    "puppy", "doggy", "kitty", "bunny", "turtle", "monkey1", "dragon1", "phoenix1", "unicorn", "pegasus",
    "redsox", "cubs", "dodgers", "giants", "patriots", "packers", "broncos", "raiders", "celtics", "bulls",
    "manchester", "barcelona", "realmadrid", "juventus", "chelsea12", "arsenal1", "liverpool1", "ronaldo", "messi", "beckham",
    "hunter1", "killer1", "master1", "shadow1", "soccer1", "football1", "baseball1", "hockey1", "basketball", "swimming",
    "golf", "tennis", "cricket", "rugby", "boxing", "skate", "surfer", "runner", "biker", "racing",
    "nothing", "something", "anything1", "everything", "whocares", "idontknow", "letmein123", "openup", "opensesame", "trustme",
    "temp", "temp123", "test123", "test1234", "testing", "tester", "demo", "demo123", "sample", "example",
    "user", "user123", "username", "administrator", "manager", "operator", "service", "support", "system", "server",
    "oracle", "mysql", "postgres", "cisco", "linux", "windows", "ubuntu", "debian", "apple123", "android",
    "secure", "security", "private", "hidden", "locked", "unlock", "access1", "accessdenied", "enter", "entry",
    "money", "money1", "cash", "rich", "dollar", "million", "millionaire", "winner", "lucky", "lucky7",
    "blink182", "green day", "linkinpark", "fuckoff", "bitch", "asshole", "sexy", "hottie", "cutie", "badboy",
    "jordan23", "kobe24", "lebron23", "number1", "number one", "one", "two", "three", "four", "five",
    "abc", "xyz", "aaa", "aaaa", "aaaaa", "aaaaaaa", "aaaaaaaa", "qqqqqq", "zzzzzz", "xxxxxx",
    "1234567891", "12345678910", "0123456789", "01234567", "0987654321", "9876543210", "87654321", "7654321", "654321a", "321654",
    "123qweasd", "qweasd", "qwerasdf", "1qazxsw2", "1qaz2wsx3edc", "zaq1xsw2", "!qaz2wsx", "1qazzaq1", "qaz123", "wsx123",
    "nicole1", "jessica1", "ashley1", "amanda1", "michael1", "daniel1", "jordan1", "andrew1", "joshua1", "matthew1",
    "hannah", "sophia", "olivia", "emily", "emma", "madison", "isabella", "abigail", "elizabeth", "victoria",
    "james", "john", "david", "chris", "mike", "steve", "kevin", "brian", "jason", "ryan",
    "tiffany", "brittany", "stephanie", "melissa", "rebecca", "lauren", "kimberly", "courtney", "danielle", "christina",
    "alexander", "alexandra", "alex", "sam", "max", "tom", "ben", "joe", "dan", "rob",
)
_COMMON_RANK = {value.lower(): index + 1 for index, value in enumerate(COMMON_PASSWORDS) if value.lower() not in
                {v.lower() for v in COMMON_PASSWORDS[:index]}}


# --------------------------------------------------------------------------- word list

@lru_cache(maxsize=1)
def load_wordlist() -> tuple[str, ...]:
    """Return the packaged passphrase word list (sorted, unique, lowercase)."""
    try:
        lines = WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return WORDLIST
    words = sorted({line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")})
    words = [word for word in words if re.fullmatch(r"[a-z]{3,12}", word)]
    return tuple(words) if len(words) >= 1000 else WORDLIST


@lru_cache(maxsize=1)
def _word_set() -> frozenset[str]:
    return frozenset(load_wordlist()) | frozenset(WORDLIST)


# --------------------------------------------------------------------------- generation

@dataclass(frozen=True)
class GeneratorOptions:
    mode: str = "password"
    length: int = 20
    lowercase: bool = True
    uppercase: bool = True
    digits: bool = True
    symbols: bool = True
    avoid_ambiguous: bool = True
    symbol_set: str = DEFAULT_SYMBOLS
    exclude: str = ""
    min_digits: int = 1
    min_symbols: int = 1
    words: int = 6
    separator: str = "-"
    capitalize: bool = False
    append_number: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _bounded_int(value: Any, low: int, high: int, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError, OverflowError):
        return default


def normalize_generator_options(raw: Any) -> GeneratorOptions:
    """Coerce a saved preference mapping into validated options (never raises)."""
    defaults = GeneratorOptions()
    if not isinstance(raw, dict):
        return defaults
    values: dict[str, Any] = {}
    values["mode"] = raw.get("mode") if raw.get("mode") in ("password", "passphrase") else defaults.mode
    values["length"] = _bounded_int(raw.get("length", defaults.length), 8, 256, defaults.length)
    for key in ("lowercase", "uppercase", "digits", "symbols", "avoid_ambiguous", "capitalize", "append_number"):
        value = raw.get(key, getattr(defaults, key))
        values[key] = value if isinstance(value, bool) else getattr(defaults, key)
    symbol_set = raw.get("symbol_set", defaults.symbol_set)
    symbol_set = "".join(dict.fromkeys(ch for ch in symbol_set if ch.isprintable() and not ch.isalnum() and not ch.isspace())) \
        if isinstance(symbol_set, str) else ""
    values["symbol_set"] = symbol_set or defaults.symbol_set
    exclude = raw.get("exclude", defaults.exclude)
    values["exclude"] = "".join(dict.fromkeys(ch for ch in exclude if ch.isprintable())) if isinstance(exclude, str) else ""
    values["min_digits"] = _bounded_int(raw.get("min_digits", defaults.min_digits), 0, 10, defaults.min_digits)
    values["min_symbols"] = _bounded_int(raw.get("min_symbols", defaults.min_symbols), 0, 10, defaults.min_symbols)
    values["words"] = _bounded_int(raw.get("words", defaults.words), 3, 16, defaults.words)
    separator = raw.get("separator", defaults.separator)
    if separator in SEPARATORS:
        separator = SEPARATORS[separator]
    values["separator"] = separator if separator in SEPARATORS.values() else defaults.separator
    return GeneratorOptions(**values)


def generate_password(
    length: int = 20,
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    avoid_ambiguous: bool = True,
    symbol_set: str = DEFAULT_SYMBOLS,
    exclude: str = "",
    min_digits: int = 1,
    min_symbols: int = 1,
) -> str:
    length = max(8, min(int(length), 256))
    excluded = set(exclude or "")
    if avoid_ambiguous:
        excluded |= AMBIGUOUS
    requested: list[tuple[str, str, int]] = []
    if lowercase:
        requested.append(("lowercase letters", string.ascii_lowercase, 1))
    if uppercase:
        requested.append(("uppercase letters", string.ascii_uppercase, 1))
    if digits:
        requested.append(("digits", string.digits, max(1, int(min_digits))))
    if symbols:
        requested.append(("symbols", symbol_set, max(1, int(min_symbols))))
    if not requested:
        raise ValueError(t("generator.error.noGroup"))
    groups: list[tuple[str, int]] = []
    for name, alphabet, minimum in requested:
        usable = "".join(dict.fromkeys(ch for ch in alphabet if ch not in excluded))
        if not usable:
            raise ValueError(f"No usable {name} remain after exclusions")
        groups.append((usable, minimum))
    required = sum(minimum for _alphabet, minimum in groups)
    if required > length:
        length = required
    selected: list[str] = []
    for alphabet, minimum in groups:
        selected.extend(secrets.choice(alphabet) for _ in range(minimum))
    pool = "".join(alphabet for alphabet, _minimum in groups)
    selected.extend(secrets.choice(pool) for _ in range(length - len(selected)))
    secrets.SystemRandom().shuffle(selected)
    return "".join(selected)


def generate_passphrase(
    words: int = 6,
    separator: str = "-",
    *,
    capitalize: bool = False,
    append_number: bool = False,
    wordlist: tuple[str, ...] | None = None,
) -> str:
    if separator in SEPARATORS:
        separator = SEPARATORS[separator]
    if separator not in SEPARATORS.values():
        raise ValueError(t("generator.error.separator"))
    count = max(3, min(int(words), 16))
    source = wordlist or load_wordlist()
    chosen = [secrets.choice(source) for _ in range(count)]
    if capitalize:
        chosen = [word[:1].upper() + word[1:] for word in chosen]
    phrase = separator.join(chosen)
    if append_number:
        phrase += str(secrets.randbelow(90) + 10)
    return phrase


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


def generate_username(style: str = "word", *, domain: str | None = None, prefix: str | None = None) -> str:
    """Generate a non-identifying username.

    ``word``: a random dictionary word plus a 3-4 digit number.
    ``alias``: ``prefix+token@domain`` for providers that support plus-addressing.
    """
    if style == "word":
        return f"{secrets.choice(load_wordlist())}{secrets.randbelow(9900) + 100}"
    if style != "alias":
        raise ValueError(t("generator.error.usernameStyle"))
    normalized_domain = (domain or "").strip().lower()
    if not normalized_domain or not _DOMAIN_RE.fullmatch(normalized_domain):
        raise ValueError(t("generator.error.domain"))
    normalized_prefix = (prefix or "").strip().lower() or secrets.choice(load_wordlist())
    if not _PREFIX_RE.fullmatch(normalized_prefix):
        raise ValueError(t("generator.error.prefix"))
    alphabet = string.ascii_lowercase + string.digits
    token = "".join(secrets.choice(alphabet) for _ in range(8))
    return f"{normalized_prefix}+{token}@{normalized_domain}"


def generate_from_options(options: GeneratorOptions) -> str:
    if options.mode == "passphrase":
        return generate_passphrase(
            options.words, options.separator, capitalize=options.capitalize, append_number=options.append_number,
        )
    return generate_password(
        options.length, lowercase=options.lowercase, uppercase=options.uppercase, digits=options.digits,
        symbols=options.symbols, avoid_ambiguous=options.avoid_ambiguous, symbol_set=options.symbol_set,
        exclude=options.exclude, min_digits=options.min_digits, min_symbols=options.min_symbols,
    )


def generate_from_preferences(raw: Any) -> str:
    """Generate using saved (possibly partial or malformed) preferences."""
    return generate_from_options(normalize_generator_options(raw))


# --------------------------------------------------------------------------- strength estimation

MIN_GUESSES_BEFORE_GROWING_SEQUENCE = 10_000
_MIN_SUBMATCH_SINGLE = 10
_MIN_SUBMATCH_MULTI = 50
_BRUTEFORCE_CARDINALITY = 10
_REFERENCE_YEAR = 2026
_MIN_YEAR_SPACE = 20
_MAX_ANALYZED = 100
_OFFLINE_FAST_HASH_PER_SECOND = 1e10

_L33T_TABLE = {
    "a": "4@", "b": "8", "c": "({[<", "e": "3", "g": "69", "i": "1!|", "l": "1|7", "o": "0", "s": "$5", "t": "+7",
    "x": "%", "z": "2",
}
_L33T_REVERSE: dict[str, tuple[str, ...]] = {}
for _letter, _subs in _L33T_TABLE.items():
    for _sub in _subs:
        _L33T_REVERSE.setdefault(_sub, ())
        _L33T_REVERSE[_sub] = _L33T_REVERSE[_sub] + (_letter,)

_QWERTY_ROWS = ("`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./")
_QWERTY_SHIFTED = ("~!@#$%^&*()_+", "QWERTYUIOP{}|", 'ASDFGHJKL:"', "ZXCVBNM<>?")
_KEY_POSITIONS: dict[str, tuple[int, int, bool]] = {}
for _row_index, (_plain, _shift) in enumerate(zip(_QWERTY_ROWS, _QWERTY_SHIFTED)):
    for _col, _ch in enumerate(_plain):
        _KEY_POSITIONS[_ch] = (_row_index, _col, False)
    for _col, _ch in enumerate(_shift):
        _KEY_POSITIONS[_ch] = (_row_index, _col, True)
_KEYBOARD_STARTS = 47
_KEYBOARD_AVERAGE_DEGREE = 4.6


@dataclass(frozen=True)
class PatternMatch:
    pattern: str
    i: int
    j: int
    token: str
    guesses: float
    detail: str = ""


@dataclass(frozen=True)
class StrengthEstimate:
    score: int
    guesses: float
    guesses_log10: float
    crack_time_seconds: float
    crack_time_display: str
    warning: str
    suggestions: tuple[str, ...]
    matches: tuple[PatternMatch, ...]


def _uppercase_variations(token: str) -> int:
    letters = [ch for ch in token if ch.isalpha()]
    if not letters or all(ch.islower() for ch in letters):
        return 1
    if (token[0].isupper() and all(ch.islower() for ch in letters[1:])) or \
            (token[-1].isupper() and all(ch.islower() for ch in letters[:-1])) or all(ch.isupper() for ch in letters):
        return 2
    upper = sum(ch.isupper() for ch in letters)
    lower = len(letters) - upper
    return max(2, sum(comb(upper + lower, k) for k in range(1, min(upper, lower) + 1)))


def _l33t_variants(lower_token: str, limit: int = 32) -> list[tuple[str, int]]:
    """Return (candidate, substitution_count) pairs with l33t characters restored."""
    if not any(ch in _L33T_REVERSE for ch in lower_token):
        return []
    variants: list[tuple[str, int]] = [("", 0)]
    for ch in lower_token:
        options = _L33T_REVERSE.get(ch)
        if options:
            variants = [(prefix + letter, count + 1) for prefix, count in variants for letter in options][:limit]
        else:
            variants = [(prefix + ch, count) for prefix, count in variants]
    return [variant for variant in variants if variant[0] != lower_token]


def _dictionary_rank(candidate: str) -> tuple[int, str] | None:
    rank = _COMMON_RANK.get(candidate)
    if rank is not None:
        return rank, "common"
    if candidate in _word_set():
        return len(load_wordlist()), "word"
    return None


def _dictionary_matches(password: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    n = len(password)
    for i in range(n):
        for j in range(i + 2, n):
            token = password[i:j + 1]
            lower = token.lower()
            candidates: list[tuple[str, int, bool]] = [(lower, 0, False), (lower[::-1], 0, True)]
            candidates += [(variant, subs, False) for variant, subs in _l33t_variants(lower)]
            candidates += [(variant, subs, True) for variant, subs in _l33t_variants(lower[::-1])]
            best: PatternMatch | None = None
            for candidate, substitutions, reversed_ in candidates:
                found = _dictionary_rank(candidate)
                if found is None:
                    continue
                rank, source = found
                guesses = float(rank) * _uppercase_variations(token)
                detail = source
                if substitutions:
                    guesses *= max(2, 2 ** substitutions)
                    detail += "+l33t"
                if reversed_:
                    guesses *= 2
                    detail += "+reversed"
                if best is None or guesses < best.guesses:
                    best = PatternMatch("dictionary", i, j, token, guesses, detail)
            if best is not None:
                matches.append(best)
    return matches


def _char_class(ch: str) -> str:
    if ch.islower():
        return "lower"
    if ch.isupper():
        return "upper"
    if ch.isdigit():
        return "digit"
    return "other"


def _sequence_matches(password: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    n = len(password)
    i = 0
    while i < n - 2:
        j = i + 1
        delta = ord(password[j]) - ord(password[i])
        if abs(delta) != 1 or _char_class(password[i]) == "other" or _char_class(password[i]) != _char_class(password[j]):
            i += 1
            continue
        while j + 1 < n and ord(password[j + 1]) - ord(password[j]) == delta and \
                _char_class(password[j + 1]) == _char_class(password[i]):
            j += 1
        if j - i + 1 >= 3:
            token = password[i:j + 1]
            first = token[0]
            if first in "aAzZ019":
                base = 4
            elif first.isdigit():
                base = 10
            else:
                base = 26
            guesses = float(base * len(token)) * (2 if delta < 0 else 1)
            matches.append(PatternMatch("sequence", i, j, token, guesses, "descending" if delta < 0 else "ascending"))
            i = j
        i += 1
    return matches


_REPEAT_RE = re.compile(r"(.+?)\1+")
_REPEAT_GREEDY_RE = re.compile(r"(.+)\1+")


def _repeat_matches(password: str, depth: int) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    if depth > 2:
        return matches
    position = 0
    while position < len(password):
        lazy = _REPEAT_RE.search(password, position)
        if lazy is None:
            break
        greedy = _REPEAT_GREEDY_RE.match(password, lazy.start())
        candidates = [lazy]
        if greedy is not None and greedy.end() > lazy.end():
            candidates.append(greedy)
        chosen = None
        chosen_guesses = math.inf
        for candidate in candidates:
            base = candidate.group(1)
            repeat_count = len(candidate.group(0)) // len(base)
            if repeat_count < 2:
                continue
            base_guesses = _estimate(base, depth + 1).guesses
            guesses = base_guesses * repeat_count
            if guesses < chosen_guesses:
                chosen, chosen_guesses = candidate, guesses
        if chosen is None:
            position = lazy.start() + 1
            continue
        matches.append(PatternMatch("repeat", chosen.start(), chosen.end() - 1, chosen.group(0), chosen_guesses,
                                    f"base={chosen.group(1)!r}"))
        position = chosen.end()
    return matches


def _adjacent(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int] | None:
    dr, dc = b[0] - a[0], b[1] - a[1]
    if dr == 0 and abs(dc) == 1:
        return (0, dc)
    if dr == 1 and dc in (0, -1):
        return (1, dc)
    if dr == -1 and dc in (0, 1):
        return (-1, dc)
    return None


def _spatial_guesses(length: int, turns: int, shifted: int) -> float:
    guesses = 0.0
    for i in range(2, length + 1):
        for j in range(1, min(turns, i - 1) + 1):
            guesses += comb(i - 1, j - 1) * _KEYBOARD_STARTS * _KEYBOARD_AVERAGE_DEGREE ** j
    if shifted:
        unshifted = length - shifted
        if unshifted == 0:
            guesses *= 2
        else:
            guesses *= sum(comb(length, k) for k in range(1, min(shifted, unshifted) + 1))
    return max(guesses, 1.0)


def _spatial_matches(password: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    n = len(password)
    i = 0
    while i < n - 2:
        start = _KEY_POSITIONS.get(password[i])
        if start is None:
            i += 1
            continue
        j = i
        turns = 0
        last_direction = None
        shifted = int(start[2])
        previous = (start[0], start[1])
        while j + 1 < n:
            nxt = _KEY_POSITIONS.get(password[j + 1])
            if nxt is None:
                break
            direction = _adjacent(previous, (nxt[0], nxt[1]))
            if direction is None:
                break
            if direction != last_direction:
                turns += 1
                last_direction = direction
            shifted += int(nxt[2])
            previous = (nxt[0], nxt[1])
            j += 1
        if j - i + 1 >= 3:
            token = password[i:j + 1]
            matches.append(PatternMatch("spatial", i, j, token, _spatial_guesses(len(token), turns, shifted),
                                        f"turns={turns}"))
            i = j
        i += 1
    return matches


def _valid_date(day: int, month: int, year: int) -> tuple[int, int, int] | None:
    if 1 <= month <= 12 and 1 <= day <= 31:
        pass
    elif 1 <= day <= 12 and 1 <= month <= 31:
        day, month = month, day
    else:
        return None
    if year < 100:
        year += 1900 if year > 30 else 2000
    if not 1900 <= year <= 2050:
        return None
    return day, month, year


_DATE_SPLITS = {
    4: ((1, 2), (2, 3)),
    5: ((1, 3), (2, 3)),
    6: ((1, 2), (2, 4), (4, 5)),
    7: ((1, 3), (2, 3), (4, 5), (4, 6)),
    8: ((2, 4), (4, 6)),
}


def _date_candidates(token: str) -> list[tuple[int, int, int]]:
    candidates: list[tuple[int, int, int]] = []
    if len(token) == 4 and token.isdigit():
        year = int(token)
        if 1900 <= year <= 2050:
            candidates.append((1, 1, year))
    for a, b in _DATE_SPLITS.get(len(token), ()):
        parts = (token[:a], token[a:b], token[b:])
        if not all(part.isdigit() for part in parts):
            continue
        p0, p1, p2 = (int(part) for part in parts)
        for day, month, year in ((p1, p2, p0), (p0, p1, p2)):
            resolved = _valid_date(day, month, year)
            if resolved is not None:
                candidates.append(resolved)
    return candidates


_DATE_NO_SEP_RE = re.compile(r"\d{4,8}")
_DATE_SEP_RE = re.compile(r"(\d{1,4})([\s/\\_.-])(\d{1,2})\2(\d{1,4})")


def _date_guesses(year: int, separated: bool) -> float:
    guesses = float(max(abs(year - _REFERENCE_YEAR), _MIN_YEAR_SPACE) * 365)
    return guesses * 4 if separated else guesses


def _date_matches(password: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    for found in _DATE_NO_SEP_RE.finditer(password):
        token = found.group(0)
        for length in range(len(token), 3, -1):
            for offset in range(0, len(token) - length + 1):
                sub = token[offset:offset + length]
                candidates = _date_candidates(sub)
                if not candidates:
                    continue
                year = min(candidates, key=lambda c: abs(c[2] - _REFERENCE_YEAR))[2]
                i = found.start() + offset
                matches.append(PatternMatch("date", i, i + length - 1, sub, _date_guesses(year, False), str(year)))
    for found in _DATE_SEP_RE.finditer(password):
        p0, _sep, p1, p2 = found.group(1), found.group(2), found.group(3), found.group(4)
        for day, month, year in ((int(p1), int(p2), int(p0)), (int(p0), int(p1), int(p2)), (int(p1), int(p0), int(p2))):
            resolved = _valid_date(day, month, year)
            if resolved is None:
                continue
            matches.append(PatternMatch("date", found.start(), found.end() - 1, found.group(0),
                                        _date_guesses(resolved[2], True), str(resolved[2])))
            break
    return matches


def _bruteforce(password: str, i: int, j: int) -> PatternMatch:
    token = password[i:j + 1]
    guesses = float(_BRUTEFORCE_CARDINALITY) ** len(token)
    minimum = _MIN_SUBMATCH_SINGLE if len(token) == 1 else _MIN_SUBMATCH_MULTI
    return PatternMatch("bruteforce", i, j, token, max(guesses, float(minimum)))


def _most_guessable_sequence(password: str, matches: list[PatternMatch]) -> tuple[float, list[PatternMatch]]:
    n = len(password)
    if n == 0:
        return 1.0, []
    by_end: list[list[PatternMatch]] = [[] for _ in range(n)]
    for match in matches:
        by_end[match.j].append(match)
    optimal_m: list[dict[int, PatternMatch]] = [{} for _ in range(n)]
    optimal_pi: list[dict[int, float]] = [{} for _ in range(n)]
    optimal_g: list[dict[int, float]] = [{} for _ in range(n)]

    def floored(match: PatternMatch) -> float:
        if match.token == password:
            return match.guesses
        minimum = _MIN_SUBMATCH_SINGLE if len(match.token) == 1 else _MIN_SUBMATCH_MULTI
        return max(match.guesses, float(minimum))

    def update(match: PatternMatch, length: int) -> None:
        k = match.j
        pi = floored(match)
        if length > 1:
            pi *= optimal_pi[match.i - 1][length - 1]
        g = math.factorial(length) * pi
        if length > 1:
            g += float(MIN_GUESSES_BEFORE_GROWING_SEQUENCE) ** (length - 1)
        for competing_length, competing_g in optimal_g[k].items():
            if competing_length > length:
                continue
            if competing_g <= g:
                return
        optimal_g[k][length] = g
        optimal_m[k][length] = match
        optimal_pi[k][length] = pi

    for k in range(n):
        for match in by_end[k]:
            if match.i > 0:
                for length in list(optimal_m[match.i - 1]):
                    update(match, length + 1)
            else:
                update(match, 1)
        update(_bruteforce(password, 0, k), 1)
        for i in range(1, k + 1):
            chunk = _bruteforce(password, i, k)
            for length, last in list(optimal_m[i - 1].items()):
                if last.pattern == "bruteforce":
                    continue
                update(chunk, length + 1)

    best_length = min(optimal_g[n - 1], key=lambda length: optimal_g[n - 1][length])
    guesses = optimal_g[n - 1][best_length]
    sequence: list[PatternMatch] = []
    k, length = n - 1, best_length
    while k >= 0 and length > 0:
        match = optimal_m[k][length]
        sequence.append(match)
        k = match.i - 1
        length -= 1
    sequence.reverse()
    return guesses, sequence


def _score(guesses: float) -> int:
    if guesses < 1e3 + 5:
        return 0
    if guesses < 1e6 + 5:
        return 1
    if guesses < 1e8 + 5:
        return 2
    if guesses < 1e10 + 5:
        return 3
    return 4


def _display_time(seconds: float) -> str:
    minute, hour, day, month, year = 60, 3600, 86400, 86400 * 31, 86400 * 365
    century = year * 100
    if seconds < 1:
        return t("strength.time.underSecond")
    for unit, name in ((century, None), (year, "year"), (month, "month"), (day, "day"), (hour, "hour"),
                       (minute, "minute"), (1, "second")):
        if seconds >= unit:
            if name is None:
                return t("strength.time.centuries")
            return t(f"strength.time.{name}", count=round(seconds / unit))
    return t("strength.time.underSecond")


def _feedback(score: int, sequence: list[PatternMatch]) -> tuple[str, tuple[str, ...]]:
    if not sequence:
        return "", (t("strength.fb.fewChars"),)
    if score > 2:
        return "", ()
    longest = max(sequence, key=lambda match: len(match.token))
    suggestions: list[str] = [t("strength.fb.addWord")]
    warning = ""
    if longest.pattern == "dictionary":
        if longest.detail.startswith("common"):
            warning = t("strength.fb.veryCommon") if len(sequence) == 1 else t("strength.fb.similarCommon")
        else:
            warning = t("strength.fb.singleWord") if len(sequence) == 1 else t("strength.fb.commonWords")
        if "+l33t" in longest.detail:
            suggestions.append(t("strength.fb.l33t"))
        if "+reversed" in longest.detail:
            suggestions.append(t("strength.fb.reversed"))
        if longest.token != longest.token.lower() and _uppercase_variations(longest.token) == 2:
            suggestions.append(t("strength.fb.caps"))
    elif longest.pattern == "spatial":
        warning = t("strength.fb.shortKeys") if "turns=1" in longest.detail else \
            t("strength.fb.rows")
        suggestions.append(t("strength.fb.longerKeys"))
    elif longest.pattern == "repeat":
        warning = t("strength.fb.repeatSingle") if len(set(longest.token)) == 1 else \
            t("strength.fb.repeatGroup")
        suggestions.append(t("strength.fb.avoidRepeats"))
    elif longest.pattern == "sequence":
        warning = t("strength.fb.sequence")
        suggestions.append(t("strength.fb.avoidSequences"))
    elif longest.pattern == "date":
        warning = t("strength.fb.dates")
        suggestions.append(t("strength.fb.avoidDates"))
    elif longest.pattern == "bruteforce" and len(longest.token) <= 8:
        warning = t("strength.fb.tooShort")
        suggestions = [t("strength.fb.addChars")]
    return warning, tuple(suggestions)


def _estimate(password: str, depth: int = 0) -> StrengthEstimate:
    analyzed = password[:_MAX_ANALYZED]
    overflow = len(password) - len(analyzed)
    matches: list[PatternMatch] = []
    if analyzed:
        matches += _dictionary_matches(analyzed)
        matches += _sequence_matches(analyzed)
        matches += _repeat_matches(analyzed, depth)
        matches += _spatial_matches(analyzed)
        matches += _date_matches(analyzed)
    guesses, sequence = _most_guessable_sequence(analyzed, matches)
    if overflow:
        guesses *= float(_BRUTEFORCE_CARDINALITY) ** overflow
    guesses = max(1.0, guesses)
    score = _score(guesses)
    seconds = guesses / _OFFLINE_FAST_HASH_PER_SECOND
    warning, suggestions = _feedback(score, sequence) if password else (t("strength.fb.empty"), ())
    return StrengthEstimate(
        score=score,
        guesses=guesses,
        guesses_log10=math.log10(guesses),
        crack_time_seconds=seconds,
        crack_time_display=_display_time(seconds),
        warning=warning,
        suggestions=suggestions,
        matches=tuple(sequence),
    )


def estimate_strength(password: str) -> StrengthEstimate:
    """zxcvbn-style estimate: guesses, 0-4 score, crack time and feedback."""
    return _estimate(str(password or ""), 0)


@dataclass(frozen=True)
class PasswordHealth:
    score: int
    label: str
    entropy_bits: float
    reasons: tuple[str, ...]


def assess_password(password: str) -> PasswordHealth:
    """Backwards-compatible 0-100 view over :func:`estimate_strength`."""
    if not password:
        return PasswordHealth(0, t("strength.health.empty"), 0.0, (t("strength.fb.empty"),))
    estimate = estimate_strength(password)
    score = max(0, min(100, round(estimate.guesses_log10 * 100 / 14)))
    reasons = [part for part in (estimate.warning, *estimate.suggestions) if part]
    # A recognizable pattern (words, repeats, walks, dates) that still leaves
    # fewer than ~46 bits of guessing work is never presented as green.
    patterned = [match for match in estimate.matches if match.pattern != "bruteforce"]
    if patterned and estimate.guesses < 1e14 and score >= 60:
        score = 59
        if not reasons:
            reasons.append(t("strength.fb.patterns"))
    label = (t("strength.health.strong") if score >= 80 else t("strength.health.review") if score >= 60
             else t("strength.health.weak") if score >= 35 else t("strength.health.veryWeak"))
    return PasswordHealth(score, label, math.log2(estimate.guesses), tuple(reasons) if score < 80 else ())


# --------------------------------------------------------------------------- vault-wide checks

STRENGTH_LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")  # English ids; shown via strength_label()


def strength_label(score: int) -> str:
    """The shown name of a 0-4 strength score, in the active language."""
    return t(f"strength.label.{max(0, min(4, int(score)))}")

HEALTH_CATEGORY_LABELS = {
    "weak": "Weak",
    "reused": "Reused",
    "no_2fa": "No 2FA",
    "old": "Old (>1 year)",
}


# Tag on a login whose password was generated as a placeholder (a 2FA QR code added it without the real
# password). Health leaves its password out of weak and reuse scoring, and breach checks skip it.
NEEDS_PASSWORD_TAG = "needs-password"  # noqa: S105 - a tag name, not a password


def needs_password(entry: dict[str, Any]) -> bool:
    tags = entry.get("tags")
    return isinstance(tags, (list, tuple)) and NEEDS_PASSWORD_TAG in tags


def vault_health(entries: list[dict[str, Any]], *, old_after_days: int = 365, now: int | None = None) -> dict[str, Any]:
    """Categorize every entry once without retaining any password text."""
    current = int(time.time()) if now is None else int(now)
    password_to_ids: dict[str, list[str]] = {}
    rows: list[dict[str, Any]] = []
    for entry in entries:
        placeholder = needs_password(entry)
        password = "" if placeholder else str(entry.get("password", ""))
        entry_id = str(entry.get("id", ""))
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest() if password else ""
        if digest:
            password_to_ids.setdefault(digest, []).append(entry_id)
        score = estimate_strength(password).score if password else 0
        updated = int(entry.get("updated_at", 0) or 0)
        rows.append({
            "id": entry_id,
            "label": str(entry.get("label", "")),
            "username": str(entry.get("username", "")),
            "kind": str(entry.get("kind", "")),
            "score": 4 if placeholder else score,
            "digest": digest,
            "has_2fa": bool(entry.get("totp")),
            "updated_at": updated,
            "old": bool(updated) and current - updated > old_after_days * 86400,
        })
    reused_ids = {entry_id for ids in password_to_ids.values() if len(ids) > 1 for entry_id in ids}
    weak: list[str] = []
    old: list[str] = []
    no_2fa: list[str] = []
    for row in rows:
        categories: list[str] = []
        if row["score"] <= 1:
            categories.append("weak")
            weak.append(row["id"])
        if row["id"] in reused_ids:
            categories.append("reused")
        if not row["has_2fa"]:
            categories.append("no_2fa")
            no_2fa.append(row["id"])
        if row["old"]:
            categories.append("old")
            old.append(row["id"])
        row["categories"] = tuple(categories)
        row.pop("digest", None)
    reused = sorted(reused_ids)
    return {
        "total": len(entries),
        "rows": rows,
        "weak_ids": sorted(set(weak)),
        "reused_ids": reused,
        "old_ids": sorted(set(old)),
        "no_2fa_ids": sorted(set(no_2fa)),
        "weak_count": len(set(weak)),
        "reused_count": len(reused),
        "old_count": len(set(old)),
        "no_2fa_count": len(set(no_2fa)),
        "age_is_risk": False,
        "advice": "Prioritize reused, guessable, or exposed logins first. Age alone is not a reason to rotate.",
    }


def breach_scan(
    passwords_by_id: dict[str, str],
    *,
    check: Callable[..., int],
    sleep: Callable[[float], None] = time.sleep,
    delay: float = 1.5,
    strict_offline: bool = False,
    cancelled: Callable[[], bool] = lambda: False,
    report: Callable[[str, int | None, str], None] | None = None,
) -> dict[str, Any]:
    """Check many passwords against a k-anonymity breach service, politely.

    Identical passwords are requested once, requests are spaced by ``delay``
    seconds, and ``report(entry_id, count_or_None, note)`` is invoked per entry
    as results arrive.  Strict offline mode refuses to start.
    """
    from .breach_check import BreachCheckError

    if strict_offline:
        raise ValueError("Strict offline mode is enabled; no external check was performed.")
    unique: dict[str, list[str]] = {}
    for entry_id, password in passwords_by_id.items():
        if password:
            unique.setdefault(password, []).append(entry_id)
    outcome = {"checked": 0, "exposed": 0, "errors": 0, "cancelled": False}
    first = True
    for password, ids in unique.items():
        if cancelled():
            outcome["cancelled"] = True
            break
        if not first:
            sleep(delay)
        first = False
        outcome["checked"] += 1
        try:
            count = int(check(password, consent=True, strict_offline=False))
        except BreachCheckError as exc:
            outcome["errors"] += 1
            if report is not None:
                for entry_id in ids:
                    report(entry_id, None, str(exc) or "Check failed")
            continue
        if count:
            outcome["exposed"] += len(ids)
        if report is not None:
            for entry_id in ids:
                report(entry_id, count, "")
    return outcome
