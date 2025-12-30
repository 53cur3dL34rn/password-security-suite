from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class PasswordGenConfig:
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = True  # avoids O/0, l/1, etc.


AMBIGUOUS = set("O0oIl1|`'\"")


def generate_password(cfg: PasswordGenConfig = PasswordGenConfig()) -> str:
    """Generate a random password using the secrets module."""
    if cfg.length < 8:
        raise ValueError("Password length should be at least 8 characters.")

    pools = []
    if cfg.use_upper:
        pools.append(string.ascii_uppercase)
    if cfg.use_lower:
        pools.append(string.ascii_lowercase)
    if cfg.use_digits:
        pools.append(string.digits)
    if cfg.use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")

    if not pools:
        raise ValueError("At least one character set must be enabled.")

    # Build allowed alphabet
    alphabet = "".join(pools)
    if cfg.avoid_ambiguous:
        alphabet = "".join(ch for ch in alphabet if ch not in AMBIGUOUS)

    # Ensure at least one char from each enabled pool
    password_chars: List[str] = []
    for pool in pools:
        pool2 = pool
        if cfg.avoid_ambiguous:
            pool2 = "".join(ch for ch in pool2 if ch not in AMBIGUOUS)
        if pool2:
            password_chars.append(secrets.choice(pool2))

    # Fill remaining
    while len(password_chars) < cfg.length:
        password_chars.append(secrets.choice(alphabet))

    # Shuffle
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


@dataclass(frozen=True)
class PassphraseConfig:
    words: int = 5
    separator: str = "-"
    capitalize: bool = False
    add_number: bool = True


DEFAULT_WORDLIST = [
    # Small built-in list. You can supply a bigger custom list via the CLI.
    "river", "paper", "candle", "planet", "honey", "forest", "silver", "window",
    "pencil", "coffee", "galaxy", "summer", "winter", "orange", "purple", "storm",
    "castle", "bottle", "camera", "garden", "ticket", "pocket", "dragon", "rocket",
    "mirror", "school", "island", "shadow", "music", "stairs", "mother", "father",
]


def generate_passphrase(cfg: PassphraseConfig = PassphraseConfig(), wordlist: List[str] | None = None) -> str:
    """Generate a passphrase (easy to type, hard to guess)."""
    wl = wordlist or DEFAULT_WORDLIST
    if cfg.words < 3:
        raise ValueError("Passphrases should usually be 3+ words (5+ is better).")

    chosen = [secrets.choice(wl).strip() for _ in range(cfg.words)]
    if cfg.capitalize:
        chosen = [w.capitalize() for w in chosen]

    phrase = cfg.separator.join(chosen)

    if cfg.add_number:
        phrase = f"{phrase}{cfg.separator}{secrets.randbelow(10)}{secrets.randbelow(10)}"
    return phrase
