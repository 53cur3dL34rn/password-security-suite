from __future__ import annotations

import csv
import math
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# --- Pattern helpers ---

_UNLEET = {
    '4': 'a', '@': 'a',
    '3': 'e', '€': 'e',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '5': 's', '$': 's',
    '7': 't',
    '8': 'b',
    '9': 'g',
    '2': 'z',
}

_COMMON_WORDS = [
    "admin", "password", "secret", "root", "master", "login", "pass", "welcome", "qwerty"
]

_KEYBOARD = re.compile(r"(qwerty|asdfgh|zxcvbn)", re.IGNORECASE)
_SEQ_NUM = re.compile(r"(012|123|234|345|456|567|678|789|890)")
_SEQ_ALPHA = re.compile(
    r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
    re.IGNORECASE,
)
_REPEATED = re.compile(r"(.)\1{2,}")
_ONLY_NUM = re.compile(r"^\d+$")
_ONLY_ALPHA = re.compile(r"^[a-zA-Z]+$")
_ONLY_SPECIAL = re.compile(r"^[^a-zA-Z0-9]+$")
_REPEATED_PATTERN = re.compile(r"(.+?)\1$")


def detect_leet_speak(password: str) -> bool:
    pw = password.lower()
    unleeted = "".join(_UNLEET.get(c, c) for c in pw)
    return any(word in unleeted for word in _COMMON_WORDS) or any(word in pw for word in _COMMON_WORDS)


def check_patterns(password: str) -> List[str]:
    patterns: Dict[str, bool] = {
        "repeated patterns": bool(_REPEATED_PATTERN.search(password)),
        "leet speak / common word": detect_leet_speak(password),
        "only numbers": bool(_ONLY_NUM.search(password)),
        "only letters": bool(_ONLY_ALPHA.search(password)),
        "only special characters": bool(_ONLY_SPECIAL.search(password)),
        "repeated characters": bool(_REPEATED.search(password)),
        "sequential numbers": bool(_SEQ_NUM.search(password)),
        "sequential letters": bool(_SEQ_ALPHA.search(password)),
        "keyboard pattern": bool(_KEYBOARD.search(password)),
        "contains a year-like number": bool(re.search(r"(19\d\d|20\d\d)", password)),
    }
    return [k for k, v in patterns.items() if v]


def calculate_entropy_bits(password: str) -> float:
    """Entropy estimate based on character variety and length.

    This is a *rough estimate* of search space, not a guarantee.
    """
    char_pool = 0
    if any(c.islower() for c in password):
        char_pool += 26
    if any(c.isupper() for c in password):
        char_pool += 26
    if any(c.isdigit() for c in password):
        char_pool += 10
    if any(not c.isalnum() for c in password):
        char_pool += 33

    if char_pool <= 0:
        return 0.0
    entropy = len(password) * math.log2(char_pool)
    return round(entropy, 2)


def human_time(seconds: float) -> str:
    if seconds <= 0:
        return "N/A"
    units = [
        ("years", 31536000),
        ("days", 86400),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    parts = []
    rem = seconds
    for name, size in units:
        if rem >= size:
            qty = int(rem // size)
            rem = rem - qty * size
            parts.append(f"{qty} {name}")
            if len(parts) == 2:
                break
    return ", ".join(parts) if parts else "less than 1 second"


@dataclass(frozen=True)
class CrackModel:
    """Very rough model: guesses per second for offline guessing."""
    guesses_per_second: float = 1e9
    description: str = "Offline guessing (assumed)."


@dataclass(frozen=True)
class AuditPolicy:
    """A lightweight policy for auditing.

    Note: This suite is defensive and aims to be practical:
    - It favors length + uniqueness.
    - It reports composition as signals rather than strict pass/fail rules.
    """
    min_length: int = 12
    prefer_length: int = 16
    allow_spaces: bool = True


@dataclass(frozen=True)
class PolicyProfile:
    name: str
    policy: AuditPolicy
    crack_model: CrackModel


def get_policy_profile(mode: str = "home") -> PolicyProfile:
    """Return a preset profile.

    home:
      - good defaults for personal use
    enterprise:
      - slightly stricter length targets, assumes a stronger offline attacker
    """
    m = (mode or "home").strip().lower()
    if m in {"enterprise", "corp", "org", "company"}:
        return PolicyProfile(
            name="enterprise",
            policy=AuditPolicy(min_length=14, prefer_length=20, allow_spaces=True),
            crack_model=CrackModel(guesses_per_second=1e10, description="Offline guessing (assumed, stronger attacker)."),
        )
    return PolicyProfile(
        name="home",
        policy=AuditPolicy(min_length=12, prefer_length=16, allow_spaces=True),
        crack_model=CrackModel(guesses_per_second=1e9, description="Offline guessing (assumed)."),
    )


def load_common_passwords(path: str | Path = "common_passwords.csv") -> List[str]:
    p = Path(path)
    if not p.exists():
        return [
            "password", "123456", "12345678", "123456789",
            "admin", "qwerty", "letmein", "welcome",
            "password1", "12345", "123123", "111111",
        ]
    passwords: List[str] = []
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                for item in row:
                    item = item.strip()
                    if item:
                        passwords.append(item)
    except Exception:
        return [
            "password", "123456", "12345678", "123456789",
            "admin", "qwerty", "letmein", "welcome",
            "password1", "12345", "123123", "111111",
        ]
    return passwords


def breach_list_contains(password: str, breach_list_path: str | Path) -> bool:
    """Check if password appears in a local list (one password per line).

    Streaming read so it works with big files without loading into memory.
    """
    p = Path(breach_list_path)
    if not p.exists():
        return False

    target = password.strip()
    if not target:
        return False

    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.rstrip("\n\r") == target:
                return True
    return False


def _score_and_risk(entropy_bits: float, length: int, patterns: List[str], common_or_breach: bool) -> Tuple[int, str]:
    """Compute a simple 0–100 score + risk label."""
    score = 0

    # Length (most weight)
    if length >= 20:
        score += 45
    elif length >= 16:
        score += 38
    elif length >= 12:
        score += 28
    elif length >= 8:
        score += 15
    else:
        score += 5

    # Entropy estimate
    if entropy_bits >= 90:
        score += 35
    elif entropy_bits >= 70:
        score += 28
    elif entropy_bits >= 55:
        score += 18
    elif entropy_bits >= 40:
        score += 8
    else:
        score += 2

    # Deductions
    if common_or_breach:
        score -= 40
    score -= min(20, 4 * len(patterns))

    score = max(0, min(100, score))

    if score >= 80:
        risk = "LOW"
    elif score >= 55:
        risk = "MEDIUM"
    else:
        risk = "HIGH"
    return score, risk


def _breakdown_scores(length: int, patterns: List[str], common_exact: bool, common_substring: bool, breach_hit: bool, policy: AuditPolicy) -> Dict[str, Dict]:
    """Return category scores for a quick visual breakdown (0–100 each)."""
    # Length score (based on policy targets)
    if length >= policy.prefer_length:
        length_score = 100
        length_note = f"Meets preferred length ({policy.prefer_length}+)."
    elif length >= policy.min_length:
        length_score = 70
        length_note = f"Meets minimum length ({policy.min_length}+), but longer is better."
    elif length >= 8:
        length_score = 40
        length_note = "Short; susceptible to faster guessing."
    else:
        length_score = 10
        length_note = "Very short; high risk."

    # Uniqueness score: reuse/common/breach signals tank it
    if breach_hit or common_exact:
        uniq_score = 0
        uniq_note = "Matches a breached/common password (do not use)."
    elif common_substring:
        uniq_score = 40
        uniq_note = "Contains a common password fragment; make it more unique."
    else:
        uniq_score = 100
        uniq_note = "Does not look like a common/breached password (based on the lists you provided)."

    # Pattern score: more predictable patterns => lower score
    n = len(patterns)
    if n == 0:
        pat_score = 100
        pat_note = "No obvious predictable patterns detected."
    elif n == 1:
        pat_score = 80
        pat_note = "One predictable pattern detected."
    elif n == 2:
        pat_score = 60
        pat_note = "Multiple predictable patterns detected."
    elif n == 3:
        pat_score = 40
        pat_note = "Several predictable patterns detected."
    else:
        pat_score = 20
        pat_note = "Many predictable patterns detected."

    return {
        "length": {"score_0_100": length_score, "note": length_note},
        "uniqueness": {"score_0_100": uniq_score, "note": uniq_note},
        "patterns": {"score_0_100": pat_score, "note": pat_note},
    }


def audit_password(
    password: str,
    policy: AuditPolicy = AuditPolicy(),
    crack_model: CrackModel = CrackModel(),
    common_passwords_path: str | Path = "common_passwords.csv",
    breach_list_path: Optional[str | Path] = None,
) -> Dict:
    """Audit a password and return structured results (dict)."""
    pw = password or ""
    length = len(pw)

    signals = {
        "has_upper": any(c.isupper() for c in pw),
        "has_lower": any(c.islower() for c in pw),
        "has_digit": any(c.isdigit() for c in pw),
        "has_symbol": any(not c.isalnum() and c != " " for c in pw),
        "has_space": (" " in pw),
    }

    space_note = None
    if signals["has_space"] and not policy.allow_spaces:
        space_note = "Spaces detected but policy disallows spaces."

    patterns = check_patterns(pw)
    entropy_bits = calculate_entropy_bits(pw)

    common_list = [c.lower() for c in load_common_passwords(common_passwords_path)]
    pw_lower = pw.lower()
    common_exact = pw_lower in common_list
    common_substring = (not common_exact) and any(c in pw_lower for c in common_list if len(c) >= 4)

    breach_hit = False
    if breach_list_path:
        breach_hit = breach_list_contains(pw, breach_list_path)

    # Crack-time estimate (defensive): 2^entropy / guesses_per_second
    if entropy_bits > 0 and crack_model.guesses_per_second > 0:
        seconds_est = (2 ** entropy_bits) / crack_model.guesses_per_second
    else:
        seconds_est = 0.0

    score, risk = _score_and_risk(entropy_bits, length, patterns, common_exact or breach_hit)

    recommendations: List[str] = []
    if length < policy.min_length:
        recommendations.append(f"Use at least {policy.min_length} characters (longer is better).")
    if common_exact or breach_hit:
        recommendations.append("This password shows up on a common/breached list. Choose something unique.")
    if patterns:
        recommendations.append("Remove predictable patterns (sequences, keyboard runs, repeats, common words).")

    # Composition: treat as signals, not strict rules
    if not signals["has_upper"] or not signals["has_lower"]:
        recommendations.append("Mixing upper and lower case can help against some guessing strategies.")
    if not signals["has_digit"]:
        recommendations.append("Add digits if it stays memorable (or use a longer passphrase).")
    if not signals["has_symbol"]:
        recommendations.append("Symbols can help, but length + uniqueness matter most.")
    if signals["has_space"] and policy.allow_spaces:
        recommendations.append("Spaces are fine—passphrases with spaces can be very strong.")

    if not recommendations:
        recommendations.append("Looks solid. Keep it unique per site and enable MFA where possible.")

    breakdown = _breakdown_scores(
        length=length,
        patterns=patterns,
        common_exact=common_exact,
        common_substring=common_substring,
        breach_hit=breach_hit,
        policy=policy,
    )

    result = {
        "meta": {
            "policy": asdict(policy),
            "crack_model": asdict(crack_model),
        },
        "metrics": {
            "length": length,
            "entropy_bits_estimate": entropy_bits,
            "score_0_100": score,
            "risk": risk,
            "offline_crack_time_seconds_estimate": seconds_est,
            "offline_crack_time_human_estimate": human_time(seconds_est),
        },
        "breakdown": breakdown,
        "signals": signals,
        "findings": {
            "patterns": patterns,
            "common_password_exact": common_exact,
            "common_password_substring": common_substring,
            "breach_list_hit": breach_hit,
            "space_note": space_note,
        },
        "recommendations": recommendations,
    }
    return result
