from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, asdict
from typing import Dict, Optional


@dataclass(frozen=True)
class HashResult:
    algorithm: str
    encoded: str
    notes: str


def pbkdf2_hash(password: str, iterations: int = 310_000, salt_bytes: int = 16) -> HashResult:
    """PBKDF2-HMAC-SHA256 example using Python stdlib.

    PBKDF2 is widely available and recommended in some compliance settings.
    You still want a per-user random salt and a high iteration count.
    """
    salt = os.urandom(salt_bytes)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    blob = b"pbkdf2_sha256$" + str(iterations).encode() + b"$" + base64.b64encode(salt) + b"$" + base64.b64encode(dk)
    return HashResult(
        algorithm="PBKDF2-HMAC-SHA256",
        encoded=blob.decode("utf-8"),
        notes="Example format: pbkdf2_sha256$iterations$salt$hash (salt and hash are base64).",
    )


def verify_pbkdf2(password: str, encoded: str) -> bool:
    try:
        prefix, iters, b64_salt, b64_hash = encoded.split("$", 3)
        if prefix != "pbkdf2_sha256":
            return False
        iterations = int(iters)
        salt = base64.b64decode(b64_salt.encode("utf-8"))
        expected = base64.b64decode(b64_hash.encode("utf-8"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hashlib.compare_digest(dk, expected)
    except Exception:
        return False


def optional_hash(password: str, algorithm: str = "argon2id") -> HashResult:
    """Try Argon2id/bcrypt/scrypt if the relevant library exists.

    This is for education and demos. In real apps, use a mature auth library/framework.
    """
    alg = algorithm.lower().strip()

    if alg in {"argon2", "argon2id"}:
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher()  # uses reasonable defaults; tune per OWASP guidance in real systems
            hashed = ph.hash(password)
            return HashResult("Argon2id", hashed, "Generated with argon2-cffi PasswordHasher defaults.")
        except Exception as e:
            return HashResult("Argon2id", "", f"argon2-cffi not available or failed: {e}")

    if alg == "bcrypt":
        try:
            import bcrypt
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
            return HashResult("bcrypt", hashed, "Generated with bcrypt default cost from gensalt().")
        except Exception as e:
            return HashResult("bcrypt", "", f"bcrypt not available or failed: {e}")

    if alg == "scrypt":
        # Python has hashlib.scrypt built-in
        salt = os.urandom(16)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
        blob = b"scrypt$" + base64.b64encode(salt) + b"$" + base64.b64encode(dk)
        return HashResult("scrypt", blob.decode("utf-8"), "Example format: scrypt$salt$hash (base64).")

    return HashResult(algorithm, "", "Unknown algorithm. Use argon2id, bcrypt, scrypt, or pbkdf2.")
