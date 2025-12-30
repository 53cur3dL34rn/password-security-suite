from __future__ import annotations

import getpass
from pathlib import Path
from typing import Dict, List, Optional

from .auditor import audit_password, AuditPolicy, CrackModel, get_policy_profile, PolicyProfile
from .exporters import export_csv, export_json
from .generators import (
    PasswordGenConfig,
    PassphraseConfig,
    generate_password,
    generate_passphrase,
)
from .hashing import pbkdf2_hash, verify_pbkdf2, optional_hash
from .logging_utils import log_event


def _bar(score_0_100: int, width: int = 24) -> str:
    score = max(0, min(100, int(score_0_100)))
    filled = round((score / 100) * width)
    return "█" * filled + "░" * (width - filled)


def _pretty_audit(result: Dict, profile_name: str) -> str:
    m = result["metrics"]
    f = result["findings"]
    s = result["signals"]
    b = result.get("breakdown", {})

    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(f"PASSWORD AUDIT RESULT  (policy: {profile_name})")
    lines.append("=" * 72)
    lines.append(f"Risk: {m['risk']}   |   Score: {m['score_0_100']}/100")
    lines.append(f"Length: {m['length']} characters")
    lines.append(f"Entropy (estimate): {m['entropy_bits_estimate']} bits")
    lines.append(f"Offline crack time (estimate): {m['offline_crack_time_human_estimate']}")
    lines.append("-" * 72)

    # Score breakdown bars
    if b:
        lines.append("Score breakdown:")
        for k in ["length", "uniqueness", "patterns"]:
            if k in b:
                sc = int(b[k]["score_0_100"])
                note = b[k].get("note", "")
                lines.append(f"  {k.title():11} [{_bar(sc)}] {sc:>3}/100  - {note}")
        lines.append("-" * 72)

    lines.append("Signals:")
    lines.append(
        f"  Upper: {s['has_upper']} | Lower: {s['has_lower']} | Digit: {s['has_digit']} | "
        f"Symbol: {s['has_symbol']} | Space: {s['has_space']}"
    )
    lines.append("-" * 72)

    if f["common_password_exact"]:
        lines.append("🚨 Common password: EXACT match")
    elif f["common_password_substring"]:
        lines.append("⚠️  Common password: contains a common substring")

    if f["breach_list_hit"]:
        lines.append("🚨 Breach list: found in local list")

    if f["patterns"]:
        lines.append("Patterns detected:")
        for p in f["patterns"]:
            lines.append(f"  - {p}")
    else:
        lines.append("Patterns detected: none obvious")

    if f.get("space_note"):
        lines.append(f"Note: {f['space_note']}")

    lines.append("-" * 72)
    lines.append("Recommendations:")
    for r in result["recommendations"]:
        lines.append(f"  - {r}")
    lines.append("=" * 72)
    return "\n".join(lines)


def _choose_profile() -> PolicyProfile:
    print("\nChoose policy mode:")
    print("1) Home (min 12, prefer 16, normal attacker model)")
    print("2) Enterprise (min 14, prefer 20, stronger attacker model)")
    choice = input("Pick (1-2, default 1): ").strip() or "1"
    return get_policy_profile("enterprise" if choice == "2" else "home")


def run_menu(logger) -> None:
    profile = get_policy_profile("home")
    results_cache: List[Dict] = []

    while True:
        print("\n🔐 PASSWORD SECURITY SUITE")
        print("=" * 72)
        print(f"Active policy mode: {profile.name}")
        print("1) Audit a password (no echo)")
        print("2) Generate a secure password")
        print("3) Generate a passphrase")
        print("4) Batch audit passwords from file")
        print("5) Export last audit results (JSON/CSV)")
        print("6) Hashing demo (PBKDF2 / optional Argon2id/bcrypt/scrypt)")
        print("7) Switch policy mode (home vs enterprise)")
        print("8) Exit")
        print("=" * 72)

        choice = input("Pick an option (1-8): ").strip()

        if choice == "1":
            pw = getpass.getpass("Enter password to audit (hidden): ").strip()
            if not pw:
                print("❌ Empty password. Try again.")
                continue

            breach_path = input("Optional: path to local breach list file (Enter to skip): ").strip() or None
            breach_path = breach_path if breach_path else None

            result = audit_password(
                pw,
                policy=profile.policy,
                crack_model=profile.crack_model,
                breach_list_path=breach_path,
            )
            results_cache = [result]
            print(_pretty_audit(result, profile.name))
            log_event(logger, "audit", {"len": result["metrics"]["length"], "risk": result["metrics"]["risk"], "score": result["metrics"]["score_0_100"], "policy": profile.name})

        elif choice == "2":
            try:
                length = int(input("Length (default 16): ").strip() or "16")
                cfg = PasswordGenConfig(length=length)
                pw = generate_password(cfg)
                print("\n✅ Generated password:")
                print(pw)
                log_event(logger, "generate_password", {"length": length, "policy": profile.name})
            except Exception as e:
                print(f"❌ Could not generate: {e}")

        elif choice == "3":
            try:
                words = int(input("Number of words (default 5): ").strip() or "5")
                sep = input("Separator (default '-'): ").strip() or "-"
                cap = (input("Capitalize words? (y/N): ").strip().lower() == "y")
                add_num = (input("Add 2-digit number? (Y/n): ").strip().lower() != "n")
                cfg = PassphraseConfig(words=words, separator=sep, capitalize=cap, add_number=add_num)
                phrase = generate_passphrase(cfg)
                print("\n✅ Generated passphrase:")
                print(phrase)
                log_event(logger, "generate_passphrase", {"words": words, "policy": profile.name})
            except Exception as e:
                print(f"❌ Could not generate: {e}")

        elif choice == "4":
            path = input("Path to file (one password per line): ").strip()
            if not path:
                print("❌ No file path provided.")
                continue
            p = Path(path)
            if not p.exists():
                print("❌ File not found.")
                continue

            breach_path = input("Optional: path to local breach list file (Enter to skip): ").strip() or None
            breach_path = breach_path if breach_path else None

            batch_results: List[Dict] = []
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    pw = line.rstrip("\n\r")
                    if not pw:
                        continue
                    batch_results.append(
                        audit_password(
                            pw,
                            policy=profile.policy,
                            crack_model=profile.crack_model,
                            breach_list_path=breach_path,
                        )
                    )

            results_cache = batch_results
            print(f"✅ Audited {len(batch_results)} passwords.")
            counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            for r in batch_results:
                counts[r["metrics"]["risk"]] += 1
            print(f"Risk breakdown: {counts}")
            log_event(logger, "batch_audit", {"count": len(batch_results), "low": counts["LOW"], "med": counts["MEDIUM"], "high": counts["HIGH"], "policy": profile.name})

        elif choice == "5":
            if not results_cache:
                print("❌ No results to export yet. Run an audit first.")
                continue
            out_dir = Path("exports")
            out_dir.mkdir(exist_ok=True)
            json_path = export_json(results_cache, out_dir / "audit_results.json")
            csv_path = export_csv(results_cache, out_dir / "audit_results.csv")
            print(f"✅ Exported:\n - {json_path}\n - {csv_path}")
            log_event(logger, "export", {"json": str(json_path), "csv": str(csv_path), "count": len(results_cache), "policy": profile.name})

        elif choice == "6":
            pw = getpass.getpass("Enter password to hash (hidden): ").strip()
            if not pw:
                print("❌ Empty password.")
                continue

            print("\nChoose hashing algorithm:")
            print("1) PBKDF2-HMAC-SHA256 (stdlib)")
            print("2) Argon2id (optional, needs argon2-cffi)")
            print("3) bcrypt (optional, needs bcrypt)")
            print("4) scrypt (stdlib)")
            opt = input("Pick (1-4): ").strip()

            if opt == "1":
                hr = pbkdf2_hash(pw)
                print("\nHashed output:")
                print(hr.encoded)
                ok = verify_pbkdf2(pw, hr.encoded)
                print(f"Verify works: {ok}")
                log_event(logger, "hash_demo", {"alg": hr.algorithm, "policy": profile.name})
            elif opt == "2":
                hr = optional_hash(pw, "argon2id")
                print("\nHashed output:")
                print(hr.encoded or "(not available)")
                print(f"Notes: {hr.notes}")
                log_event(logger, "hash_demo", {"alg": hr.algorithm, "available": bool(hr.encoded), "policy": profile.name})
            elif opt == "3":
                hr = optional_hash(pw, "bcrypt")
                print("\nHashed output:")
                print(hr.encoded or "(not available)")
                print(f"Notes: {hr.notes}")
                log_event(logger, "hash_demo", {"alg": hr.algorithm, "available": bool(hr.encoded), "policy": profile.name})
            elif opt == "4":
                hr = optional_hash(pw, "scrypt")
                print("\nHashed output:")
                print(hr.encoded)
                print(f"Notes: {hr.notes}")
                log_event(logger, "hash_demo", {"alg": hr.algorithm, "policy": profile.name})
            else:
                print("❌ Invalid option.")

        elif choice == "7":
            profile = _choose_profile()
            print(f"✅ Switched policy mode to: {profile.name}")
            log_event(logger, "switch_policy", {"policy": profile.name})

        elif choice == "8":
            log_event(logger, "exit", {"policy": profile.name})
            print("Bye.")
            break

        else:
            print("❌ Invalid choice. Pick 1-8.")
