from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from .auditor import audit_password, get_policy_profile, CrackModel
from .exporters import export_csv, export_json
from .generators import PasswordGenConfig, PassphraseConfig, generate_password, generate_passphrase
from .hashing import pbkdf2_hash, verify_pbkdf2, optional_hash
from .logging_utils import setup_logger, log_event


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="password-suite",
        description="Password Security Suite (defensive): audit, generate, export, hashing demo.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # audit
    a = sub.add_parser("audit", help="Audit a password (interactive hidden input by default).")
    a.add_argument("--password", help="Provide password directly (not recommended).")
    a.add_argument("--breach-list", help="Optional local breach list file (one password per line).")
    a.add_argument("--common-list", default="common_passwords.csv", help="Common password CSV (default: common_passwords.csv).")
    a.add_argument("--policy", choices=["home", "enterprise"], default="home", help="Policy mode preset.")
    a.add_argument("--guess-rate", type=float, help="Override offline guesses/sec used for the crack-time estimate.")
    a.add_argument("--out-json", help="Write audit result to JSON file.")
    a.add_argument("--out-csv", help="Write audit result to CSV file (single row).")

    # genpass
    gp = sub.add_parser("genpass", help="Generate a secure random password.")
    gp.add_argument("--length", type=int, default=16)

    # genphrase
    gph = sub.add_parser("genphrase", help="Generate a passphrase.")
    gph.add_argument("--words", type=int, default=5)
    gph.add_argument("--sep", default="-")
    gph.add_argument("--cap", action="store_true")
    gph.add_argument("--no-number", action="store_true")

    # batch
    b = sub.add_parser("batch", help="Batch-audit passwords from a file (one per line).")
    b.add_argument("path", help="Input file path.")
    b.add_argument("--breach-list", help="Optional local breach list file (one password per line).")
    b.add_argument("--common-list", default="common_passwords.csv")
    b.add_argument("--policy", choices=["home", "enterprise"], default="home", help="Policy mode preset.")
    b.add_argument("--guess-rate", type=float, help="Override offline guesses/sec used for the crack-time estimate.")
    b.add_argument("--out-json", default="exports/audit_results.json")
    b.add_argument("--out-csv", default="exports/audit_results.csv")

    # hash demo
    h = sub.add_parser("hash", help="Hashing demo (PBKDF2 / optional Argon2id/bcrypt / scrypt).")
    h.add_argument("--alg", choices=["pbkdf2", "argon2id", "bcrypt", "scrypt"], default="pbkdf2")
    h.add_argument("--password", help="Provide password directly (not recommended).")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logger = setup_logger()

    if args.cmd == "audit":
        profile = get_policy_profile(args.policy)
        pw = args.password or getpass.getpass("Enter password (hidden): ")

        crack_model = profile.crack_model
        if args.guess_rate is not None:
            crack_model = CrackModel(guesses_per_second=float(args.guess_rate), description=crack_model.description)

        result = audit_password(
            pw,
            policy=profile.policy,
            crack_model=crack_model,
            common_passwords_path=args.common_list,
            breach_list_path=args.breach_list,
        )
        print(result)

        log_event(
            logger,
            "audit_cli",
            {"len": result["metrics"]["length"], "risk": result["metrics"]["risk"], "score": result["metrics"]["score_0_100"], "policy": profile.name},
        )

        if args.out_json:
            export_json([result], args.out_json)
        if args.out_csv:
            export_csv([result], args.out_csv)

    elif args.cmd == "genpass":
        pw = generate_password(PasswordGenConfig(length=args.length))
        print(pw)
        log_event(logger, "generate_password_cli", {"length": args.length})

    elif args.cmd == "genphrase":
        phrase = generate_passphrase(
            PassphraseConfig(
                words=args.words,
                separator=args.sep,
                capitalize=args.cap,
                add_number=not args.no_number,
            )
        )
        print(phrase)
        log_event(logger, "generate_passphrase_cli", {"words": args.words})

    elif args.cmd == "batch":
        profile = get_policy_profile(args.policy)
        p = Path(args.path)
        if not p.exists():
            raise SystemExit("Input file not found.")

        crack_model = profile.crack_model
        if args.guess_rate is not None:
            crack_model = CrackModel(guesses_per_second=float(args.guess_rate), description=crack_model.description)

        results = []
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.rstrip("\n\r")
                if not pw:
                    continue
                results.append(
                    audit_password(
                        pw,
                        policy=profile.policy,
                        crack_model=crack_model,
                        common_passwords_path=args.common_list,
                        breach_list_path=args.breach_list,
                    )
                )

        export_json(results, args.out_json)
        export_csv(results, args.out_csv)
        print(f"Audited {len(results)} passwords. Exported to {args.out_json} and {args.out_csv}.")
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for r in results:
            counts[r["metrics"]["risk"]] += 1
        log_event(logger, "batch_cli", {"count": len(results), "low": counts["LOW"], "med": counts["MEDIUM"], "high": counts["HIGH"], "policy": profile.name})

    elif args.cmd == "hash":
        pw = args.password or getpass.getpass("Enter password (hidden): ")
        if args.alg == "pbkdf2":
            hr = pbkdf2_hash(pw)
            print(hr.encoded)
            print("verify:", verify_pbkdf2(pw, hr.encoded))
        else:
            hr = optional_hash(pw, args.alg)
            print(hr.encoded or "(not available)")
            print("notes:", hr.notes)
        log_event(logger, "hash_cli", {"alg": args.alg})


if __name__ == "__main__":
    main()
