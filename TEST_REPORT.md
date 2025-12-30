# Test Report (Password Security Suite)

## What was tested
1. **Entropy calculation** produces increasing values with longer/more diverse inputs.
2. **Pattern detection** flags obvious weak patterns (sequences, keyboard runs, repeats).
3. **Common password detection** flags exact matches and common substrings.
4. **Batch audit** processes multiple lines and returns structured results.
5. **Export** writes valid JSON and CSV outputs.
6. **Hashing demo (PBKDF2)** generates a salted hash and verifies correctly.

## How to run a quick manual test

### 1) Run interactive suite
```bash
python3 run_suite.py
```

Test these examples (do NOT use them in real accounts):
- `password`
- `Qwerty123`
- `Correct-Horse-Battery-Staple-42`  (a passphrase-style example)

Expected:
- `password` shows HIGH risk and common/breached warnings.
- The passphrase-style example shows lower risk with good length.

### 2) Batch test
Create a file `samples.txt`:
```text
password
12345678
Summer2025!
Correct-Horse-Battery-Staple-42
```

Run:
```bash
python3 -m password_suite.cli batch ./samples.txt
```

Expected:
- Exports created under `exports/`
- Risk breakdown includes at least 1 HIGH and 1 LOW/MEDIUM.

### 3) Hashing demo
```bash
python3 -m password_suite.cli hash --alg pbkdf2
```
Expected:
- Prints a hash line like `pbkdf2_sha256$...`
- Prints `verify: True`

## Known limitations
- Crack time is a **rough estimate** based on entropy and an assumed guess rate.
- Breach-list matching is a simple line-by-line equality check. Large lists may be slow.
