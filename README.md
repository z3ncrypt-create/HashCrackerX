# HashCrackX

**HashCrackX**  — a lightweight CLI tool to *detect* and *decode* common encodings, ciphers and obfuscation used in CTFs and pentesting. Developed by **Zencrypt**.

---

## Summary

Paste an encoded/obfuscated string and the tool will attempt to identify which method(s) were used and show decoded output when possible. Hashes (MD5, SHA-*) are **identified only** (not reversible).

This repository contains a single-file CLI tool and supporting files to run it locally.

---

## Features

* Detects and identifies common **hashes**: MD5, SHA1, SHA224, SHA256, SHA384, SHA512 (identified only).
* Detects and decodes many encodings and ciphers, including:

  * Base64 (standard & URL-safe), Base32, Base85 (a85/b85), Base58
  * Hex, Binary
  * URL encoding, HTML entities, UUEncode
  * ROT13, ROT5, ROT18 (letters + digits), Caesar (all shifts via helper)
  * Atbash, Reverse, Morse
  * Single-byte XOR brute-force (filtered high-confidence candidates)
  * Heuristic Vigenère attempts using a small built-in keylist
* Multi-layer peeling (breadth-first, limited depth) to detect chained encodings.
* Bannered, colored CLI using `pyfiglet` and `termcolor`.

---

## Requirements

Minimum tested with **Python 3.8+**.

`requirements.txt` (included in repo):

```
pyfiglet==0.8.post1
termcolor==1.1.0
# optional but recommended for Windows terminal colors
colorama==0.4.6
# optional: robust Base58 implementation
base58==2.1.1
```

> The script uses only Python standard library modules for all decoding logic; third-party packages are used for UI niceties.

---

## Files in this repository

* `hashcrackx.py — the main CLI tool (single-file).
* `requirements.txt` — Python package list for easy installation.
* `.gitignore` — recommended file to ignore `__pycache__`, `*.pyc`, virtualenv folders, etc.
* `README.md` — this document.

---

## Installation

1. Create a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate  # macOS / Linux
.\.venv\Scripts\activate   # Windows PowerShell
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Make the script executable (Linux/macOS):

```bash
chmod +x hashcrackerx.py
```

---

## Usage

Run the tool and paste the encoded/obfuscated string when prompted:

```bash
python hashcrackx.py
# or if executable
./hashcrackx.py
```

Example session:

```
$ python hashcrackx.py
🔹 Paste the encoded/obfuscated text: Uryyb Jbeyq

Likely methods (top 3):
1. ROT13 (confidence 90%)
   → Hello World
2. Atbash (confidence 60%)
   → ...

Multi-layer peel (limited):
[ROT13] -> Hello World
```

### Command-line options

* (Future) `--wordlist` — support will allow supplying a custom wordlist used for Vigenère / XOR cracking attempts. (If you include this feature, add it to the script and update the README.)

---

## Notes & best practices

* **Hashes are one-way.** The tool will only report that a string appears to be a hash (MD5/SHA*). It will not attempt to "decrypt" hashes.
* **Heuristics:** Some decoders (XOR, Vigenère) use heuristics and small keylists; they can produce false positives. Use the confidence score and readable snippets to judge usefulness.
* **Multi-layer decoding** is intentionally limited (depth-limited) to avoid explosion of candidates. Increase depth with caution.

---

## Contributing

Contributions are welcome! Suggested improvements:

* Add `--wordlist` support and allow custom wordlists for Vigenère/XOR (see `examples/wordlists/`).
* Add gzip/zip detection and automatic decompression for compressed payloads.
* Improve Base58 handling using the `base58` package and add Bitcoin address validation.
* Add unit tests and CI (GitHub Actions) to run linting and tests on push/pull requests.

Please fork the repository, create a feature branch, and open a pull request.

---

## License

This repository uses the **MIT License** by default. Add a `LICENSE` file with the MIT text.

---


