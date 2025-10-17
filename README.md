# SHA-256 Implementation — Book of Mark Hash Project

# Overview
This project implements the **SHA-256 cryptographic hash algorithm** entirely in pure Python — without using any external hashing libraries such as `hashlib`.  
It uses the official algorithm steps from [Wikipedia: SHA-2](https://en.wikipedia.org/wiki/SHA-2) and applies it to the full text of the **Book of Mark**.

--

# Features
-  Pure Python SHA-256 implementation
-  Verified using test vectors (e.g., empty string and `"abc"`)
-  Normalizes the Book of Mark text for deterministic hashing
-  Optional automatic scraping from the source URL
-  Cross-checked against `hashlib` and OpenSSL for validation

---

# Project Structure
sha256_mark/
├── sha256_mark.py # Main algorithm & CLI tool
├── mark_rsv.txt # Raw text of the Book of Mark
├── normalized_mark.txt # Normalized text (generated automatically)
├── .gitignore # Git ignore rules
└── README.md # Documentation
---

#Algorithm Description
The `sha256_mark.py` file contains:
- Bitwise operations for message scheduling, rotation, and compression.
- Standard SHA-256 initialization vectors and round constants.
- Full message padding and block processing as per the specification.

---

# How to Run

# Setup
```bash
cd sha256_mark
python3 -m venv .venv
source .venv/bin/activate
pip install requests beautifulsoup4 lxml

# Run with Local Text
python3 sha256_mark.py --file mark_rsv.txt


Author

Mohammed Faiz
Master of Science in Computer Science — Concordia University Wisconsin
