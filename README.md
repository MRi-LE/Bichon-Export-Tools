# Bichon-Export-Tools
**Authored by Michael (MRi-LE)**

[![Blog](https://img.shields.io/badge/Read_The-Blog_Post-blue?style=for-the-badge&logo=ghost)](https://michaelrichter.online/bichon-a-lightweight-email-archiver/)



Bichon Export Tool + Inspector with search capabilties due to current lack of EML Export in Bichon



## 🚀 Key Features
- **On-the-fly Archiving:** Streams recovered emails directly into a `.tar.gz` file without writing individual files to disk (saves SSD wear and metadata overhead).
- **Forensic Carving:** Uses magic-byte detection (`ZSTD_MAGIC`) to identify and decompress email chunks.
- **Strict Filtering:** Automatically filters out metadata noise and fragments by enforcing minimum size and header validation (`Return-Path`, `Received`, `From`).
- **Integrated Inspector:** Includes a built-in search and inspection tool to query headers and bodies inside the compressed archive.

## 🛠️ Requirements
- Python 3.11+
- `zstandard` library

## 📖 Usage


```bash
1. Setup Environment

python3 -m venv venv
source venv/bin/activate
pip install zstandard

2. Export Emails

$ python3 bichon_mail_export.py
Version 1.5: Starting Recovery Engine...
Phase 1: Decompressing .store files...
13d8203e5c1548fbb3db76fbfc367d77.store
   Added 3 potential email fragments.
3e75823dafc84cdcbea042997e203d3c.store
   Added 17851 potential email fragments.
5cbc891ac2304fd8a6c6e9d58f062d4b.store
   Added 4 potential email fragments.
7ed490b08b444286bd17e8dc8c6e978c.store
   Added 9 potential email fragments.

Phase 2: Analyzing Identity & Owner...
Detected Owner: mail@MRi-LE

Phase 3: Parsing Headers & Deduplicating...
   500 processed...
   1000 processed...
   1500 processed...
   2000 processed...
   2500 processed...
   3000 processed...
   3500 processed...
   4000 processed...
   4500 processed...
   5000 processed...

Phase 4: Fixing Dates & Exporting...

ALL DONE!
Final Archive: /mnt/ssd-pool/bichon/2026-02-03_bichon_5452_emails.tar.gz
Total Unique Emails: 5452



3. Inspect/Search Archive

Use the inspector tool to verify your results:

Bash
# List top 10 emails
python3 bichon_export_inspector.py path/to/archive.tar.gz -l 10

# Search for a keyword (Case Insensitive)
python3 bichon_export_inspector.py path/to/archive.tar.gz -s "Invoice" -b
