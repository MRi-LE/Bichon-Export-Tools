# Bichon-Export-Tools
**Authored by Michael (MRi-LE)**

[![Blog](https://img.shields.io/badge/Read_The-Blog_Post-blue?style=for-the-badge&logo=ghost)](https://michaelrichter.online/bichon-a-lightweight-email-archiver/)



Bichon Export Tool + Inspector with search capabilties due to lack of EML Export in Bichon



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
Edit the STORE_DIR and OUTPUT_FILE paths in bichon_mail_export.py, then run:

Bash
python3 bichon_mail_export.py

3. Inspect/Search Archive
Use the inspector tool to verify your results:

Bash
# List top 10 emails
python3 bichon_export_inspector.py path/to/archive.tar.gz -l 10

# Search for a keyword (Case Insensitive)
python3 bichon_export_inspector.py path/to/archive.tar.gz -s "Invoice" -b
