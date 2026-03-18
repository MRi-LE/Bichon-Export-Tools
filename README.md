# Bichon-Export-Tools

**Authored by MRi-LE**

[![Blog](https://img.shields.io/badge/Read_The-Blog_Post-blue?style=for-the-badge&logo=ghost)](https://michaelrichter.online/bichon-a-lightweight-email-archiver/)

Forensic email recovery tools for Bichon `.store` files built on a conservative, audit-friendly methodology.

This project reconstructs **top-level email messages** from compressed `.store` containers while deliberately avoiding common false positives such as:

- DKIM/ARC signature header lists
- quoted or forwarded embedded headers
- partial header fragments that resemble standalone messages

The guiding principle is:

> Recover real but slightly broken top-level emails without reopening embedded DKIM/ARC false positives.

---

# Project Overview

Bichon `.store` files act as containers of concatenated **Zstandard (ZSTD) frames**.  
A single decompressed frame may contain:

- complete emails
- partial emails
- multiple concatenated email blobs
- embedded forwarded messages
- quoted message headers
- DKIM/ARC signature metadata
- transport/header fragments

The pipeline focuses on reconstructing only **true top-level messages** and preserving an auditable trail of how they were detected.

---

# Current Capabilities

- Recursive discovery of `.store` files
- ZSTD frame splitting and independent decompression
- Conservative top-level email carving
- Strict rejection of DKIM/ARC “header ghost” artifacts
- Deduplication by `Message-ID` with hash fallback
- Canonical forensic CSV export
- Per-account account assignment CSV export
- Per-account reconstructed `.eml` folders
- Conservative provider-alias normalization
- `rcpt_hints` extraction from transport headers
- `dump.out` evidence file for grep-based inspection
- Optional `.tar.gz` packaging of reconstructed output

---

# Design Principles

This pipeline intentionally favors:

- **accuracy over maximum count**
- **false negatives over false positives**
- **top-level message integrity**
- **header-based evidence over body-based guessing**
- **reproducible output over aggressive recovery**
- **CSV-first forensic auditing**

In practical terms, that means some damaged emails may remain unrecovered, but signature ghosts and embedded header fragments are much less likely to be misidentified as real messages.

---

# Requirements

## Python

- Python 3.10+

## Dependency

Install the required external package:

```bash
pip install zstandard
