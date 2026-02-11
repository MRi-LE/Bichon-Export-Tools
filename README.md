# Bichon-Export-Tools (WIP )

**Authored by MRi-LE**

[![Blog](https://img.shields.io/badge/Read_The-Blog_Post-blue?style=for-the-badge&logo=ghost)](https://michaelrichter.online/bichon-a-lightweight-email-archiver/)


Forensic email recovery pipeline for Bichon `.store` files (Zstandard frame containers).

This project reconstructs top-level email messages from compressed `.store` files while **preventing DKIM/ARC header ghosts** (e.g. `Subject:Date;` artifacts inside signature blocks).

The conservative strategy focuses on:

> Recovering real but slightly broken top-level emails without reopening embedded DKIM/ARC false positives.



#  Project Overview

Bichon `.store` files are containers of concatenated **Zstandard (ZSTD) frames**.  
Each frame may contain:

- Complete emails
- Partial emails
- Concatenated email blobs
- Embedded forwarded messages
- DKIM/ARC signature header lists
- Header fragments

The pipeline reconstructs valid top-level messages while rejecting embedded or signature-based false positives.


## Requirements

- Python 3.10+
- pip install zstandard
- pip install dateutils

Standard library modules used:
- re
- csv
- hashlib
- tarfile
- argparse
- email.utils
- email.header
- datetime
- collections
- pathlib
- io
- os


## Usage
```python
python3 bichon_mail_exporter.py -p /path/to/store/files --max-bytes $((200*1024*1024))
```


#### Optional parameters:

| Flag             | Meaning                                        |
| ---------------- | ---------------------------------------------- |
| `-p`             | Root directory containing `.store` files       |
| `-o`             | Custom output directory                        |
| `--max-bytes`    | Maximum decompressed frame size                |
| `--no-tar`       | Skip tar.gz creation                           |
| `--write-frames` | Write decompressed frames (debug only, large!) |

## Pipeline Architecture

##### Stage 1 — Discover .store files

Recursively scans the input directory for:

`*.store`

These files are treated as ZSTD frame containers.

##### Stage 2 — Frame Splitting & Decompression

Each .store file is split at the ZSTD magic header:

`28 b5 2f fd`


Each frame is decompressed independently.

##### Output
frames_report.csv

| Column             | Meaning                            |
| ------------------ | ---------------------------------- |
| store_file         | Source `.store` file               |
| frame_index        | Frame number                       |
| frame_bytes        | Compressed size                    |
| decompressed_bytes | Decompressed size                  |
| decompress_ok      | 1 = success                        |
| has_return_path    | 1 if frame contains `Return-Path:` |


## Stage 3 — Carving Messages

This is the forensic core.

Carving is performed in two tiers.

##### Tier 1 — Return-Path Segmentation

If a frame contains:

`Return-Path:`


It is segmented at:

`^Return-Path:`


Each segment becomes a candidate email region.

##### Tier 2 — Strict Top-Level Header Detection

Each region is scanned for a valid header block.

A block is accepted only if:

1.	Contains a header/body separator (\n\n)
2.	Does NOT start with:
o	DKIM-Signature:
o	ARC-Message-Signature:
o	Authentication-Results:
o	ARC-Authentication-Results:
3.	Contains at least 3 of 4 core headers:
o	From
o	To (or Delivered-To)
o	Date
o	Message-ID
4.	Contains a valid From: header
5.	Is not in quoted/forwarded context (`>, |, "Original Message"`)
This prevents carving embedded signature metadata as separate emails.

## Stage 4 — Deduplication
Messages are deduplicated using:
1.	Message-ID (primary key)
2.	SHA-256 fingerprint (fallback if no Message-ID)
Rejected duplicates are logged in:
`carve_report.csv`

	Possible rejection reasons:
	•	dup_message_id
	•	dup_fingerprint
	•	validator_reject
	•	no_messages

## Stage 5 — Segment Storage
Each accepted message is written to:
`segments/*.seg`
These files contain the raw carved bytes and serve as forensic evidence.

## Stage 6 — dump.out
All carved messages concatenated into:
`dump.out`
Useful for quick searching:
grep -a -n "Keyword" OUTDIR/dump.out

## Stage 7 — clean_emails.csv
Final deduplicated index of accepted messages.

Contains:
•	segment_file
•	from
•	to
•	date
•	subject
•	message_id
•	store_file
•	frame_index
•	tier

## Stage 8 — EML Reconstruction
Each segment is written as:
`reconstructed/*.eml`
Filename format:
`<index>_<date>_<sender>_<subject>.eml`
If subject missing:
`NO_SUBJECT`
Note: Missing subject does NOT imply invalid email.

## Stage 9 — TAR Archive
All .eml files are packed into:
`date_bichon_mail_export.tar.gz`

## Output Structure

    YYYYMMDD_HHMMSS_bichon_mail_export/
    │
    ├── frames_report.csv
    ├── carve_report.csv
    ├── clean_emails.csv
    ├── dump.out
    ├── summary.txt
    ├── segments/
    ├── reconstructed/
    ├── debug/
    └── date_bichon_mail_export.tar.gz

## Debugging & Tuning Guide

###### Check Frame Decompression
```python
python3 - <<'PY'
import csv, collections
c = collections.Counter()
with open("OUTDIR/frames_report.csv", newline="") as f:
    for r in csv.DictReader(f):
        c[r["decompress_ok"]] += 1
print(c)
PY
```
If failures occur → increase --max-bytes.

###### Count Frames With Return-Path
```python
python3 - <<'PY'
import csv, collections
c = collections.Counter()
with open("OUTDIR/frames_report.csv", newline="") as f:
    for r in csv.DictReader(f):
        c[r["has_return_path"]] += 1
print(c)
PY
```

###### Count Accepted Messages by Tier
```python
python3 - <<'PY'
import csv, collections
c = collections.Counter()
with open("OUTDIR/carve_report.csv", newline="") as f:
    for r in csv.DictReader(f):
        if r["accepted"] == "1":
            c[r["tier"]] += 1
print(c)
PY
```

**If Carved = 0**
Check:
•	Only no_messages in carve_report?
→ header validation too strict
•	Only validator_reject?
→ boundary detection issue

**If Too Many Messages**
Likely DKIM/ARC ghosts returned.
Search for:
Subject:Date;
If present → header validation too loose.


## Philosophy
This pipeline intentionally favors:

- Accuracy over maximum count
- Top-level message integrity
- Avoiding embedded/quoted message carving
- Avoiding DKIM/ARC header list ghosts



