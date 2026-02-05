#!/usr/bin/env python3

"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MRi-LE
# This software is provided "as is", without warranty of any kind.
# Authored by Michael Richter, with assistance from AI tools.


Bichon Inspect Export Tool: Inspect or Search .eml files inside a .tar.gz archive.
- Added Fuzzy Date Parsing to resolve 'ERR' status.
- Enhanced German character support (ISO-8859-1 fallback).
- Fixed formatting for high-resolution terminals.

positional arguments:
  archive               Path to the .tar.gz or .tar file to process

options:
  -h, --help            show this help message and exit

Inspection Options:
  -l LIMIT, --limit LIMIT
                        Limit the number of files displayed during inspection (default: 10)



"""

import tarfile
import re
import argparse
import os
from email.header import decode_header
from email.utils import parsedate_to_datetime

# ---------------------------
# Helpers
# ---------------------------

def decode_mime(text):
    if not text:
        return ""
    try:
        parts = decode_header(text)
        out = ""
        for part, charset in parts:
            if isinstance(part, bytes):
                # Try multiple encodings for German/International support
                for enc in [charset, 'utf-8', 'iso-8859-1', 'latin-1']:
                    if not enc: continue
                    try:
                        out += part.decode(enc)
                        break
                    except: continue
                else:
                    out += part.decode('utf-8', errors='replace')
            else:
                out += str(part)
        return out.strip().replace('\n', ' ').replace('\r', '')
    except:
        return str(text).strip()

def extract_internal_metadata(content):
    """Extracts Subject and Date from the internal EML headers."""
    subj = None
    m_s = re.search(r'(?i)^Subject:\s*(.*?)(?:\r?\n[^\s]|\Z)', content, re.M | re.S)
    if m_s:
        subj = decode_mime(m_s.group(1))

    date_str = None
    m_d = re.search(r'(?i)^Date:\s*([^\r\n]+)', content, re.M)
    if m_d:
        try:
            # Standard RFC Parse
            raw_dt = re.sub(r'\s*\([^)]*\)', '', m_d.group(1)).strip()
            dt = parsedate_to_datetime(raw_dt)
            date_str = dt.strftime("%Y-%m-%d")
        except:
            # FUZZY FALLBACK: If standard parse fails, find YYYY-MM-DD pattern
            m_fuzz = re.search(r'(\d{4}-\d{2}-\d{2})', m_d.group(1))
            date_str = m_fuzz.group(1) if m_fuzz else "ERR_VAL"

    return subj, date_str

def extract_filename_metadata(filename):
    """Extracts Date and Subject from the Bichon naming convention."""
    base = os.path.basename(filename)
    date_m = re.match(r'(\d{4}-\d{2}-\d{2})', base)
    subj_m = re.search(r'_SUBJ_(.+?)_\d+\.eml$', base)

    f_date = date_m.group(1) if date_m else "0000-00-00"
    f_subj = subj_m.group(1).replace('_', ' ') if subj_m else "No_Subject"

    return f_date, f_subj

# ---------------------------
# Core logic
# ---------------------------

def process_archive(args):
    if not os.path.exists(args.archive):
        print(f"Error: File '{args.archive}' not found.")
        return

    search_keyword = args.search.lower() if args.search else None
    print(f"📦 Archive: {os.path.basename(args.archive)}")

    # Column Widths
    W_FILE, W_SIZE, W_DATE, W_SUBJ = 45, 10, 25, 50

    header = f"{'FILENAME (TRUNC)':<{W_FILE}} | {'SIZE':>{W_SIZE}} | {'DATE (INT vs FILE)':<{W_DATE}} | {'SUBJECT (INTERNAL)'}"
    print(header)
    print("-" * len(header))

    found = 0
    try:
        with tarfile.open(args.archive, "r:*") as tar:
            for member in tar:
                if not (member.isfile() and member.name.endswith(".eml")):
                    continue

                f = tar.extractfile(member)
                if not f: continue

                # Read enough for headers or deep search
                read_limit = 128 * 1024 if (search_keyword and args.body) else 32 * 1024
                raw = f.read(read_limit)

                try:
                    content = raw.decode("utf-8")
                except:
                    content = raw.decode("latin-1", errors="ignore")

                if search_keyword and search_keyword not in content.lower():
                    continue

                h_subj, h_date = extract_internal_metadata(content)
                f_date, f_subj = extract_filename_metadata(member.name)

                # Format filename display
                short_name = os.path.basename(member.name)
                if len(short_name) > W_FILE:
                    short_name = short_name[:W_FILE-3] + "..."

                disp_size = f"{member.size / 1024:.1f} KB"
                disp_date = f"{h_date or 'NONE':<10} / {f_date}"

                # Subject logic for the report
                subj_final = h_subj if h_subj else f"FILE: {f_subj}"
                if args.trust_filename and (not h_subj or h_subj == "No_Subject"):
                    subj_final = f"[F] {f_subj}"

                print(f"{short_name:<{W_FILE}} | {disp_size:>{W_SIZE}} | {disp_date:<{W_DATE}} | {subj_final[:W_SUBJ]}")

                found += 1
                if found >= args.limit:
                    break

        print("-" * len(header))
        print(f"Finished. Found {found} entries.")

    except Exception as e:
        print(f"Critical Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bichon Inspector Pro v2.3")
    parser.add_argument("archive", help="Path to .tar.gz")
    parser.add_argument("-l", "--limit", type=int, default=20)
    parser.add_argument("-s", "--search", help="Keyword search")
    parser.add_argument("-b", "--body", action="store_true", help="Search body")
    parser.add_argument("--trust-filename", action="store_true", help="Prefer filename subjects")
    args = parser.parse_args()
    process_archive(args)
