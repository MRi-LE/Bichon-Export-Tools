#!/usr/bin/env python3
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MRi-LE
# This software is provided "as is", without warranty of any kind.
# Authored by Michael Richter, with assistance from AI tools.

- Scans .store Zstd files recursively
- Detects legit accounts (≥10% weight)
- Matches emails to accounts via To/Delivered-To headers, with From-header fallback
- Duplicates emails for multiple accounts
- Produces dump.out and TAR.GZ archive
- Staged progress output + summary table
- Garbage / unknown emails tracked separately
"""

import os, re, sys, io, tarfile, hashlib, argparse
from pathlib import Path
from collections import Counter, defaultdict
from email.utils import parseaddr, parsedate_to_datetime, formatdate
from email.header import decode_header
from datetime import datetime
import zstandard as zstd

ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'

# ---------------------- Utilities ----------------------
def decode_mime_header(s):
    if not s:
        return ""
    s = re.sub(r'[\r\n\t]+', ' ', s).strip()
    try:
        parts = decode_header(s)
        decoded = []
        for content, charset in parts:
            if isinstance(content, bytes):
                decoded.append(content.decode(charset or 'utf-8', errors='ignore'))
            else:
                decoded.append(str(content))
        return "".join(decoded).strip()
    except:
        return s

def sanitize_name(text, length=40):
    if not text:
        return "UNK"
    clean = re.sub(r'[^a-zA-Z0-9]', '_', text)
    clean = re.sub(r'_+', '_', clean).strip('_')
    return clean[:length].upper()

def parse_date_from_headers(raw_bytes, fallback="0000-00-00"):
    text = raw_bytes.decode('utf-8', errors='replace')
    date_match = re.search(r'(?i)^(Date|Datum):\s*([^\r\n]+)', text, re.M)
    if date_match:
        try:
            dt = parsedate_to_datetime(date_match.group(2).strip())
            return dt.strftime("%Y-%m-%d")
        except: pass
    return fallback

# ---------------------- Account Detection ----------------------
def detect_accounts(store_files):
    tally = Counter()
    dctx = zstd.ZstdDecompressor(max_window_size=2**31)
    print(f"🚀 Stage 1: Scanning {len(store_files)} .store files for account detection...")

    for sf in store_files:
        with open(sf, 'rb') as f:
            chunks = f.read().split(ZSTD_MAGIC)
            for chunk in chunks[1:]:
                try:
                    dec = dctx.decompress(ZSTD_MAGIC + chunk, max_output_size=1024*1024)
                    txt = dec.decode('utf-8', errors='ignore')
                    to_addrs = re.findall(r'(?i)^(?:To|Delivered-To):\s*([^\n]+)', txt, re.MULTILINE)
                    for addr_raw in to_addrs:
                        _, addr = parseaddr(addr_raw)
                        if addr and '@' in addr:
                            addr_lower = addr.lower()
                            tally.update([addr_lower])
                except:
                    continue
    total = sum(tally.values())
    accounts = [a for a, c in tally.items() if c / max(1, total) >= 0.10]
    print(f"✅ Stage 1 complete: Detected legit accounts ≥10% weight: {accounts}\n")
    return accounts

# ---------------------- Email Extraction ----------------------
def extract_emails(store_files, accounts):
    dctx = zstd.ZstdDecompressor(max_window_size=2**31)
    all_emails = []
    dump_lines = []
    acc_counts = Counter()
    earliest_date = None

    print(f"🚀 Stage 2: Extracting emails from .store files...")

    for sf in store_files:
        print(f"   📖 Processing {sf.name}...")
        with open(sf, 'rb') as f:
            chunks = f.read().split(ZSTD_MAGIC)
            for chunk in chunks[1:]:
                try:
                    dec = dctx.decompress(ZSTD_MAGIC + chunk, max_output_size=200*1024*1024)
                    positions = [m.start() for m in re.finditer(b'Return-Path:', dec)]
                    positions.append(len(dec))
                    for i in range(len(positions)-1):
                        email_bytes = dec[positions[i]:positions[i+1]]

                        # Determine date
                        date_str = parse_date_from_headers(email_bytes)
                        if earliest_date is None or (date_str != "0000-00-00" and date_str < earliest_date):
                            earliest_date = date_str

                        # Determine accounts
                        text = email_bytes.decode('utf-8', errors='ignore').lower()
                        matched_accounts = set()
                        for acc in accounts:
                            if acc.lower() in text:
                                matched_accounts.add(acc)
                        # Fallback: From header
                        if not matched_accounts:
                            from_m = re.search(r'(?i)^From:\s*([^\r\n]+)', text, re.MULTILINE)
                            if from_m:
                                _, addr = parseaddr(from_m.group(1))
                                if addr and addr.lower() in accounts:
                                    matched_accounts.add(addr.lower())
                        if not matched_accounts:
                            matched_accounts.add("UNK")

                        # Prepare dump_lines
                        dump_lines.append(f"\n===== EMAIL {len(all_emails):05d} =====\nSIZE: {len(email_bytes)} bytes\nHASH: {hashlib.md5(email_bytes[:4096]).hexdigest()}\n--------------------------\n".encode('utf-8'))
                        dump_lines.append(email_bytes)

                        # Duplicate per account
                        for acc in matched_accounts:
                            all_emails.append({
                                "bytes": email_bytes,
                                "acc": acc.upper(),
                                "date": date_str
                            })
                            acc_counts.update([acc.upper()])

                except:
                    continue

    return all_emails, dump_lines, acc_counts, earliest_date

# ---------------------- Tarball Creation ----------------------
def build_tarball(emails, output_path):
    print(f"\n📦 Stage 4: Building TAR.GZ archive: {output_path}")
    with tarfile.open(output_path, "w:gz") as tar:
        for idx, em in enumerate(emails):
            text = em["bytes"].decode('utf-8', errors='ignore')
            subj_m = re.search(r'(?i)^Subject:\s*(.*?)(?=\r?\n[A-Z]|$)', text, re.M)
            subj = decode_mime_header(subj_m.group(1)) if subj_m else "NO_SUBJECT"
            clean_subj = sanitize_name(subj, 40)

            # Filename: <ACCOUNT>_<DATE>_<FROM or TO>_<SENDER or RECEPIENT>_<SUBJECT>
            from_m = re.search(r'(?i)^From:\s*([^\r\n]+)', text, re.M)
            from_name = sanitize_name(parseaddr(from_m.group(1))[0]) if from_m else "UNK"
            to_m = re.search(r'(?i)^(To|Delivered-To):\s*([^\r\n]+)', text, re.M)
            to_name = sanitize_name(parseaddr(to_m.group(2))[0]) if to_m else "UNK"

            fname = f"{em['acc']}_{em['date']}_{from_name}_{to_name}_{clean_subj}_{idx:05d}.eml"
            ti = tarfile.TarInfo(name=fname)
            ti.size = len(em["bytes"])
            tar.addfile(ti, fileobj=io.BytesIO(em["bytes"]))

# ---------------------- Main ----------------------
def main():
    parser = argparse.ArgumentParser(description="Bichon v93 Mail Export")
    parser.add_argument("-p", "--path", required=True, help="Path to folder containing .store files")
    args = parser.parse_args()

    root = Path(args.path)
    store_files = sorted(root.glob("*.store"))

    # Stage 1: Account Detection
    accounts = detect_accounts(store_files)

    # Stage 2: Email Extraction
    emails, dump_lines, acc_counts, earliest_date = extract_emails(store_files, accounts)

    # Stage 3: Dump File
    dump_file = root / "dump.out"
    print(f"\n💾 Stage 3: Writing dump file: {dump_file}")
    with open(dump_file, "wb") as df:
        for line in dump_lines:
            df.write(line if isinstance(line, bytes) else line.encode('utf-8'))

    # Stage 4: Build Tarball
    out_name = root / f"{earliest_date}_bichon_mail_export.tar.gz" if earliest_date else root / "bichon_mail_export.tar.gz"
    build_tarball(emails, out_name)

    # Stage 5: Summary Table
    print(f"\n📊 Stage 5: Summary Table (Account Duplicates & Weights)")
    total_emails = sum(acc_counts.values())
    print(f"{'Account':<25}{'Emails':>8}{'Weight %':>12}")
    print("-"*45)
    for acc, count in acc_counts.most_common():
        weight = (count / max(1, total_emails)) * 100
        print(f"{acc:<25}{count:>8}{weight:>12.2f}%")
    print(f"\n✅ Extraction Complete.\nDump: {dump_file}\nArchive: {out_name}")

if __name__ == "__main__":
    main()

