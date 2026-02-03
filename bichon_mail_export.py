#!/usr/bin/env python3

"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MRi-LE
# This software is provided "as is", without warranty of any kind.
# Authored by Michael Richter, with assistance from AI tools.
#
# Version 1.4: Directional Logic Recovery + Content-Aware + (FROM/TO) + Owner detection 
"""

import os
import zstandard as zstd
import tarfile
import io
import re
import hashlib
from pathlib import Path
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from email.header import decode_header
from collections import Counter

# === CONFIG ===
STORE_DIR = "/mnt/ssd-pool/bichon/eml"
OUTPUT_DIR = "/mnt/ssd-pool/bichon"
ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
MIN_FILE_SIZE = 2500 

def decode_mime(text):
    if not text: return ""
    try:
        decoded_parts = decode_header(text)
        res = ""
        for s, charset in decoded_parts:
            if isinstance(s, bytes):
                res += s.decode(charset or 'utf-8', errors='ignore')
            else: res += s
        return res
    except: return text

def sanitize_name(name, length=25):
    if not name: return "UNKNOWN"
    clean = re.sub(r'[^a-zA-Z0-9]', '_', str(name).split('@')[0])
    return re.sub(r'_+', '_', clean).strip('_')[:length].upper()

def extract_date(text):
    for pat in [r'(?i)^Date:\s*(.*)', r'(?i)^Received:.*?;([^\n]*)']:
        matches = re.findall(pat, text, re.MULTILINE)
        for m in reversed(matches):
            try:
                dt = parsedate_to_datetime(m.strip())
                if 1990 < dt.year < 2030: return dt.strftime("%Y-%m-%d")
            except: continue
    return None

def main():
    store_files = sorted(Path(STORE_DIR).glob("*.store"))
    dctx = zstd.ZstdDecompressor(max_window_size=2**31)
    
    raw_parts = []
    print(f"🚀 Version 1.4: Directional Logic Recovery...")

    # 1. DECOMPRESS AND COLLECT
    for store_file in store_files:
        with open(store_file, 'rb') as f:
            raw_data = f.read()
        full_buffer = b""
        chunks = raw_data.split(ZSTD_MAGIC)
        for chunk in chunks[1:]:
            try:
                full_buffer += dctx.decompress(ZSTD_MAGIC + chunk, max_output_size=100*1024*1024)
            except: continue

        raw_parts.extend(re.split(b'\n(?=Return-Path:|Received:|X-Account-Key:|From: )', full_buffer))

    # 2. DYNAMIC OWNER DETECTION
    # We look at the first 500 emails to see which address appears most in To/From
    addr_counter = Counter()
    for part in raw_parts[:500]:
        if len(part) < MIN_FILE_SIZE: continue
        text = part[:10000].decode('utf-8', errors='ignore')
        for pat in [r'(?i)^From:\s*(.*)', r'(?i)^To:\s*(.*)']:
            m = re.search(pat, text, re.MULTILINE)
            if m:
                _, addr = parseaddr(m.group(1))
                if addr: addr_counter[addr.lower()] += 1
    
    owner_email = addr_counter.most_common(1)[0][0] if addr_counter else "unknown_owner"
    print(f"👤 Detected Mailbox Owner: {owner_email}")

    # 3. PROCESS AND LABEL
    final_emails = []
    seen_hashes = set()
    for part in raw_parts:
        if len(part) < MIN_FILE_SIZE: continue
        
        content_hash = hashlib.md5(part[-3000:]).hexdigest()
        if content_hash in seen_hashes: continue
        seen_hashes.add(content_hash)

        text_sample = part[:32000].decode('utf-8', errors='ignore')
        
        f_date = extract_date(text_sample)
        subj_m = re.search(r'(?i)^Subject:\s*(.*)', text_sample, re.MULTILINE)
        from_m = re.search(r'(?i)^From:\s*(.*)', text_sample, re.MULTILINE)
        to_m = re.search(r'(?i)^To:\s*(.*)', text_sample, re.MULTILINE)

        raw_from = (from_m.group(1) if from_m else "").lower()
        raw_to = (to_m.group(1) if to_m else "").lower()
        
        if owner_email in raw_from:
            direction, entity_raw = "TO", raw_to
        else:
            direction, entity_raw = "FROM", raw_from

        entity = parseaddr(entity_raw)[0] or parseaddr(entity_raw)[1]

        final_emails.append({
            'bytes': part,
            'date': f_date,
            'dir': direction,
            'entity': sanitize_name(entity),
            'subj': sanitize_name(decode_mime(subj_m.group(1))) if subj_m else "NOSUBJECT"
        })

    # 4. INTERPOLATION
    last_date = "0000-00-00"
    for em in final_emails:
        if em['date']: last_date = em['date']
        else: em['date'] = last_date
    next_date = final_emails[-1]['date'] if final_emails else "0000-00-00"
    for em in reversed(final_emails):
        if em['date'] != "0000-00-00": next_date = em['date']
        elif em['date'] == "0000-00-00": em['date'] = next_date

    # 5. FINAL EXPORT
    current_day = datetime.now().strftime('%Y-%m-%d')
    final_filename = f"{current_day}_bichon_{len(final_emails)}_emails.tar.gz"
    final_path = os.path.join(OUTPUT_DIR, final_filename)

    with tarfile.open(final_path, "w:gz") as tar:
        for i, em in enumerate(final_emails):
            filename = f"{em['date']}_{em['dir']}_{em['entity']}_{em['subj']}_{i:05d}.eml"
            tar_info = tarfile.TarInfo(name=filename)
            tar_info.size = len(em['bytes'])
            tar.addfile(tar_info, fileobj=io.BytesIO(em['bytes']))

    print(f"\n🎉 Success! Archive created in your requested format.")
    print(f"📁 File: {final_path}")

if __name__ == "__main__":
    main()
