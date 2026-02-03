#!/usr/bin/env python3

"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MRi-LE
# This software is provided "as is", without warranty of any kind.
# Authored by Michael Richter, with assistance from AI tools.
#
# Version 1.4: Directional Logic Recovery + Content-Aware + (FROM/TO) + Owner detection 
# Version 1.5: fixed Bug in (FROM/TO) + Process Stages 
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
    name = re.sub(r'(?i)=\?utf-8\?[qb]\?.*?\?=', '', str(name))
    clean = re.sub(r'[^a-zA-Z0-9]', '_', name.split('@')[0])
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
    print(f"🚀 Version 1.5: Starting Recovery Engine...")

    # --- PHASE 1: DECOMPRESSION ---
    print("📂 Phase 1: Decompressing .store files...")
    for store_file in store_files:
        print(f"📖 {store_file.name}")
        with open(store_file, 'rb') as f:
            raw_data = f.read()
        
        full_buffer = b""
        chunks = raw_data.split(ZSTD_MAGIC)
        for chunk in chunks[1:]:
            try:
                full_buffer += dctx.decompress(ZSTD_MAGIC + chunk, max_output_size=100*1024*1024)
            except: continue
        
        new_parts = re.split(b'\n(?=Return-Path:|Received:|X-Account-Key:|From: )', full_buffer)
        raw_parts.extend(new_parts)
        print(f"   ✨ Added {len(new_parts)} potential email fragments.")

    # --- PHASE 2: IDENTITY DETECTION ---
    print("\n🔍 Phase 2: Analyzing Identity & Owner...")
    addr_counter = Counter()
    for part in raw_parts[:1500]: 
        if len(part) < MIN_FILE_SIZE: continue
        text = part[:5000].decode('utf-8', errors='ignore')
        if re.search(r'(?i)Michael|Richter', text):
            f_match = re.search(r'(?i)^From:\s*(.*)', text, re.MULTILINE)
            t_match = re.search(r'(?i)^To:\s*(.*)', text, re.MULTILINE)
            for m in [f_match, t_match]:
                if m:
                    _, addr = parseaddr(m.group(1))
                    if addr and ("michael" in addr.lower() or "richter" in addr.lower()):
                        addr_counter[addr.lower()] += 1
    
    owner_email = addr_counter.most_common(1)[0][0] if addr_counter else "michael_richter"
    print(f"👤 Detected Owner: {owner_email}")

    # --- PHASE 3: PROCESSING ---
    print("\n🛠️  Phase 3: Parsing Headers & Deduplicating...")
    final_emails = []
    seen_hashes = set()
    proc_count = 0

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
        
        is_sent_by_me = (owner_email in raw_from) or ("michael" in raw_from and "richter" in raw_from)
        
        if is_sent_by_me:
            direction = "TO"
            dest_raw = to_m.group(1) if to_m else "UNKNOWN_RECIPIENT"
        else:
            direction = "FROM"
            dest_raw = from_m.group(1) if from_m else "UNKNOWN_SENDER"

        dest = parseaddr(dest_raw)[0] or parseaddr(dest_raw)[1]

        final_emails.append({
            'bytes': part,
            'date': f_date,
            'dir': direction,
            'entity': sanitize_name(dest),
            'subj': sanitize_name(decode_mime(subj_m.group(1))) if subj_m else "NOSUBJECT"
        })
        
        proc_count += 1
        if proc_count % 500 == 0:
            print(f"   ✨ {proc_count} processed...")

    # --- PHASE 4: INTERPOLATION & EXPORT ---
    print("\n📅 Phase 4: Fixing Dates & Exporting...")
    # Forward Pass
    last_date = "0000-00-00"
    for em in final_emails:
        if em['date']: last_date = em['date']
        else: em['date'] = last_date
    # Backward Pass
    next_date = final_emails[-1]['date'] if final_emails else "0000-00-00"
    for em in reversed(final_emails):
        if em['date'] != "0000-00-00": next_date = em['date']
        elif em['date'] == "0000-00-00": em['date'] = next_date

    current_day = datetime.now().strftime('%Y-%m-%d')
    final_filename = f"{current_day}_bichon_{len(final_emails)}_emails.tar.gz"
    final_path = os.path.join(OUTPUT_DIR, final_filename)

    with tarfile.open(final_path, "w:gz") as tar:
        for i, em in enumerate(final_emails):
            filename = f"{em['date']}_{em['dir']}_{em['entity']}_{em['subj']}_{i:05d}.eml"
            tar_info = tarfile.TarInfo(name=filename)
            tar_info.size = len(em['bytes'])
            tar.addfile(tar_info, fileobj=io.BytesIO(em['bytes']))

    print(f"\n🎉 ALL DONE!")
    print(f"📦 Final Archive: {final_path}")
    print(f"📧 Total Unique Emails: {len(final_emails)}")

if __name__ == "__main__":
    main()

