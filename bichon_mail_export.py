#!/usr/bin/env python3

"""
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 MRi-LE
#
# This software is provided "as is", without warranty of any kind.
# Authored by Michael Richter, with assistance from AI tools.
"""

import os
import zstandard as zstd
import tarfile
import io
import re
from pathlib import Path

# === CONFIG ===
STORE_DIR = "/mnt/ssd-pool/bichon/eml"
OUTPUT_FILE = "/mnt/ssd-pool/bichon/exported_emails.tar.gz"
ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
MIN_SIZE = 2000 

def main():
    store_files = sorted(Path(STORE_DIR).glob("*.store"))
    dctx = zstd.ZstdDecompressor(max_window_size=2**31)
    total_count = 0

    print(f"Creating compressed archive: {OUTPUT_FILE}")
    
    # Open tarball for writing with gzip compression ('w:gz')
    with tarfile.open(OUTPUT_FILE, "w:gz") as tar:
        for store_file in store_files:
            print(f"Streaming from: {store_file.name}")
            with open(store_file, 'rb') as f:
                data = f.read()

            chunks = data.split(ZSTD_MAGIC)
            
            for chunk in chunks[1:]:
                try:
                    decompressed = dctx.decompress(ZSTD_MAGIC + chunk, max_output_size=100*1024*1024)
                    parts = re.split(b'\n(?=Return-Path:|Received:|From: )', decompressed)
                    
                    for part in parts:
                        clean_part = part.strip()
                        
                        # Apply our proven "Strict Filters"
                        if len(clean_part) > MIN_SIZE:
                            if clean_part.startswith((b"Return-Path:", b"Received:", b"From:")):
                                # Create a file-like object in memory
                                email_stream = io.BytesIO(clean_part)
                                
                                # Create header info for the file inside the tar
                                tar_info = tarfile.TarInfo(name=f"email_{total_count:05d}.eml")
                                tar_info.size = len(clean_part)
                                
                                # Add the memory stream to the tarball
                                tar.addfile(tar_info, fileobj=email_stream)
                                total_count += 1
                                
                                if total_count % 500 == 0:
                                    print(f"  Archived {total_count} emails...")
                except:
                    continue

    print(f"\nSuccess! Total of {total_count} emails streamed into {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
