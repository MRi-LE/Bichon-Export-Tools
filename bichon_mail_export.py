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
from datetime import datetime

# === CONFIG ===
STORE_DIR = "/mnt/ssd-pool/bichon/eml"
OUTPUT_DIR = "/mnt/ssd-pool/bichon"
ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
MIN_SIZE = 2000 

def main():
    store_files = sorted(Path(STORE_DIR).glob("*.store"))
    dctx = zstd.ZstdDecompressor(max_window_size=2**31)
    total_count = 0
    
    # 1. Create a temporary filename for the streaming process
    temp_output = os.path.join(OUTPUT_DIR, "recovery_in_progress.tar.gz")
    date_str = datetime.now().strftime("%Y-%m-%d")

    print(f"Starting recovery process...")
    
    try:
        with tarfile.open(temp_output, "w:gz") as tar:
            for store_file in store_files:
                print(f"Streaming from: {store_file.name}")
                with open(store_file, 'rb') as f:
                    data = f.read()

                chunks = data.split(ZSTD_MAGIC)
                
                for chunk in chunks[1:]:
                    try:
                        decompressed = dctx.decompress(ZSTD_MAGIC + chunk, max_output_size=100*1024*1024)
                        # Split based on common email headers
                        parts = re.split(b'\n(?=Return-Path:|Received:|From: )', decompressed)
                        
                        for part in parts:
                            clean_part = part.strip()
                            
                            if len(clean_part) > MIN_SIZE:
                                if clean_part.startswith((b"Return-Path:", b"Received:", b"From:")):
                                    email_stream = io.BytesIO(clean_part)
                                    
                                    # Create flat file structure (no subfolders)
                                    tar_info = tarfile.TarInfo(name=f"email_{total_count:05d}.eml")
                                    tar_info.size = len(clean_part)
                                    
                                    tar.addfile(tar_info, fileobj=email_stream)
                                    total_count += 1
                                    
                                    if total_count % 500 == 0:
                                        print(f"  Archived {total_count} emails...")
                    except:
                        continue

        # 2. Rename the file once we know the total_count
        final_filename = f"{date_str}_bichon_{total_count}_emails_exported.tar.gz"
        final_path = os.path.join(OUTPUT_DIR, final_filename)
        
        os.rename(temp_output, final_path)
        
        print(f"\nSuccess!")
        print(f"Final Archive: {final_path}")
        print(f"Total Emails:  {total_count}")

    except Exception as e:
        print(f"An error occurred: {e}")
        if os.path.exists(temp_output):
            print("Cleaning up temporary file...")
            os.remove(temp_output)

if __name__ == "__main__":
    main()
