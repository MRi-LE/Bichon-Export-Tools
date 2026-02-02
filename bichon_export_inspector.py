#!/usr/bin/env python3

"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MRi-LE
# This software is provided "as is", without warranty of any kind.
# Authored by Michael Richter, with assistance from AI tools.


Bichon Inspect Export Tool: Inspect or Search .eml files inside a .tar.gz archive.

positional arguments:
  archive               Path to the .tar.gz or .tar file to process

options:
  -h, --help            show this help message and exit

Inspection Options:
  -l LIMIT, --limit LIMIT
                        Limit the number of files displayed during inspection (default: 10)

Search Options:
  -s KEYWORD, --search KEYWORD
                        Search for a specific word/phrase inside the archive
  -b, --body            Extend search to the email body (default: headers only)
"""

import tarfile
import re
import argparse
import os
from email.header import decode_header

def decode_mime(text):
    try:
        decoded_parts = decode_header(text)
        result = ""
        for decoded_string, charset in decoded_parts:
            if isinstance(decoded_string, bytes):
                result += decoded_string.decode(charset or 'utf-8', errors='ignore')
            else:
                result += decoded_string
        return result
    except:
        return text

def process_archive(args):
    if not os.path.exists(args.archive):
        print(f"Error: File '{args.archive}' not found.")
        return

    # Prepare search keyword (Case Insensitive)
    search_keyword = args.search.lower() if args.search else None
    
    print(f"Opening: {os.path.basename(args.archive)}")
    if search_keyword:
        mode = "BODY" if args.body else "HEADERS"
        print(f"Action: Searching for '{args.search}' (Case Insensitive) in {mode}")
        print(f"Limit:  Stopping after {args.limit} matches.")
    else:
        print(f"Action: Inspecting top {args.limit} files")
    
    print(f"{'Filename':<18} | {'Size (KB)':<10} | {'Subject (Decoded)'}")
    print("-" * 80)

    try:
        with tarfile.open(args.archive, "r:*") as tar:
            found_count = 0
            for member in tar:
                if member.isfile() and member.name.endswith(".eml"):
                    f = tar.extractfile(member)
                    if f:
                        # Determine how much to read
                        read_size = 1024 * 64 if (search_keyword and args.body) else 8192
                        raw_content = f.read(read_size)
                        
                        # Convert content to lower case for case-insensitive matching
                        content_text = raw_content.decode('utf-8', errors='ignore')
                        content_lower = content_text.lower()
                        
                        # Filter logic
                        should_display = False
                        if search_keyword:
                            if search_keyword in content_lower:
                                should_display = True
                        else:
                            should_display = True

                        if should_display:
                            # Extract Subject only if we are actually displaying the file
                            subject = "No Subject Found"
                            s_match = re.search(r'(?i)^Subject:\s*(.*)', content_text, re.MULTILINE)
                            if s_match:
                                subject = decode_mime(s_match.group(1).strip())
                            
                            size_kb = member.size / 1024
                            print(f"{member.name:<18} | {size_kb:<10.2f} | {subject}")
                            found_count += 1
                        
                        # Apply the limit to BOTH inspection and search
                        if found_count >= args.limit:
                            break

            print("-" * 80)
            status = f"Found {found_count} matches." if search_keyword else f"Showed {found_count} files."
            print(f"Done. {status}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="EML Archive Tool: Inspect or Search .eml files inside a .tar.gz archive.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("archive", help="Path to the .tar.gz or .tar file to process")

    # Global Options
    parser.add_argument("-l", "--limit", type=int, default=10, 
                        help="Limit displayed files or search results (default: 10)")

    # Search Options
    src_group = parser.add_argument_group('Search Options')
    src_group.add_argument("-s", "--search", metavar="KEYWORD", 
                           help="Search for a word/phrase (Case Insensitive)")
    src_group.add_argument("-b", "--body", action="store_true", 
                           help="Extend search to the email body (default: headers only)")

    args = parser.parse_args()
    process_archive(args)
