#!/usr/bin/env python3
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MRi-LE
# This software is provided "as is", without warranty of any kind.
# Authored by Michael Richter, with assistance from AI tools.

FIX INCLUDED:
- Carving now "jumps past header end" after accepting a message start
  to avoid splitting inside a single message header (Date/Message-ID/From).

Goals:
- get close to original ~7800 by carving ONLY top-level messages
- avoid DKIM/ARC "Subject:Date;" false positives
- avoid forwarded/quoted embedded headers being counted as messages
- produce full debug artifacts for forensic tuning

Stages:
1) Discover .store files recursively
2) Split into ZSTD frames + decompress (frame report CSV)
3) Carve messages:
   - Tier1: Return-Path segmentation (primary)
   - Tier2: strict top-level header blocks inside frames/segments
4) Dedupe by Message-ID else by strong hash fingerprint
5) Build clean_emails.csv
6) Reconstruct .eml files + tar.gz
7) Summary + debug reports

Usage:
  python3 bichon_mail_export.py -p /../../bichon/eml --max-bytes $((200*1024*1024))
"""

import os, re, sys, io, csv, tarfile, hashlib, argparse
from pathlib import Path
from collections import Counter
from email.utils import parseaddr, parsedate_to_datetime
from email.header import decode_header
from datetime import datetime
import zstandard as zstd

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# ---------------------- Header helpers ----------------------

def decode_mime_header(s: str) -> str:
    if not s:
        return ""
    s = re.sub(r"[\r\n\t]+", " ", s).strip()
    try:
        parts = decode_header(s)
        out = []
        for content, charset in parts:
            if isinstance(content, bytes):
                out.append(content.decode(charset or "utf-8", errors="ignore"))
            else:
                out.append(str(content))
        return "".join(out).strip()
    except Exception:
        return s

def sanitize_name(text: str, length: int = 60) -> str:
    if not text:
        return "UNK"
    clean = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_")
    clean = re.sub(r"_+", "_", clean)
    return (clean[:length] or "UNK").upper()

def normalize_newlines(b: bytes) -> bytes:
    return b.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\x00", b"\n")

RX_HDR_END = re.compile(br"\n\n")
RX_BAD_PREFIX = re.compile(
    br"(?im)^(dkim-signature|arc-message-signature|authentication-results|arc-authentication-results):"
)
RX_START = re.compile(br"(?im)^(return-path|from|message-id|date):\s+")
RX_FROM = re.compile(br"(?im)^from:\s*(.+)$")
RX_TO = re.compile(br"(?im)^(to|delivered-to):\s*(.+)$")
RX_DATE = re.compile(br"(?im)^(date|datum):\s*(.+)$")
RX_SUBJ = re.compile(br"(?im)^subject:\s*(.*)$")
RX_MID  = re.compile(br"(?im)^message-id:\s*(.+)$")

CORE_HEADER_RXS = [RX_FROM, RX_TO, RX_DATE, RX_MID]  # subject optional

def looks_quoted_or_forwarded_context(b: bytes, pos: int) -> bool:
    pre = b[max(0, pos-260):pos].lower()
    # Common quote markers / forward separators
    if b"\n>" in pre or pre.endswith(b">") or b"\n|" in pre:
        return True
    if b"original message" in pre or b"forwarded message" in pre or b"weitergeleitete nachricht" in pre:
        return True
    return False

def parse_top_header_block(b: bytes, start: int, max_scan: int = 128*1024):
    """
    Return (header_bytes, header_end_index_in_original) if a top-level header block is found.
    Enforces strict constraints to avoid embedded headers.
    """
    if start < 0 or start >= len(b):
        return None, -1

    # Top-level boundary heuristic (keep as in your gold; can tighten later)
    if start != 0:
        # prefer blank-line boundary but don't hard-fail here (we can tighten later if needed)
        pass

    # reject quoted/forwarded contexts
    if looks_quoted_or_forwarded_context(b, start):
        return None, -1

    tail = b[start:start+max_scan]
    m = RX_HDR_END.search(tail)
    if not m:
        return None, -1
    header = tail[:m.start()+2]  # includes "\n\n"

    # header must not start as DKIM/ARC blocks
    head_first = header[:4096]
    if RX_BAD_PREFIX.search(head_first):
        return None, -1

    # Require at least 3 of the core headers (From/To(or Delivered-To)/Date/Message-ID)
    hits = 0
    for rx in CORE_HEADER_RXS:
        if rx.search(header):
            hits += 1
    if hits < 3:
        return None, -1

    # must contain a plausible From:
    fm = RX_FROM.search(header)
    if not fm:
        return None, -1

    return header, start + (m.start()+2)

def parse_header_fields(header: bytes) -> dict:
    s = header.decode("latin-1", errors="replace")
    out = {"from": "", "to": "", "date": "", "subject": "", "message_id": ""}

    m = re.search(r"(?im)^from:\s*(.+)$", s)
    if m: out["from"] = m.group(1).strip()

    m = re.search(r"(?im)^(to|delivered-to):\s*(.+)$", s)
    if m: out["to"] = m.group(2).strip()

    m = re.search(r"(?im)^(date|datum):\s*(.+)$", s)
    if m: out["date"] = m.group(2).strip()

    m = re.search(r"(?im)^subject:\s*(.*)$", s)
    if m: out["subject"] = decode_mime_header(m.group(1).strip())

    m = re.search(r"(?im)^message-id:\s*(.+)$", s)
    if m:
        mid = m.group(1).strip().splitlines()[0].strip()
        out["message_id"] = mid

    return out

def date_to_ymd(date_raw: str) -> str:
    if not date_raw:
        return "0000-00-00"
    try:
        dt = parsedate_to_datetime(date_raw.strip())
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return "0000-00-00"

def strong_fingerprint(header: bytes, body_prefix: bytes) -> str:
    h = hashlib.sha256()
    h.update(header)
    h.update(b"\n--BODY--\n")
    h.update(body_prefix[:4096])
    return h.hexdigest()

# ---------------------- Store/frame reading ----------------------

def discover_store_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.store"))

def split_frames(store_path: Path) -> list[bytes]:
    data = store_path.read_bytes()
    return data.split(ZSTD_MAGIC)[1:]

def decompress_frame(dctx: zstd.ZstdDecompressor, frame: bytes, max_bytes: int):
    try:
        return dctx.decompress(ZSTD_MAGIC + frame, max_output_size=max_bytes)
    except Exception:
        return None

# ---------------------- Carving ----------------------

def carve_messages_from_blob(blob: bytes) -> list[tuple[int, bytes]]:
    """
    Strict top-level message carving that avoids splitting inside one message's header.

    FIX: after accepting a header block, jump to hdr_end before searching again.
    """
    b = normalize_newlines(blob)
    carved: list[tuple[int, bytes]] = []
    starts: list[int] = []

    pos = 0
    while True:
        m = RX_START.search(b, pos)
        if not m:
            break
        s = m.start()

        header, hdr_end = parse_top_header_block(b, s)
        if header is None:
            pos = s + 1
            continue

        starts.append(s)

        # CRITICAL FIX: jump past the end of the header block
        pos = max(hdr_end, s + 1)

    if not starts:
        return []

    # Deduplicate + sort
    starts = sorted(set(starts))

    # Build message slices
    for i, s in enumerate(starts):
        e = starts[i+1] if i+1 < len(starts) else len(b)
        msg = b[s:e].strip(b"\n")
        if msg:
            carved.append((s, msg))

    return carved

def tier1_return_path_split(blob: bytes) -> list[bytes]:
    b = normalize_newlines(blob)
    if b"Return-Path:" not in b:
        return []
    parts = re.split(br"(?m)(?=^Return-Path:\s*)", b)
    out = []
    for p in parts:
        if p.strip() and p.lstrip().startswith(b"Return-Path:"):
            out.append(p.strip(b"\n"))
    return out

# ---------------------- Main pipeline ----------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--path", required=True, help="Root directory containing .store files")
    ap.add_argument("-o", "--out", default=None, help="Output directory (default: <path>/<timestamp>_bichon_mail_export)")
    ap.add_argument("--max-bytes", type=int, default=200*1024*1024, help="Max decompressed bytes per frame")
    ap.add_argument("--write-frames", action="store_true", help="Write decompressed frames for debugging (large!)")
    ap.add_argument("--no-tar", action="store_true", help="Skip tar.gz creation")
    args = ap.parse_args()

    root = Path(args.path)
    outdir = Path(args.out) if args.out else (root.parent / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_bichon_mail_export")
    outdir.mkdir(parents=True, exist_ok=True)

    seg_dir = outdir / "segments"
    eml_dir = outdir / "reconstructed"
    dbg_dir = outdir / "debug"
    for d in (seg_dir, eml_dir, dbg_dir):
        d.mkdir(parents=True, exist_ok=True)

    frame_csv = outdir / "frames_report.csv"
    carve_csv = outdir / "carve_report.csv"
    clean_csv = outdir / "clean_emails.csv"
    summary_txt = outdir / "summary.txt"
    dump_path = outdir / "dump.out"

    store_files = discover_store_files(root)
    dctx = zstd.ZstdDecompressor(max_window_size=2**31)

    # ---------------- Stage 1: frames report ----------------
    all_frames = []  # list of dicts
    with frame_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["store_file","frame_index","frame_bytes","decompressed_bytes","decompress_ok","has_return_path"])

        for sf in store_files:
            frames = split_frames(sf)
            for idx, fr in enumerate(frames):
                dec = decompress_frame(dctx, fr, args.max_bytes)
                ok = dec is not None
                has_rp = (b"Return-Path:" in dec) if ok else False
                w.writerow([sf.name, idx, len(fr), len(dec) if ok else 0, int(ok), int(has_rp)])
                if ok:
                    all_frames.append({
                        "store": sf,
                        "frame_index": idx,
                        "dec": dec,
                        "has_rp": has_rp,
                    })
                    if args.write_frames:
                        (dbg_dir / f"frame_{sf.stem}_{idx:04d}.bin").write_bytes(dec)

    # ---------------- Stage 2: carve ----------------
    carved_msgs = []  # dict records
    fp_seen = set()
    mid_seen = set()

    with carve_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "store_file","frame_index","tier","start_offset",
            "bytes","has_return_path","accepted",
            "reason","message_id","date_ymd","from","to","subject"
        ])

        for fr in all_frames:
            dec = fr["dec"]
            b = normalize_newlines(dec)

            # Tier1: RP split (if present)
            tier1 = tier1_return_path_split(b)
            if tier1:
                for seg in tier1:
                    msgs = carve_messages_from_blob(seg)
                    if not msgs:
                        w.writerow([fr["store"].name, fr["frame_index"], "tier2_in_tier1", -1, len(seg), int(fr["has_rp"]), 0,
                                    "no_strict_headers", "", "", "", "", ""])
                        continue

                    seg_norm = normalize_newlines(seg)
                    for start, msg in msgs:
                        header, hdr_end = parse_top_header_block(seg_norm, start)
                        if header is None:
                            w.writerow([fr["store"].name, fr["frame_index"], "tier2_in_tier1", start, len(msg), int(fr["has_rp"]), 0,
                                        "validator_reject", "", "", "", "", ""])
                            continue

                        fields = parse_header_fields(header)
                        mid = (fields["message_id"] or "").strip().lower()
                        ymd = date_to_ymd(fields["date"])
                        fp = mid if mid else strong_fingerprint(header, msg[hdr_end-start:])

                        accepted = 0
                        reason = ""
                        if mid and mid in mid_seen:
                            reason = "dup_message_id"
                        elif (not mid) and fp in fp_seen:
                            reason = "dup_fingerprint"
                        else:
                            accepted = 1
                            if mid:
                                mid_seen.add(mid)
                            fp_seen.add(fp)

                            seg_name = f"{hashlib.md5(msg[:4096]).hexdigest()}_f{fr['frame_index']:05d}_s{len(carved_msgs):05d}.seg"
                            (seg_dir / seg_name).write_bytes(msg)

                            carved_msgs.append({
                                "segment_file": seg_name,
                                "from": fields["from"],
                                "to": fields["to"],
                                "date": ymd,
                                "subject": fields["subject"],
                                "message_id": fields["message_id"],
                                "size": len(msg),
                                "store_file": fr["store"].name,
                                "frame_index": fr["frame_index"],
                                "tier": "tier2_in_tier1",
                            })

                        w.writerow([
                            fr["store"].name, fr["frame_index"], "tier2_in_tier1", start, len(msg),
                            int(fr["has_rp"]), accepted, reason,
                            fields["message_id"], ymd, fields["from"], fields["to"], fields["subject"]
                        ])
            else:
                # No RP: carve directly from frame with strict headers
                msgs = carve_messages_from_blob(b)
                for start, msg in msgs:
                    header, hdr_end = parse_top_header_block(b, start)
                    if header is None:
                        w.writerow([fr["store"].name, fr["frame_index"], "tier2_no_rp", start, len(msg), 0, 0,
                                    "validator_reject", "", "", "", "", ""])
                        continue

                    fields = parse_header_fields(header)
                    mid = (fields["message_id"] or "").strip().lower()
                    ymd = date_to_ymd(fields["date"])
                    fp = mid if mid else strong_fingerprint(header, msg[hdr_end-start:])

                    accepted = 0
                    reason = ""
                    if mid and mid in mid_seen:
                        reason = "dup_message_id"
                    elif (not mid) and fp in fp_seen:
                        reason = "dup_fingerprint"
                    else:
                        accepted = 1
                        if mid:
                            mid_seen.add(mid)
                        fp_seen.add(fp)

                        seg_name = f"{hashlib.md5(msg[:4096]).hexdigest()}_f{fr['frame_index']:05d}_s{len(carved_msgs):05d}.seg"
                        (seg_dir / seg_name).write_bytes(msg)

                        carved_msgs.append({
                            "segment_file": seg_name,
                            "from": fields["from"],
                            "to": fields["to"],
                            "date": ymd,
                            "subject": fields["subject"],
                            "message_id": fields["message_id"],
                            "size": len(msg),
                            "store_file": fr["store"].name,
                            "frame_index": fr["frame_index"],
                            "tier": "tier2_no_rp",
                        })

                    w.writerow([
                        fr["store"].name, fr["frame_index"], "tier2_no_rp", start, len(msg),
                        0, accepted, reason,
                        fields["message_id"], ymd, fields["from"], fields["to"], fields["subject"]
                    ])

    # ---------------- Stage 3: dump.out ----------------
    with dump_path.open("wb") as df:
        for i, r in enumerate(carved_msgs):
            seg = (seg_dir / r["segment_file"]).read_bytes()
            df.write(f"\n===== EMAIL {i:05d} =====\n".encode("utf-8"))
            df.write(f"SEGMENT: {r['segment_file']}\n".encode("utf-8"))
            df.write(f"SIZE: {len(seg)}\n".encode("utf-8"))
            df.write(f"STORE: {r['store_file']} FRAME: {r['frame_index']} TIER: {r['tier']}\n".encode("utf-8"))
            df.write(b"--------------------------\n")
            df.write(seg)
            df.write(b"\n")

    # ---------------- Stage 4: clean_emails.csv ----------------
    with clean_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "segment_file","from","to","date","subject","message_id","mode",
            "classification","size","store_file","frame_index","tier"
        ])
        w.writeheader()
        for r in carved_msgs:
            w.writerow({
                "segment_file": r["segment_file"],
                "from": r["from"],
                "to": r["to"],
                "date": r["date"],
                "subject": r["subject"],
                "message_id": r["message_id"],
                "mode": "carve",
                "classification": "carved",
                "size": r["size"],
                "store_file": r["store_file"],
                "frame_index": r["frame_index"],
                "tier": r["tier"],
            })

    # ---------------- Stage 5: reconstruct eml ----------------
    no_subject = 0
    for idx, r in enumerate(carved_msgs, start=1):
        seg = (seg_dir / r["segment_file"]).read_bytes()

        subj = (r["subject"] or "").strip() or "NO_SUBJECT"
        if subj == "NO_SUBJECT":
            no_subject += 1

        frm = sanitize_name(parseaddr(r["from"])[1] or parseaddr(r["from"])[0] or "UNK", 30)
        dt = r["date"] or "0000-00-00"
        fn = f"{idx:06d}_{dt}_{frm}_{sanitize_name(subj,60)}.eml"
        (eml_dir / fn).write_bytes(seg)

    # ---------------- Stage 6: tar.gz ----------------
    tar_path = outdir / f"{min([r['date'] for r in carved_msgs if r['date']!='0000-00-00'], default='0000-00-00')}_bichon_mail_export.tar.gz"
    if not args.no_tar:
        with tarfile.open(tar_path, "w:gz") as tar:
            for p in sorted(eml_dir.glob("*.eml")):
                ti = tarfile.TarInfo(name=p.name)
                data = p.read_bytes()
                ti.size = len(data)
                tar.addfile(ti, fileobj=io.BytesIO(data))

    # ---------------- Summary ----------------
    total = len(carved_msgs)
    missing_subj = sum(1 for r in carved_msgs if not (r["subject"] or "").strip())
    with summary_txt.open("w", encoding="utf-8") as f:
        f.write("Bichon Gold Pipeline Summary (jump past header end)\n")
        f.write(f"Output dir: {outdir}\n")
        f.write(f"Store files: {len(store_files)}\n")
        f.write(f"Frames: {len(all_frames)}\n")
        f.write(f"Carved messages (deduped): {total}\n")
        f.write(f"Missing Subject (real): {missing_subj}\n")
        f.write(f"NO_SUBJECT EMLs: {no_subject}\n")
        f.write(f"Dump: {dump_path}\n")
        f.write(f"CSV: {clean_csv}\n")
        f.write(f"Frames report: {frame_csv}\n")
        f.write(f"Carve report: {carve_csv}\n")
        if not args.no_tar:
            f.write(f"TAR: {tar_path}\n")

    print("✅ Done")
    print(f"Output dir: {outdir}")
    print(f"Carved (deduped): {total}")
    print(f"Missing real Subject: {missing_subj}")
    print(f"NO_SUBJECT EMLs: {no_subject}")
    print(f"CSV: {clean_csv}")
    print(f"Frames report: {frame_csv}")
    print(f"Carve report: {carve_csv}")
    print(f"Dump: {dump_path}")
    if not args.no_tar:
        print(f"TAR: {tar_path}")

if __name__ == "__main__":
    main()
