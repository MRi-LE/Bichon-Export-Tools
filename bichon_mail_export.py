#!/usr/bin/env python3
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MRi-LE
# This software is provided "as is", without warranty of any kind.
# Authored by MRi-LE, with assistance from AI tools.

Bichon Email Export Pipeline
Forensic carving of Zstandard-compressed mail store files with
strict top-level message validation, deduplication, account assignment,
and auditable CSV outputs.

FIX INCLUDED:
- Carving now "jumps past header end" after accepting a message start
  to avoid splitting inside a single message header (Date/Message-ID/From).

Goals:
- get close to original Email Count by carving ONLY top-level messages
- avoid DKIM/ARC "Subject:Date;" false positives
- avoid forwarded/quoted embedded headers being counted as messages
- produce full debug artifacts for forensic tuning
- detect multiple mailbox accounts & duplicate messages into per-account folders
- reduce residual UNK via conservative provider-alias normalization

Stages:
1) Discover .store files recursively
2) Split into ZSTD frames + decompress (frame report CSV)
3) Carve messages:
   - Tier1: Return-Path segmentation (primary)
   - Tier2: strict top-level header blocks inside frames/segments
4) Dedupe by Message-ID else by strong hash fingerprint
5) Build clean_emails.csv (deduped canonical messages)
6) Account detection + account assignment CSVs
7) Reconstruct .eml files into reconstructed/<ACCOUNT>/... (+ optional tar.gz)
8) Summary + debug reports

Usage:
  python3 bichon_mail_export.py -p /<path2eml>
"""

import os, re, sys, io, csv, tarfile, hashlib, argparse
from pathlib import Path
from collections import Counter
from email.utils import parseaddr, parsedate_to_datetime, getaddresses
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
RX_CC = re.compile(br"(?im)^cc:\s*(.+)$")
RX_DATE = re.compile(br"(?im)^(date|datum):\s*(.+)$")
RX_SUBJ = re.compile(br"(?im)^subject:\s*(.*)$")
RX_MID  = re.compile(br"(?im)^message-id:\s*(.+)$")

CORE_HEADER_RXS = [RX_FROM, RX_TO, RX_DATE, RX_MID]  # subject optional

def looks_quoted_or_forwarded_context(b: bytes, pos: int) -> bool:
    pre = b[max(0, pos-260):pos].lower()
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

    if start != 0:
        pass

    if looks_quoted_or_forwarded_context(b, start):
        return None, -1

    tail = b[start:start+max_scan]
    m = RX_HDR_END.search(tail)
    if not m:
        return None, -1
    header = tail[:m.start()+2]  # includes "\n\n"

    head_first = header[:4096]
    if RX_BAD_PREFIX.search(head_first):
        return None, -1

    hits = 0
    for rx in CORE_HEADER_RXS:
        if rx.search(header):
            hits += 1
    if hits < 3:
        return None, -1

    fm = RX_FROM.search(header)
    if not fm:
        return None, -1

    return header, start + (m.start()+2)

def parse_header_fields(header: bytes) -> dict:
    s = header.decode("latin-1", errors="replace")
    out = {
        "from": "", "to": "", "cc": "", "rcpt_hints": "",
        "date": "", "subject": "", "message_id": "",
    }

    m = re.search(r"(?im)^from:\s*(.+)$", s)
    if m: out["from"] = m.group(1).strip()

    m = re.search(r"(?im)^(to|delivered-to):\s*(.+)$", s)
    if m: out["to"] = m.group(2).strip()

    m = re.search(r"(?im)^cc:\s*(.+)$", s)
    if m: out["cc"] = m.group(1).strip()

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

# ---------------------- Account helpers ----------------------

def canonicalize_email(addr: str) -> str:
    addr = (addr or "").strip().lower()
    if "@" not in addr:
        return addr
    local, dom = addr.split("@", 1)

    # Canonical mappings already proven useful in this dataset
    if dom == "gmx.net":
        dom = "gmx.de"
    elif dom == "01019freenet.de":
        dom = "freenet.de"

    return f"{local}@{dom}"

def extract_emails_from_header_value(v: str) -> list[str]:
    """
    Parse a header value that may contain multiple addresses.
    Returns canonicalized email addresses only.
    """
    if not v:
        return []
    addrs = []
    for _name, addr in getaddresses([v]):
        addr = canonicalize_email(addr)
        if addr and "@" in addr:
            addrs.append(addr)
    return addrs

def domain_of(addr: str) -> str:
    addr = canonicalize_email(addr)
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[1]

def localpart_of(addr: str) -> str:
    addr = canonicalize_email(addr)
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[0]

def build_account_domain_index(accounts: list[str]) -> dict[str, list[str]]:
    idx = {}
    for acc in accounts:
        a = canonicalize_email(acc)
        d = domain_of(a)
        idx.setdefault(d, []).append(a)
    return idx

def normalize_provider_alias(addr: str, accounts: list[str]) -> str | None:
    """
    Conservative provider-alias normalization.

    Currently supported:
    - GMX masked rcpt aliases like '#123456@gmx.de'
      -> canonical detected GMX account, but only if exactly one exists.
    - disable or alter if requried

    Returns canonical account or None.
    """
    addr = canonicalize_email(addr)
    if "@" not in addr:
        return None

    lp = localpart_of(addr)
    dom = domain_of(addr)

    acc_by_dom = build_account_domain_index(accounts)

    if dom in ("gmx.de", "gmx.net") and lp.startswith("#"):
        gmx_accounts = []
        gmx_accounts.extend(acc_by_dom.get("gmx.de", []))
        gmx_accounts.extend(acc_by_dom.get("gmx.net", []))
        gmx_accounts = sorted(set(gmx_accounts))
        if len(gmx_accounts) == 1:
            return gmx_accounts[0]

    return None

RX_ENV_TO = re.compile(r"(?im)^envelope-to:\s*<?([^>\r\n]+)>?")
RX_X_ORIG_TO = re.compile(r"(?im)^x-original-to:\s*<?([^>\r\n]+)>?")
RX_DELIV_TO = re.compile(r"(?im)^delivered-to:\s*<?([^>\r\n]+)>?")
RX_RECEIVED_FOR = re.compile(r"(?im)^received:.*?\bfor\s+<([^>\r\n]+)>", re.S)

def extract_rcpt_hints(raw_msg: bytes) -> list[str]:
    """
    Extract recipient hints from top-level transport headers only.
    Conservative: only Envelope-To / X-Original-To / Delivered-To / Received ... for <...>
    """
    b = normalize_newlines(raw_msg)
    header, _hdr_end = parse_top_header_block(b, 0)
    if header is None:
        # fallback: inspect first header-looking block from raw start
        m = RX_HDR_END.search(b[:128*1024])
        if not m:
            return []
        header = b[:m.start()+2]

    s = header.decode("latin-1", errors="replace")
    hits = []

    for rx in (RX_ENV_TO, RX_X_ORIG_TO, RX_DELIV_TO):
        for m in rx.finditer(s):
            addr = canonicalize_email(m.group(1))
            if addr and "@" in addr:
                hits.append(addr)

    for m in RX_RECEIVED_FOR.finditer(s):
        addr = canonicalize_email(m.group(1))
        if addr and "@" in addr:
            hits.append(addr)

    out = []
    seen = set()
    for a in hits:
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out

def detect_accounts_from_carved_rows(rows: list[dict], min_weight: float) -> list[str]:
    """
    Detect legit mailbox accounts based on recipient-facing header signals.
    Uses To + Cc + rcpt_hints.
    """
    tally = Counter()
    for r in rows:
        for hdr in (r.get("to",""), r.get("cc",""), r.get("rcpt_hints","")):
            for addr in extract_emails_from_header_value(hdr):
                tally.update([addr])

    total = sum(tally.values())
    if total <= 0:
        return []

    accounts = []
    for addr, c in tally.most_common():
        if c / total >= min_weight:
            accounts.append(addr)

    return accounts

def assign_accounts_for_message(r: dict, accounts: list[str]) -> list[str]:
    """
    Match a message to one or more accounts:
    - direct match if any known account appears in To/Cc
    - direct match from rcpt_hints
    - conservative provider-alias normalization from rcpt_hints
    - fallback: From matches known account
    - else: UNK
    """
    acc_set = set(canonicalize_email(a) for a in accounts)
    matched = set()

    for hdr in (r.get("to",""), r.get("cc","")):
        for addr in extract_emails_from_header_value(hdr):
            if addr in acc_set:
                matched.add(addr)

    if not matched:
        for addr in extract_emails_from_header_value(r.get("rcpt_hints","")):
            if addr in acc_set:
                matched.add(addr)

    if not matched:
        for addr in extract_emails_from_header_value(r.get("rcpt_hints","")):
            canon = normalize_provider_alias(addr, accounts)
            if canon and canon in acc_set:
                matched.add(canon)

    if not matched:
        _n, frm = parseaddr(r.get("from","") or "")
        frm = canonicalize_email(frm)
        if frm and frm in acc_set:
            matched.add(frm)

    if not matched:
        return ["UNK"]
    return sorted(matched)

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
        pos = max(hdr_end, s + 1)

    if not starts:
        return []

    starts = sorted(set(starts))

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
    ap.add_argument("--account-min-weight", type=float, default=0.10, help="Min weight (0..1) to treat an address as a legit account")
    args = ap.parse_args()

    root = Path(args.path)
    outdir = Path(args.out) if args.out else (root.parent / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_bichon_mail_export")
    outdir.mkdir(parents=True, exist_ok=True)

    seg_dir = outdir / "segments"
    eml_root = outdir / "reconstructed"
    dbg_dir = outdir / "debug"
    for d in (seg_dir, eml_root, dbg_dir):
        d.mkdir(parents=True, exist_ok=True)

    frame_csv = outdir / "frames_report.csv"
    carve_csv = outdir / "carve_report.csv"
    clean_csv = outdir / "clean_emails.csv"
    accounts_csv = outdir / "clean_emails_accounts.csv"
    accounts_summary_csv = outdir / "accounts_summary.csv"
    summary_txt = outdir / "summary.txt"
    dump_path = outdir / "dump.out"

    store_files = discover_store_files(root)
    dctx = zstd.ZstdDecompressor(max_window_size=2**31)

    # ---------------- Stage 1: frames report ----------------
    all_frames = []
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
    carved_msgs = []
    fp_seen = set()
    mid_seen = set()

    with carve_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "store_file","frame_index","tier","start_offset",
            "bytes","has_return_path","accepted",
            "reason","message_id","date_ymd","from","to","cc","rcpt_hints","subject"
        ])

        for fr in all_frames:
            dec = fr["dec"]
            b = normalize_newlines(dec)

            tier1 = tier1_return_path_split(b)
            if tier1:
                for seg in tier1:
                    msgs = carve_messages_from_blob(seg)
                    if not msgs:
                        w.writerow([fr["store"].name, fr["frame_index"], "tier2_in_tier1", -1, len(seg), int(fr["has_rp"]), 0,
                                    "no_strict_headers", "", "", "", "", "", "", ""])
                        continue

                    seg_norm = normalize_newlines(seg)
                    for start, msg in msgs:
                        header, hdr_end = parse_top_header_block(seg_norm, start)
                        if header is None:
                            w.writerow([fr["store"].name, fr["frame_index"], "tier2_in_tier1", start, len(msg), int(fr["has_rp"]), 0,
                                        "validator_reject", "", "", "", "", "", "", ""])
                            continue

                        fields = parse_header_fields(header)
                        rcpt_hints = ",".join(extract_rcpt_hints(msg))
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
                                "cc": fields.get("cc",""),
                                "rcpt_hints": rcpt_hints,
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
                            fields["message_id"], ymd, fields["from"], fields["to"], fields.get("cc",""), rcpt_hints, fields["subject"]
                        ])
            else:
                msgs = carve_messages_from_blob(b)
                for start, msg in msgs:
                    header, hdr_end = parse_top_header_block(b, start)
                    if header is None:
                        w.writerow([fr["store"].name, fr["frame_index"], "tier2_no_rp", start, len(msg), 0, 0,
                                    "validator_reject", "", "", "", "", "", "", ""])
                        continue

                    fields = parse_header_fields(header)
                    rcpt_hints = ",".join(extract_rcpt_hints(msg))
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
                            "cc": fields.get("cc",""),
                            "rcpt_hints": rcpt_hints,
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
                        fields["message_id"], ymd, fields["from"], fields["to"], fields.get("cc",""), rcpt_hints, fields["subject"]
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

    # ---------------- Stage 4: clean_emails.csv (canonical) ----------------
    with clean_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "segment_file","from","to","cc","rcpt_hints","date","subject","message_id","mode",
            "classification","size","store_file","frame_index","tier"
        ])
        w.writeheader()
        for r in carved_msgs:
            w.writerow({
                "segment_file": r["segment_file"],
                "from": r["from"],
                "to": r["to"],
                "cc": r.get("cc",""),
                "rcpt_hints": r.get("rcpt_hints",""),
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

    # ---------------- Stage 4b: detect accounts ----------------
    accounts = detect_accounts_from_carved_rows(carved_msgs, args.account_min_weight)

    # ---------------- Stage 4c: account assignment CSV ----------------
    acc_counts = Counter()
    with accounts_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "segment_file","account","from","to","cc","rcpt_hints","date","subject","message_id",
            "size","store_file","frame_index","tier"
        ])
        w.writeheader()

        for r in carved_msgs:
            for acc in assign_accounts_for_message(r, accounts):
                acc_counts.update([acc])
                w.writerow({
                    "segment_file": r["segment_file"],
                    "account": acc,
                    "from": r["from"],
                    "to": r["to"],
                    "cc": r.get("cc",""),
                    "rcpt_hints": r.get("rcpt_hints",""),
                    "date": r["date"],
                    "subject": r["subject"],
                    "message_id": r["message_id"],
                    "size": r["size"],
                    "store_file": r["store_file"],
                    "frame_index": r["frame_index"],
                    "tier": r["tier"],
                })

    with accounts_summary_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["account","emails","weight_percent"])
        total_assigned = sum(acc_counts.values()) or 1
        for acc, c in acc_counts.most_common():
            w.writerow([acc, c, round((c/total_assigned)*100.0, 2)])

    # ---------------- Stage 5: reconstruct eml per account ----------------
    no_subject = 0
    total_written = 0

    msg_accounts = []
    for r in carved_msgs:
        msg_accounts.append(assign_accounts_for_message(r, accounts))

    for idx, r in enumerate(carved_msgs, start=1):
        seg = (seg_dir / r["segment_file"]).read_bytes()

        subj = (r["subject"] or "").strip() or "NO_SUBJECT"
        if subj == "NO_SUBJECT":
            no_subject += 1

        frm_email = parseaddr(r["from"])[1] or parseaddr(r["from"])[0] or "UNK"
        frm = sanitize_name(frm_email, 30)
        dt = r["date"] or "0000-00-00"
        base = f"{idx:06d}_{dt}_{frm}_{sanitize_name(subj,60)}"

        accs = msg_accounts[idx-1]
        if not accs:
            accs = ["UNK"]

        for a_i, acc in enumerate(accs, start=1):
            acc_dir_name = sanitize_name(acc, 80) if acc != "UNK" else "UNK"
            acc_dir = eml_root / acc_dir_name
            acc_dir.mkdir(parents=True, exist_ok=True)

            suffix = f"_A{a_i:02d}" if len(accs) > 1 else ""
            fn = f"{base}{suffix}.eml"
            (acc_dir / fn).write_bytes(seg)
            total_written += 1

    # ---------------- Stage 6: tar.gz ----------------
    earliest = min([r["date"] for r in carved_msgs if r["date"] != "0000-00-00"], default="0000-00-00")
    tar_path = outdir / f"{outdir.name}_bichon_mail_export.tar.gz"
    if not args.no_tar:
        with tarfile.open(tar_path, "w:gz") as tar:
            for p in sorted(eml_root.rglob("*.eml")):
                arcname = str(p.relative_to(outdir))
                ti = tarfile.TarInfo(name=arcname)
                data = p.read_bytes()
                ti.size = len(data)
                tar.addfile(ti, fileobj=io.BytesIO(data))

    # ---------------- Summary ----------------
    total = len(carved_msgs)
    missing_subj = sum(1 for r in carved_msgs if not (r["subject"] or "").strip())

    with summary_txt.open("w", encoding="utf-8") as f:
        f.write("Bichon Email Export Pipeline Summary (jump past header end + multi-account + rcpt_hints + GMX alias normalization)\n")
        f.write(f"Output dir: {outdir}\n")
        f.write(f"Store files: {len(store_files)}\n")
        f.write(f"Frames: {len(all_frames)}\n")
        f.write(f"Carved messages (deduped): {total}\n")
        f.write(f"Missing Subject (real): {missing_subj}\n")
        f.write(f"NO_SUBJECT (real): {no_subject}\n")
        f.write(f"Accounts detected (min_weight={args.account_min_weight}): {accounts}\n")
        f.write(f"EMLs written (with duplication): {total_written}\n")
        f.write(f"Dump: {dump_path}\n")
        f.write(f"CSV (canonical): {clean_csv}\n")
        f.write(f"CSV (accounts): {accounts_csv}\n")
        f.write(f"Accounts summary: {accounts_summary_csv}\n")
        f.write(f"Frames report: {frame_csv}\n")
        f.write(f"Carve report: {carve_csv}\n")
        if not args.no_tar:
            f.write(f"TAR: {tar_path}\n")

    print("✅ Done")
    print(f"Output dir: {outdir}")
    print(f"Carved (deduped): {total}")
    print(f"Missing real Subject: {missing_subj}")
    print(f"NO_SUBJECT (real): {no_subject}")
    print(f"Accounts detected (min_weight={args.account_min_weight}): {accounts}")
    print(f"EMLs written (with duplication): {total_written}")
    print(f"Reconstructed root: {eml_root}")
    print(f"CSV (canonical): {clean_csv}")
    print(f"CSV (accounts): {accounts_csv}")
    print(f"Accounts summary: {accounts_summary_csv}")
    print(f"Frames report: {frame_csv}")
    print(f"Carve report: {carve_csv}")
    print(f"Dump: {dump_path}")
    if not args.no_tar:
        print(f"TAR: {tar_path}")

if __name__ == "__main__":
    main()
