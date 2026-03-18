#!/usr/bin/env python3
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MRi-LE
# This software is provided "as is", without warranty of any kind.
# Authored by MRi-LE, with assistance from AI tools.

Bichon Inspector Tool

Purpose
-------
Inspect, summarize, search, and validate reconstructed .eml exports produced by
the Bichon email export pipeline.

Supported inputs
----------------
- export root directory (contains clean_emails_accounts.csv + reconstructed/)
- reconstructed/ directory directly

Core functions
--------------
1) summary
   Show overall counts, per-account distribution, duplicate Message-ID groups,
   and counts of problematic messages.

2) list
   List messages, optionally filtered by account, header search, body search,
   or problem-only mode.

3) validate
   Compare clean_emails_accounts.csv against reconstructed .eml files and report:
   - missing files
   - orphan files
   - account mismatches
   - date mismatches
   - duplicate Message-ID groups
"""

import argparse
import csv
import email
import re
import sys
from collections import Counter, defaultdict
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from pathlib import Path


# ---------------------------
# Helpers
# ---------------------------

def decode_mime(text: str) -> str:
    if not text:
        return ""
    try:
        parts = decode_header(text)
        out = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded = None
                for enc in (charset, "utf-8", "iso-8859-1", "latin-1"):
                    if not enc:
                        continue
                    try:
                        decoded = part.decode(enc)
                        break
                    except Exception:
                        pass
                if decoded is None:
                    decoded = part.decode("utf-8", errors="replace")
                out.append(decoded)
            else:
                out.append(str(part))
        return "".join(out).replace("\r", " ").replace("\n", " ").strip()
    except Exception:
        return str(text).replace("\r", " ").replace("\n", " ").strip()


def sanitize_name(text: str, length: int = 80) -> str:
    if not text:
        return "UNK"
    clean = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_")
    clean = re.sub(r"_+", "_", clean)
    return (clean[:length] or "UNK").upper()


def trunc(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: max(0, n - 3)] + "..."


def parse_ymd(date_raw: str) -> str:
    if not date_raw:
        return "0000-00-00"
    try:
        raw_dt = re.sub(r"\s*\([^)]*\)", "", date_raw).strip()
        dt = parsedate_to_datetime(raw_dt)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", date_raw)
        return m.group(1) if m else "0000-00-00"


def first_email(value: str) -> str:
    if not value:
        return ""
    _n, addr = parseaddr(value)
    return (addr or "").strip().lower()


def parse_filename_bits(path: Path):
    """
    Expected exporter filename:
      000001_2021-07-23_SENDER_SUBJECT.eml
      or ..._A01.eml for multi-account duplication

    Returns:
      idx, date, sender_slug, subject_slug
    """
    name = path.name
    m = re.match(r"^(\d{6})_(\d{4}-\d{2}-\d{2})_(.+)\.eml$", name)
    if not m:
        return "", "0000-00-00", "", ""
    idx = m.group(1)
    date = m.group(2)
    rest = m.group(3)

    if rest.endswith("_A01") or re.search(r"_A\d{2}$", rest):
        rest = re.sub(r"_A\d{2}$", "", rest)

    parts = rest.split("_", 1)
    sender_slug = parts[0] if parts else ""
    subject_slug = parts[1] if len(parts) > 1 else ""
    return idx, date, sender_slug, subject_slug


def read_eml_headers(path: Path):
    """
    Reads headers only.
    """
    try:
        with path.open("rb") as f:
            msg = email.message_from_binary_file(f)
    except Exception:
        return {
            "subject": "",
            "date": "0000-00-00",
            "from": "",
            "to": "",
            "message_id": "",
            "parse_error": True,
        }

    subject = decode_mime(msg.get("Subject", "") or "")
    date = parse_ymd(msg.get("Date", "") or "")
    frm = decode_mime(msg.get("From", "") or "")
    to = decode_mime(msg.get("To", "") or msg.get("Delivered-To", "") or "")
    mid = (msg.get("Message-ID", "") or "").strip()

    return {
        "subject": subject,
        "date": date,
        "from": frm,
        "to": to,
        "message_id": mid,
        "parse_error": False,
    }


def read_eml_text_prefix(path: Path, limit: int = 256 * 1024) -> str:
    try:
        raw = path.read_bytes()[:limit]
        try:
            return raw.decode("utf-8")
        except Exception:
            return raw.decode("latin-1", errors="replace")
    except Exception:
        return ""


def build_problem_flags(meta: dict, account_folder: str) -> list[str]:
    flags = []
    if not meta.get("subject", "").strip():
        flags.append("missing_subject")
    if (meta.get("date") or "0000-00-00") == "0000-00-00":
        flags.append("missing_date")
    if not (meta.get("message_id") or "").strip():
        flags.append("missing_message_id")
    if meta.get("parse_error"):
        flags.append("parse_error")
    if account_folder == "UNK":
        flags.append("account_unk")
    return flags


def collect_reconstructed(root: Path):
    """
    Accepts either:
    - export root containing reconstructed/
    - reconstructed/ directly
    """
    if (root / "reconstructed").is_dir():
        reconstructed = root / "reconstructed"
        export_root = root
    else:
        reconstructed = root
        export_root = root.parent if root.name == "reconstructed" else root

    rows = []
    for eml in sorted(reconstructed.rglob("*.eml")):
        rel = eml.relative_to(reconstructed)
        parts = rel.parts
        account_folder = parts[0] if len(parts) >= 2 else "ROOT"

        hdr = read_eml_headers(eml)
        idx, file_date, sender_slug, subject_slug = parse_filename_bits(eml)

        rows.append({
            "path": eml,
            "relpath": str(rel),
            "account_folder": account_folder,
            "size": eml.stat().st_size if eml.exists() else 0,
            "file_index": idx,
            "file_date": file_date,
            "sender_slug": sender_slug,
            "subject_slug": subject_slug,
            **hdr,
        })
    return export_root, reconstructed, rows


# ---------------------------
# Inspect / summary
# ---------------------------

def cmd_summary(args):
    _export_root, _reconstructed, rows = collect_reconstructed(Path(args.path))

    total = len(rows)
    acc = Counter(r["account_folder"] for r in rows)
    unk = acc.get("UNK", 0)
    missing_subject = sum(1 for r in rows if not r["subject"].strip())
    missing_date = sum(1 for r in rows if r["date"] == "0000-00-00")
    mids = [r["message_id"] for r in rows if r["message_id"].strip()]
    unique_mid_count = len(set(mids))
    dup_groups = sum(1 for _mid, c in Counter(mids).items() if c > 1)
    problem_count = sum(1 for r in rows if build_problem_flags(r, r["account_folder"]))

    print("INSPECT SUMMARY")
    print("---------------")
    print(f"Total messages:               {total}")
    print(f"Accounts:                     {len(acc)}")
    print(f"UNK messages:                 {unk}")
    print(f"Missing subject:              {missing_subject}")
    print(f"Missing date:                 {missing_date}")
    print(f"Messages with problem flags:  {problem_count}")
    print(f"Unique Message-ID count:      {unique_mid_count}")
    print(f"Duplicate Message-ID groups:  {dup_groups}")
    print()
    print("Per-account counts:")
    for a, c in acc.most_common():
        pct = (c / total * 100.0) if total else 0.0
        print(f"  {a}: {c} ({pct:.2f}%)")


def cmd_list(args):
    _export_root, _reconstructed, rows = collect_reconstructed(Path(args.path))

    if args.account:
        rows = [r for r in rows if r["account_folder"].upper() == args.account.upper()]

    if args.only_problems:
        rows = [r for r in rows if build_problem_flags(r, r["account_folder"])]

    if args.search:
        q = args.search.lower()
        filtered = []
        for r in rows:
            hay = " ".join([
                r.get("subject", ""),
                r.get("from", ""),
                r.get("to", ""),
                r.get("message_id", ""),
                r.get("relpath", ""),
            ]).lower()
            if q in hay:
                filtered.append(r)
                continue
            if args.body:
                body = read_eml_text_prefix(r["path"]).lower()
                if q in body:
                    filtered.append(r)
        rows = filtered

    W_ACC = 20
    W_FILE = 42
    W_SIZE = 9
    W_DATE = 10
    W_SUBJ = 50

    header = (
        f"{'ACCOUNT':<{W_ACC}} | "
        f"{'FILE':<{W_FILE}} | "
        f"{'SIZE':>{W_SIZE}} | "
        f"{'DATE':<{W_DATE}} | "
        f"{'SUBJECT':<{W_SUBJ}} | "
        f"FLAGS"
    )
    print(header)
    print("-" * len(header))

    shown = 0
    for r in rows[: args.limit]:
        flags = ",".join(build_problem_flags(r, r["account_folder"]))
        size_k = f"{r['size'] / 1024:.1f}K"
        print(
            f"{trunc(r['account_folder'], W_ACC):<{W_ACC}} | "
            f"{trunc(r['path'].name, W_FILE):<{W_FILE}} | "
            f"{size_k:>{W_SIZE}} | "
            f"{r['date']:<{W_DATE}} | "
            f"{trunc(r['subject'], W_SUBJ):<{W_SUBJ}} | "
            f"{flags}"
        )
        shown += 1

    if shown == 0:
        print("(no matching messages)")


# ---------------------------
# Validation
# ---------------------------

def csv_validation_key(row: dict):
    """
    Prefer Message-ID if present, else fallback to account/date/subject/size.
    Account is normalized with SAME exporter-style sanitize_name() logic.
    """
    acc_folder = sanitize_name(row.get("account", "") or "UNK", 80) if row.get("account") != "UNK" else "UNK"
    mid = (row.get("message_id", "") or "").strip().lower()
    date = (row.get("date", "") or "0000-00-00").strip()
    subject = (row.get("subject", "") or "").strip()
    size = str(row.get("size", "") or "").strip()

    if mid:
        return ("mid", acc_folder, mid)
    return ("fallback", acc_folder, date, subject, size)


def eml_validation_key(row: dict):
    acc_folder = row.get("account_folder", "UNK")
    mid = (row.get("message_id", "") or "").strip().lower()
    date = (row.get("date", "") or row.get("file_date", "") or "0000-00-00").strip()
    subject = (row.get("subject", "") or "").strip()
    size = str(row.get("size", "") or "").strip()

    if mid:
        return ("mid", acc_folder, mid)
    return ("fallback", acc_folder, date, subject, size)


def cmd_validate(args):
    export_root = Path(args.path)
    accounts_csv = export_root / "clean_emails_accounts.csv"
    if not accounts_csv.exists():
        print(f"Error: missing {accounts_csv}")
        sys.exit(1)

    _export_root, _reconstructed, eml_rows = collect_reconstructed(export_root)

    with accounts_csv.open(newline="", encoding="utf-8", errors="replace") as f:
        csv_rows = list(csv.DictReader(f))

    csv_keys = defaultdict(list)
    for r in csv_rows:
        csv_keys[csv_validation_key(r)].append(r)

    eml_keys = defaultdict(list)
    for r in eml_rows:
        eml_keys[eml_validation_key(r)].append(r)

    missing = []
    for k, items in csv_keys.items():
        if k not in eml_keys:
            missing.extend(items)

    orphan = []
    for k, items in eml_keys.items():
        if k not in csv_keys:
            orphan.extend(items)

    account_mismatches = 0
    date_mismatches = 0

    csv_by_mid = defaultdict(list)
    eml_by_mid = defaultdict(list)

    for r in csv_rows:
        mid = (r.get("message_id", "") or "").strip().lower()
        if mid:
            csv_by_mid[mid].append(r)

    for r in eml_rows:
        mid = (r.get("message_id", "") or "").strip().lower()
        if mid:
            eml_by_mid[mid].append(r)

    for mid in set(csv_by_mid) & set(eml_by_mid):
        csv_acc = sorted({
            sanitize_name(x.get("account", "") or "UNK", 80) if x.get("account") != "UNK" else "UNK"
            for x in csv_by_mid[mid]
        })
        eml_acc = sorted({x.get("account_folder", "UNK") for x in eml_by_mid[mid]})
        if csv_acc != eml_acc:
            account_mismatches += 1

        csv_dates = sorted({(x.get("date", "") or "0000-00-00") for x in csv_by_mid[mid]})
        eml_dates = sorted({(x.get("date", "") or x.get("file_date", "") or "0000-00-00") for x in eml_by_mid[mid]})
        if csv_dates != eml_dates:
            date_mismatches += 1

    dup_mid_groups = sum(
        1 for _mid, c in Counter(
            (r.get("message_id", "") or "").strip().lower()
            for r in eml_rows
            if (r.get("message_id", "") or "").strip()
        ).items() if c > 1
    )

    print("VALIDATION SUMMARY")
    print("------------------")
    print(f"Accounts CSV rows:              {len(csv_rows)}")
    print(f"Reconstructed .eml files:       {len(eml_rows)}")
    print(f"Missing files:                  {len(missing)}")
    print(f"Orphan files:                   {len(orphan)}")
    print(f"Account mismatches:             {account_mismatches}")
    print(f"Date mismatches:                {date_mismatches}")
    print(f"Duplicate Message-ID groups:    {dup_mid_groups}")

    if args.show_missing and missing:
        print()
        print(f"MISSING (first {args.limit})")
        print("-" * 18)
        for r in missing[: args.limit]:
            print(
                f"{r.get('account','')} | "
                f"{r.get('date','')} | "
                f"{trunc(r.get('subject',''), 70)} | "
                f"{r.get('message_id','')}"
            )

    if args.show_orphan and orphan:
        print()
        print(f"ORPHAN (first {args.limit})")
        print("-" * 17)
        for r in orphan[: args.limit]:
            print(
                f"{r.get('account_folder','')} | "
                f"{r.get('date','')} | "
                f"{trunc(r.get('subject',''), 70)} | "
                f"{r.get('message_id','')} | "
                f"{r.get('relpath','')}"
            )


# ---------------------------
# CLI
# ---------------------------

def build_parser():
    examples = """
Examples:
  python3 bichon_inspector.py summary OUTDIR
  python3 bichon_inspector.py list OUTDIR/reconstructed --account
  python3 bichon_inspector.py list OUTDIR/reconstructed -s
  python3 bichon_inspector.py list OUTDIR/reconstructed -s subject -b
  python3 bichon_inspector.py list OUTDIR/reconstructed --only-problems -l 100
  python3 bichon_inspector.py validate OUTDIR --show-missing
  python3 bichon_inspector.py validate OUTDIR --show-missing --show-orphan -l 100


""".strip()

    p = argparse.ArgumentParser(
        description=(
            "Inspect, search, summarize, and validate Bichon reconstructed email exports.\n\n"
            "Input can be either the export root directory or the reconstructed/ directory."
        ),
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    p_summary = sub.add_parser(
        "summary",
        help="show high-level summary for an export",
        description=(
            "Show overall mailbox/export statistics.\n\n"
            "Includes:\n"
            "- total reconstructed messages\n"
            "- per-account counts\n"
            "- UNK count\n"
            "- missing subject/date counts\n"
            "- messages with problem flags\n"
            "- unique Message-ID count\n"
            "- duplicate Message-ID groups"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_summary.add_argument(
        "path",
        help="Path to export root or reconstructed/ directory",
    )
    p_summary.set_defaults(func=cmd_summary)

    p_list = sub.add_parser(
        "list",
        help="list messages, optionally filtered/searched",
        description=(
            "List reconstructed .eml messages.\n\n"
            "Useful for:\n"
            "- inspecting UNK messages\n"
            "- searching by subject/header/body text\n"
            "- showing only problematic mails\n"
            "- reviewing a specific account folder"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_list.add_argument(
        "path",
        help="Path to export root or reconstructed/ directory",
    )
    p_list.add_argument(
        "--account",
        help="Filter by account folder name",
    )
    p_list.add_argument(
        "-l", "--limit",
        type=int,
        default=50,
        help="Maximum number of rows to display (default: 50)",
    )
    p_list.add_argument(
        "-s", "--search",
        help="Case-insensitive search in headers/metadata (subject, from, to, message-id, path)",
    )
    p_list.add_argument(
        "-b", "--body",
        action="store_true",
        help="Also search body prefix (only used together with --search)",
    )
    p_list.add_argument(
        "--only-problems",
        action="store_true",
        help="Show only messages with one or more problem flags",
    )
    p_list.set_defaults(func=cmd_list)

    p_val = sub.add_parser(
        "validate",
        help="validate reconstructed output against clean_emails_accounts.csv",
        description=(
            "Validate that reconstructed .eml files match the account CSV.\n\n"
            "Checks:\n"
            "- CSV row count vs reconstructed file count\n"
            "- missing reconstructed files for CSV rows\n"
            "- orphan reconstructed files not represented in CSV\n"
            "- account mismatches by Message-ID\n"
            "- date mismatches by Message-ID\n"
            "- duplicate Message-ID groups in reconstructed output\n\n"
            "Important:\n"
            "This command expects the EXPORT ROOT, because it needs:\n"
            "  clean_emails_accounts.csv\n"
            "and usually also:\n"
            "  reconstructed/"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_val.add_argument(
        "path",
        help="Path to export root directory",
    )
    p_val.add_argument(
        "-l", "--limit",
        type=int,
        default=50,
        help="Maximum number of missing/orphan rows to display (default: 50)",
    )
    p_val.add_argument(
        "--show-missing",
        action="store_true",
        help="Print first N CSV rows that have no matching reconstructed .eml",
    )
    p_val.add_argument(
        "--show-orphan",
        action="store_true",
        help="Print first N reconstructed .eml files that have no matching CSV row",
    )
    p_val.set_defaults(func=cmd_validate)

    return p


def compat_mode(argv):
    """
    Backward-friendly shortcut:
      python3 bichon_inspector.py OUTDIR --summary
      python3 bichon_inspector.py OUTDIR/reconstructed --account UNK
    """
    if len(argv) >= 2 and not argv[1].startswith("-") and argv[1] not in {"summary", "list", "validate"}:
        path = argv[1]
        if "--summary" in argv[2:]:
            return ["summary", path]
        out = ["list", path]
        i = 2
        while i < len(argv):
            tok = argv[i]
            if tok == "--summary":
                i += 1
                continue
            out.append(tok)
            if tok in {"--account", "-l", "--limit", "-s", "--search"} and i + 1 < len(argv):
                i += 1
                out.append(argv[i])
            i += 1
        return out
    return argv[1:]


def main():
    parser = build_parser()
    args = parser.parse_args(compat_mode(sys.argv))

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
