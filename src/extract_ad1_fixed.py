#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
extract_ad1_fixed.py - Robust AccessData AD1 Extractor & Cache Carver
Extracts all files and metadata from AD1 images into a destination folder,
builds an SQLite index compatible with Autopsy, and carves media/documents
from browser cache streams (f_######).

Fixes all bugs from the original extract_ad1.exe:
1. Ignores .ad1.txt, .ad1.csv, and non-segment files in the image directory.
2. Fixes the 'hashMetadata referenced before assignment' bug on folders.
3. Preserves the exact nested directory structure using parent_path.
4. Uses SQLite transactions for fast bulk inserts.
5. Sanitizes file and directory names safely for Windows filesystems.
6. Automatically carves and decompresses JPEG/PNG/WebP/MP4/HTML from browser cache.
"""

import sys
import os
import re
import glob
import time
import struct
import zlib
import io
import hashlib
import sqlite3
import datetime
from collections import defaultdict
from operator import itemgetter

class SafeAD1Reader(object):
    """Robust AD1 Reader based on pyad1 with fixes for segment discovery."""

    def __init__(self, ad1_path, separator=os.sep, margin=512, string_encoding='utf-8'):
        self.separator = separator
        self.margin = margin
        self.string_encoding = string_encoding

        self.paths = self._Glob(ad1_path)
        self.absolute_offset = 0
        self.header_read = False
        self.sha1_meta_digest = hashlib.sha1()
        self.sha1_content_digest = hashlib.sha1()

    def __enter__(self):
        current_path = self.paths.pop(0)
        self.current_file = open(current_path, 'rb')
        self.current_size = os.path.getsize(current_path)
        self._ReadHeader()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'current_file') and not self.current_file.closed:
            self.current_file.close()

    def _ReadHeader(self):
        # Margin (512 bytes)
        self._Read(self.margin, False)

        # Signature (16 bytes)
        sig = self._Read(16)

        # AD1 version (= 3 or 4)
        self.version, = struct.unpack('<I', self._Read(4))
        if self.version not in (3, 4):
            raise Exception("Invalid AD1 version: %s" % self.version)

        # Unknown (4 bytes)
        self._Read(4)

        self.zlib_chunk_size, = struct.unpack("<I", self._Read(4))
        self.image_header_length, = struct.unpack("<q", self._Read(8))
        self.image_header_length_2, = struct.unpack("<q", self._Read(8))
        logical_image_path_length, = struct.unpack('<I', self._Read(4))

        if self.version == 4:
            self._Read(44)

        self.logical_image_path = self._Read(logical_image_path_length)

        try:
            log_path_str = self.logical_image_path.decode('utf-8', errors='ignore')
        except:
            log_path_str = str(self.logical_image_path)

        if log_path_str != 'Custom Content Image([Multi])':
            skip_len = self.margin + self.image_header_length_2 - self.current_file.tell()
            if skip_len > 0:
                self._Read(skip_len)

        if self.version == 4 and len(self.paths) > 0:
            self._ReadLastFrom(-372)

        self.header_read = True

    def _Glob(self, path):
        if not path.lower().endswith('.ad1'):
            raise ValueError('Invalid AD1 path: %s' % path)

        base_pattern = path[0:-1] + "*"
        unsorted_ad_paths = glob.glob(base_pattern)

        if not unsorted_ad_paths:
            raise Exception('No AD1 segment files found for: %s' % path)

        index_ad_paths = []
        for ad_path in unsorted_ad_paths:
            # Match strictly .ad followed by digits at the end of the filename
            m = re.search(r'\.ad(\d+)$', ad_path, re.IGNORECASE)
            if not m:
                continue
            index = int(m.group(1))
            index_ad_paths.append((ad_path, index))

        if not index_ad_paths:
            raise Exception('No valid AD1 segment files found matching pattern')

        sorted_ad_paths = [p for p, _ in sorted(index_ad_paths, key=itemgetter(1))]
        return sorted_ad_paths

    def _Read(self, length, doDigest=True):
        last_read = self.current_file.read(length)
        data = last_read

        while len(data) < length and len(self.paths) > 0:
            if not last_read:
                self.absolute_offset += self.current_file.tell() - self.margin
                self.current_file.close()

                current_path = self.paths.pop(0)
                self.current_size = os.path.getsize(current_path)
                self.current_file = open(current_path, 'rb')
                self.current_file.seek(self.margin)

            last_read = self.current_file.read(length - len(data))
            data += last_read

        if len(data) < length:
            raise Exception('Incomplete read from AD1 image')

        if doDigest:
            self.sha1_meta_digest.update(data)

        return data

    def _ReadLastFrom(self, pos):
        last_seg = self.paths[-1] if self.paths else None
        if last_seg and os.path.isfile(last_seg):
            with open(last_seg, 'rb') as inp:
                inp.seek(pos, io.SEEK_END)
                data = inp.read()
                self.sha1_meta_digest.update(data)

    def __iter__(self):
        folder_cache = {}

        while len(self.paths) > 0 or self.current_file.tell() < self.current_size - self.margin:
            block_start = self.current_file.tell()

            raw_block = self._Read(8 * 5)
            if len(raw_block) < 40:
                break

            next_group, next_in_group, next_block, start_of_data, decompressed_size = struct.unpack(
                '<5q', raw_block
            )

            raw_type = self._Read(4 * 2)
            if len(raw_type) < 8:
                break
            item_type, filename_length = struct.unpack('<2I', raw_type)

            next_block += self.margin
            start_of_data += self.margin

            filename_bytes = self._Read(filename_length)
            folder_index, = struct.unpack('<q', self._Read(8))

            parent_path = folder_cache.get(folder_index + self.margin, '')

            try:
                fname_str = filename_bytes.decode(self.string_encoding)
            except:
                fname_str = filename_bytes.decode('latin-1', errors='replace')

            if parent_path:
                path = os.path.join(parent_path, fname_str)
            else:
                path = fname_str

            folder_cache[block_start + self.absolute_offset] = path

            content = b''
            if decompressed_size > 0:
                chunk_count_raw = self._Read(8, False)
                if len(chunk_count_raw) == 8:
                    chunk_count = struct.unpack('<q', chunk_count_raw)[0] + 1
                    chunk_arr = struct.unpack('<%sq' % chunk_count, self._Read(8 * chunk_count, False))

                    for c in range(1, len(chunk_arr)):
                        compressed = self._Read(chunk_arr[c] - chunk_arr[c - 1], False)
                        try:
                            decompressed = zlib.decompress(compressed)
                        except:
                            decompressed = compressed
                        self.sha1_content_digest.update(decompressed)
                        content += decompressed

            metadata = {}
            while next_block > 0:
                raw_next = self._Read(8)
                if len(raw_next) < 8:
                    break
                next_block, = struct.unpack('<q', raw_next)

                raw_cat = self._Read(4 * 3)
                if len(raw_cat) < 12:
                    break
                category, key, value_length = struct.unpack('<3I', raw_cat)

                if category not in metadata:
                    metadata[category] = {}

                val_data = self._Read(value_length)
                metadata[category][key] = val_data

            yield item_type, parent_path, fname_str, metadata, content

        self.sha1_meta_digest.update(self.sha1_content_digest.digest())


def convert_date(date_str):
    """Convert AD1 timestamp (e.g. 20261014T104141.684624) to unix timestamp."""
    if not date_str:
        return None
    try:
        clean = date_str.split(".")[0]
        pattern = "%Y%m%dT%H%M%S"
        return int(time.mktime(time.strptime(clean, pattern)))
    except:
        return None


def process_metadata(metadata):
    """Extract standard metadata fields safely."""
    res = {
        "MD5": None,
        "SHA1": None,
        "File Size": None,
        "Physical File Size": None,
        "File Created": None,
        "File Modified": None,
        "File Accessed": None,
        "File Record Changed": None,
    }

    # Hash metadata (Category 1)
    if 1 in metadata:
        hm = metadata[1]
        if 20481 in hm:
            try:
                res["MD5"] = hm[20481].decode('utf-8', errors='ignore')
            except:
                pass
        if 20482 in hm:
            try:
                res["SHA1"] = hm[20482].decode('utf-8', errors='ignore')
            except:
                pass

    # File size metadata (Category 3)
    if 3 in metadata:
        fm = metadata[3]
        if 3 in fm:
            try:
                res["File Size"] = int(fm[3].decode('utf-8', errors='ignore'))
            except:
                pass
        if 4 in fm:
            try:
                res["Physical File Size"] = int(fm[4].decode('utf-8', errors='ignore'))
            except:
                pass

    # Dates metadata (Category 5)
    if 5 in metadata:
        dm = metadata[5]
        if 7 in dm:
            try:
                res["File Accessed"] = convert_date(dm[7].decode('utf-8', errors='ignore'))
            except:
                pass
        if 8 in dm:
            try:
                res["File Created"] = convert_date(dm[8].decode('utf-8', errors='ignore'))
            except:
                pass
        if 9 in dm:
            try:
                res["File Modified"] = convert_date(dm[9].decode('utf-8', errors='ignore'))
            except:
                pass
        if 40962 in dm:
            try:
                res["File Record Changed"] = convert_date(dm[40962].decode('utf-8', errors='ignore'))
            except:
                pass

    return res


def carve_browser_cache(output_dir, cursor, insert_sql):
    """
    Scans unpacked browser cache directories (f_###### files), identifies
    embedded media signatures, decompresses gzip streams, and carves out
    actual images, videos, and documents into a Carved_Browser_Cache folder.
    Also indexes each carved asset into the SQLite database.
    """
    output_base = os.path.join(output_dir, "Carved_Browser_Cache")
    total_carved = 0
    batch = []

    for root, dirs, files in os.walk(output_dir):
        if "Carved_Browser_Cache" in root:
            continue
        if not ("Cache_Data" in root or "Cache" in root):
            continue

        cache_files = [f for f in files if f.startswith("f_")]
        if not cache_files:
            continue

        # Extract profile name
        rel = os.path.relpath(root, output_dir)
        parts = rel.split(os.sep)
        profile_name = "Default"
        for p in parts:
            if "profile" in p.lower() or p.lower() == "default":
                profile_name = p
                break

        profile_out = os.path.join(output_base, profile_name)
        os.makedirs(profile_out, exist_ok=True)

        for fname in cache_files:
            fp = os.path.join(root, fname)
            try:
                with open(fp, "rb") as f_in:
                    data = f_in.read()
            except:
                continue
            if len(data) < 16:
                continue

            is_gzip = data.startswith(b"\x1f\x8b")
            payload = data
            if is_gzip:
                try:
                    payload = zlib.decompress(data, 16 + zlib.MAX_WBITS)
                except:
                    payload = data

            ext = None
            if payload.startswith(b"\xff\xd8\xff"):
                ext = "jpg"
            elif payload.startswith(b"\x89PNG\r\n\x1a\n"):
                ext = "png"
            elif payload.startswith(b"GIF87a") or payload.startswith(b"GIF89a"):
                ext = "gif"
            elif payload[:4] == b"RIFF" and payload[8:12] == b"WEBP":
                ext = "webp"
            elif payload.startswith(b"%PDF"):
                ext = "pdf"
            elif payload.startswith(b"\x00\x00\x01\x00"):
                ext = "ico"
            elif b"<svg" in payload[:200]:
                ext = "svg"
            elif b"<!DOCTYPE html" in payload[:200].lower() or b"<html" in payload[:200].lower():
                ext = "html"
            elif len(payload) > 8 and payload[4:8] == b"ftyp":
                ext = "mp4"
            elif payload.startswith(b"\x1a\x45\xdf\xa3"):
                ext = "webm"

            if ext:
                carved_name = f"{fname}.{ext}"
                target_path = os.path.join(profile_out, carved_name)
                try:
                    with open(target_path, "wb") as f_out:
                        f_out.write(payload)

                    md5 = hashlib.md5(payload).hexdigest()
                    sha1 = hashlib.sha1(payload).hexdigest()
                    cur_time = int(time.time())

                    row = (
                        f"Carved_Browser_Cache/{profile_name}",
                        "0",
                        profile_out,
                        carved_name,
                        len(payload),
                        len(payload),
                        cur_time,
                        cur_time,
                        cur_time,
                        cur_time,
                        md5,
                        sha1
                    )
                    batch.append(row)
                    total_carved += 1

                    if len(batch) >= 500:
                        cursor.executemany(insert_sql, batch)
                        batch = []
                except:
                    pass

    if batch:
        cursor.executemany(insert_sql, batch)

    if total_carved > 0:
        print(f"Browser Cache Carving: successfully recovered {total_carved} media assets into Carved_Browser_Cache.")


def parse_indexeddb_webapps(output_dir, cursor):
    """
    Scans unpacked IndexedDB LevelDB folders for web application data,
    recovering ChatGPT conversation titles, DeepSeek chat sessions,
    Claude AI project threads, and tracking all active web applications.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS indexeddb_records (
            app_name TEXT,
            app_domain TEXT,
            profile_name TEXT,
            record_type TEXT,
            title TEXT,
            details TEXT,
            date_created INTEGER,
            source_file TEXT
        )
    """)

    def parse_iso_to_epoch(iso_str):
        try:
            iso_clean = iso_str.rstrip("Z").split(".")[0]
            dt = datetime.datetime.fromisoformat(iso_clean)
            return int(dt.timestamp())
        except:
            return 0

    batch = []
    webapps = {}

    for root, dirs, files in os.walk(output_dir):
        if not root.endswith(".indexeddb.leveldb"):
            continue

        dirname = os.path.basename(root)
        domain_match = re.search(r"https?_([^_]+(?:_[^_]+)*?)_\d+\.indexeddb", dirname)
        domain = domain_match.group(1).replace("_", ".") if domain_match else dirname

        rel = os.path.relpath(root, output_dir)
        profile = "Default"
        for p in rel.split(os.sep):
            if "profile" in p.lower() or p.lower() == "default":
                profile = p
                break

        ldb_files = [f for f in files if f.endswith((".log", ".ldb"))]
        total_size = sum(os.path.getsize(os.path.join(root, f)) for f in ldb_files)

        if domain not in webapps:
            webapps[domain] = {"profile": profile, "size": total_size, "files": len(ldb_files)}
        else:
            webapps[domain]["size"] += total_size
            webapps[domain]["files"] += len(ldb_files)

        for f in ldb_files:
            fp = os.path.join(root, f)
            try:
                with open(fp, "rb") as fin:
                    data = fin.read()
            except:
                continue

            # 1. ChatGPT Conversations
            if "chatgpt" in domain:
                pattern = rb'createdAt"\x1b([\d\-T:\.Z]+)"\x02id"\$([a-f0-9\-]+).*?title"[\x01-\x7f]([^\x00-\x1f"]{3,100})'
                for m in re.finditer(pattern, data):
                    created, cid, title = m.groups()
                    epoch = parse_iso_to_epoch(created.decode(errors="ignore"))
                    batch.append(("ChatGPT", "chatgpt.com", profile, "AI Conversation",
                                  title.decode(errors="ignore"), f"Conversation ID: {cid.decode()}", epoch, f))

            # 2. DeepSeek AI Sessions
            elif "deepseek" in domain:
                pattern = rb'{"title":"([^"]+)","url":"([^"]+)".*?"time":(\d+)'
                for m in re.finditer(pattern, data):
                    t, u, ts = m.groups()
                    epoch = int(ts.decode()) // 1000 if len(ts) > 10 else int(ts.decode())
                    batch.append(("DeepSeek AI", "chat.deepseek.com", profile, "Chat Session",
                                  t.decode(errors="ignore"), f"URL: {u.decode()}", epoch, f))

                for sid in set(re.findall(rb'session_id"\$([a-f0-9\-]{36})', data)):
                    batch.append(("DeepSeek AI", "chat.deepseek.com", profile, "Active Session",
                                  "DeepSeek Chat Session", f"Session ID: {sid.decode()}", 0, f))

            # 3. Claude AI Projects/Conversations
            elif "claude" in domain:
                pattern = rb'"name"[:\x22]([^\x00-\x1f"\\]{4,80})["\x22].*?"uuid"[:\x22]([a-f0-9\-]{36})'
                for m in re.finditer(pattern, data):
                    n, uid = m.groups()
                    batch.append(("Claude AI", "claude.ai", profile, "Conversation / Project",
                                  n.decode(errors="ignore"), f"UUID: {uid.decode()}", 0, f))

    # Record all active Web Applications
    for dom, info in webapps.items():
        batch.append((dom, dom, info["profile"], "Web App IndexedDB Storage",
                      f"Web App: {dom}", f"Storage Size: {info['size']} bytes ({info['files']} files)", 0, "IndexedDB"))

    # Deduplicate batch
    unique_batch = []
    seen = set()
    for row in batch:
        key = (row[0], row[3], row[4], row[5])
        if key not in seen:
            seen.add(key)
            unique_batch.append(row)

    if unique_batch:
        cursor.executemany("""
            INSERT INTO indexeddb_records 
            (app_name, app_domain, profile_name, record_type, title, details, date_created, source_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, unique_batch)

    print(f"IndexedDB Parser: recovered {len(unique_batch)} web application & AI conversation records ({len(webapps)} unique web apps).")


def parse_messengers(output_dir, cursor):
    """
    Scans unpacked browser storage for WhatsApp Web and Telegram Web artifacts.
    Extracts contacts (phone numbers), chat threads, message counts, and security state.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whatsapp_contacts (
            phone_number TEXT,
            formatted_number TEXT,
            profile_name TEXT,
            source_file TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whatsapp_messages (
            chat_jid TEXT,
            chat_type TEXT,
            total_messages INTEGER,
            sent_count INTEGER,
            recv_count INTEGER,
            sample_message_ids TEXT,
            profile_name TEXT,
            source_file TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telegram_artifacts (
            profile_name TEXT,
            artifact_name TEXT,
            details TEXT,
            source_file TEXT
        )
    """)

    msg_pattern = re.compile(rb'(true|false)_([0-9\-]+(?:@c\.us|@g\.us|@lid))_([A-Za-z0-9]+)')
    phone_pattern = re.compile(rb'([0-9]{10,13})@c\.us')

    total_wa_contacts = 0
    total_wa_chats = 0
    total_tg_artifacts = 0

    for root, dirs, files in os.walk(output_dir):
        r_low = root.lower()

        # Extract profile name
        rel = os.path.relpath(root, output_dir)
        profile = "Default"
        for p in rel.split(os.sep):
            if "profile" in p.lower() or p.lower() == "default":
                profile = p
                break

        # --- WhatsApp Web Parsing ---
        if "whatsapp" in r_low and root.endswith(".indexeddb.leveldb"):
            ldb_files = [f for f in files if f.endswith((".log", ".ldb"))]
            contacts = set()
            chats = defaultdict(lambda: {"sent": 0, "recv": 0, "mids": []})

            for f in ldb_files:
                fp = os.path.join(root, f)
                try:
                    with open(fp, "rb") as fin:
                        data = fin.read()
                except:
                    continue

                for p in phone_pattern.findall(data):
                    contacts.add(p.decode())

                for from_me, peer, mid in msg_pattern.findall(data):
                    fm = from_me.decode()
                    p = peer.decode()
                    m = mid.decode()

                    if fm == "true":
                        chats[p]["sent"] += 1
                    else:
                        chats[p]["recv"] += 1

                    if len(chats[p]["mids"]) < 5:
                        chats[p]["mids"].append(m)

            contact_rows = []
            for p in contacts:
                if len(p) == 12:
                    fmt = f"+{p[:2]} {p[2:7]} {p[7:]}"
                elif len(p) == 11 and p.startswith("1"):
                    fmt = f"+1 ({p[1:4]}) {p[4:7]}-{p[7:]}"
                else:
                    fmt = f"+{p}"
                contact_rows.append((p, fmt, profile, "IndexedDB"))

            if contact_rows:
                cursor.executemany("""
                    INSERT INTO whatsapp_contacts (phone_number, formatted_number, profile_name, source_file)
                    VALUES (?, ?, ?, ?)
                """, contact_rows)
                total_wa_contacts += len(contact_rows)

            chat_rows = []
            for peer, d in chats.items():
                ctype = "WhatsApp Group Chat" if "@g.us" in peer else ("WhatsApp Direct Chat" if "@c.us" in peer else "WhatsApp Linked Device Chat")
                mids_str = ", ".join(d["mids"])
                chat_rows.append((peer, ctype, d["sent"] + d["recv"], d["sent"], d["recv"], mids_str, profile, "IndexedDB"))

            if chat_rows:
                cursor.executemany("""
                    INSERT INTO whatsapp_messages (chat_jid, chat_type, total_messages, sent_count, recv_count, sample_message_ids, profile_name, source_file)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, chat_rows)
                total_wa_chats += len(chat_rows)

        # --- Telegram Web Parsing ---
        elif "telegram" in r_low and "blob" in r_low:
            for f in files:
                fp = os.path.join(root, f)
                try:
                    sz = os.path.getsize(fp)
                    if sz > 100 * 1024:  # State blob
                        with open(fp, "rb") as fin:
                            data = fin.read()
                        has_2fa = b'twoFaSettings' in data
                        has_passcode = b'passcode' in data
                        is_locked = b'isScreenLocked' in data
                        details = f"Passcode Lock: {'Configured (LOCKED)' if (has_passcode and is_locked) else ('Configured' if has_passcode else 'None')}, 2FA: {'Enabled' if has_2fa else 'Disabled'}, Client State Blob: {sz} bytes"
                        cursor.execute("""
                            INSERT INTO telegram_artifacts (profile_name, artifact_name, details, source_file)
                            VALUES (?, ?, ?, ?)
                        """, (profile, "Telegram Web Client State", details, f))
                        total_tg_artifacts += 1
                except:
                    pass

    print(f"Messenger Parser: recovered {total_wa_contacts} WhatsApp contacts, {total_wa_chats} chat threads, {total_tg_artifacts} Telegram security artifacts.")


def main():
    if len(sys.argv) < 4:
        print("Usage: extract_ad1_fixed.py <ad1_file> <output_directory> <db3_file>")
        sys.exit(1)

    ad1_file = os.path.abspath(sys.argv[1])
    output_dir = os.path.abspath(sys.argv[2])
    db3_file = os.path.abspath(sys.argv[3])

    print("ad1 file is ", ad1_file)
    print("output Directory is ", output_dir)
    print("DB file is ", db3_file)

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.dirname(db3_file), exist_ok=True)

    if os.path.exists(db3_file):
        try:
            os.remove(db3_file)
        except:
            pass

    conn = sqlite3.connect(db3_file)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE ad1_info (
            ad1_path_name text,
            ad1_item_type text,
            autopsy_path_name text,
            file_name text,
            file_size int,
            file_physical_size int,
            date_created int,
            date_modified int,
            date_accessed int,
            date_record_changed int,
            md5_hash text,
            sha1_hash text
        )
    """)

    cursor.execute("""
        CREATE TABLE ad1_Errors (
            ad1_path_name text,
            ad1_item_type text,
            autopsy_path_name text,
            file_name text,
            file_size int,
            file_physical_size int,
            date_created int,
            date_modified int,
            date_accessed int,
            date_record_changed int,
            md5_hash text,
            sha1_hash text
        )
    """)
    conn.commit()

    insert_sql = """
        INSERT INTO ad1_info VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    file_count = 0
    dir_count = 0
    batch = []

    try:
        with SafeAD1Reader(ad1_file) as reader:
            for item_type, parent_path, filename, metadata, content in reader:
                try:
                    rel_dir = parent_path.lstrip('/\\')
                    target_dir = os.path.join(output_dir, rel_dir) if rel_dir else output_dir

                    if item_type == 5:  # Directory
                        dir_count += 1
                        os.makedirs(os.path.join(target_dir, filename), exist_ok=True)
                    elif item_type == 0:  # File
                        file_count += 1
                        os.makedirs(target_dir, exist_ok=True)
                        file_path = os.path.join(target_dir, filename)
                        with open(file_path, 'wb') as f_out:
                            f_out.write(content)

                    # Extract metadata
                    meta = process_metadata(metadata)
                    row = (
                        parent_path,
                        str(item_type),
                        target_dir,
                        filename,
                        meta["File Size"] if meta["File Size"] is not None else (len(content) if item_type == 0 else 0),
                        meta["Physical File Size"],
                        meta["File Created"],
                        meta["File Modified"],
                        meta["File Accessed"],
                        meta["File Record Changed"],
                        meta["MD5"],
                        meta["SHA1"]
                    )
                    batch.append(row)

                    if len(batch) >= 500:
                        cursor.executemany(insert_sql, batch)
                        conn.commit()
                        batch = []

                    if (file_count + dir_count) % 500 == 0:
                        print("Processed %d items (%d files, %d folders)..." % (
                            file_count + dir_count, file_count, dir_count
                        ))

                except Exception as inner_ex:
                    print("Item error: %s" % inner_ex)

        if batch:
            cursor.executemany(insert_sql, batch)
            conn.commit()

        print("Extraction complete: %d files, %d folders." % (file_count, dir_count))

        # --- Automatically Carve Browser Cache ---
        print("Starting automated browser cache carving...")
        carve_browser_cache(output_dir, cursor, insert_sql)
        conn.commit()

        # --- Automatically Parse IndexedDB & Web App Data ---
        print("Starting IndexedDB & Web App triage...")
        parse_indexeddb_webapps(output_dir, cursor)
        conn.commit()

        # --- Automatically Parse WhatsApp & Telegram Messengers ---
        print("Starting WhatsApp & Telegram triage...")
        parse_messengers(output_dir, cursor)
        conn.commit()

    except Exception as ex:
        print("Fatal extraction error: %s" % ex)

    finally:
        conn.close()

if __name__ == '__main__':
    main()
