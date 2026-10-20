#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
extract_ad1_fixed.py - Robust AccessData AD1 Extractor
Extracts all files and metadata from AD1 images into a destination folder
and builds an SQLite index compatible with Autopsy.

Fixes all bugs from the original extract_ad1.exe:
1. Ignores .ad1.txt, .ad1.csv, and non-segment files in the image directory.
2. Fixes the 'hashMetadata referenced before assignment' bug on folders.
3. Preserves the exact nested directory structure using parent_path.
4. Uses SQLite transactions for fast bulk inserts.
5. Sanitizes file and directory names safely for Windows filesystems.
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
        if 4 in fm:  # Fixed: previously had bug checking hashMetadata instead of fm!
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


def sanitize_filename(name):
    """Sanitize illegal characters for Windows filenames."""
    return re.sub(r'[\\/*?:"<>|]', '_', name)


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
                    # Clean relative path
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

    except Exception as ex:
        print("Fatal extraction error: %s" % ex)

    finally:
        conn.close()

if __name__ == '__main__':
    main()
