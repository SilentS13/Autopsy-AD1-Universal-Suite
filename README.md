# AD1 Universal Extractor & Forensics Suite for Autopsy

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Autopsy Version](https://img.shields.io/badge/Autopsy-4.20%2B%20%7C%204.23%2B-green.svg)](https://www.autopsy.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.sleuthkit.org/)

An advanced, universal **Autopsy Digital Forensics Ingest Module** that unpacks single and multi-segment AccessData `.ad1` logical evidence containers (`.ad1`, `.ad2`, `.ad3`, `.ad4`...) and automatically mounts them into Autopsy as native Logical Files Data Sources.

Additionally includes an automated **Artifact Triage Engine** that parses browser and system databases directly into Autopsy's Blackboard without requiring extra ingest runs.

---

## 🎯 Why This Plugin Exists

Autopsy natively relies on The Sleuth Kit (TSK) to read raw sectors and partition tables (MBR/GPT) of physical disk images (`.raw`, `.dd`, `.E01`). Because AccessData `.ad1` files are proprietary logical containers (similar to forensic compressed archives), **Autopsy cannot natively ingest AD1 files as disk images**.

Previous community plugins (such as legacy `AD1_Extractor`) suffered from critical bugs:
* **The `.ad1.csv` / `.ad1.txt` Crash**: When FTK Imager created companion export reports in the same directory, the extractor crashed attempting to parse report extensions as segment numbers (`invalid literal for int(): '1.csv'`).
* **The `hashMetadata` Crash**: A variable scoping bug caused directory parsing to crash with `local variable 'hashMetadata' referenced before assignment`.
* **Mangled Folder Trees**: Concatentation bugs nested subdirectories infinitely.
* **Autopsy 4.20+ `ClassCastException`**: Obsolete API calls tried to notify Autopsy on each individual file instead of the data source object.

**This suite completely fixes all of these issues**, providing a stable, high-performance extraction and triage workflow for modern Autopsy.

---

## 🚀 Key Features

* **Universal AD1 Unpacking**: Extracts **any** `.ad1` container created by FTK Imager (User Profiles `C:\Users\<user>`, Windows Registry, USB Triage, Documents, Network captures).
* **Multi-Segment Support**: Seamlessly combines split images (`.ad1`, `.ad2`, `.ad3`, `.ad4`...) of arbitrary sizes.
* **Automatic Native Data Source Mount**: Mounts the extracted directory tree directly into Autopsy so standard modules (Keyword Search, Hash Lookup, File Type Identification, Recent Activity, PhotoRec Carver) can run immediately.
* **Integrated Metadata Catalog**: Every file's original timestamps (MACB) and cryptographic hashes (MD5, SHA-1) are preserved and indexed under `AD1 Extracted File Info`.
* **Out-of-the-Box Browser Triage**:
  * **Chromium (Chrome, Edge, Brave, Opera, Vivaldi)**: History, Downloads, Search Queries, Cookies, Saved Web Accounts (`Login Data`), Bookmarks, Autofill, and Extensions.
  * **Mozilla (Firefox, LibreWolf, Waterfox)**: Places (`places.sqlite`), Bookmarks, Downloads, Cookies, Form History, and Logins (`logins.json`).

---

## 📦 Installation

1. Open **Autopsy**.
2. Go to **Tools** → **Python Plugins**.
3. Autopsy will open the local Python modules directory:
   ```text
   %APPDATA%\autopsy\python_modules\
   ```
4. Clone or copy this repository into a folder named `AD1_Universal_Extractor`:
   ```bash
   cd %APPDATA%\autopsy\python_modules\
   git clone https://github.com/<your-username>/Autopsy-AD1-Universal-Suite.git AD1_Universal_Extractor
   ```
5. Restart Autopsy.

---

## 🔍 How to Ingest an AD1 Image

> **Important**: Always add `.ad1` files as **Logical Files**, never as *Disk Image*.

1. Open or create an Autopsy case.
2. Click **Add Data Source**.
3. Select **Logical Files** as the data source type.
4. Browse to and select your primary `.ad1` file (e.g. `Evidence.ad1`). All subsequent split segments (`.ad2`, `.ad3`...) in the same folder are automatically resolved.
5. In the **Configure Ingest Modules** list, check:
   * ☑️ **AD1 Universal Extractor & Forensics Suite**
6. Click **Finish**.

---

## 📊 Extracted Artifacts Overview

| Category | Artifact Description | Blackboard Type |
|---|---|---|
| **File System** | AD1 Container File Metadata & Hashes | `TSK_AD1_FILE_INFO` |
| **Web Activity** | Visited URLs, Visit Counts, Timestamps | `TSK_WEB_HISTORY` |
| **Web Search** | Search Engine Queries | `TSK_WEB_SEARCH_QUERY` |
| **Downloads** | File Destination Paths, Source URLs, Timestamps | `TSK_WEB_DOWNLOAD` |
| **Web Accounts** | Saved Login Credentials & Domains | `TSK_SERVICE_ACCOUNT` |
| **Cookies** | Cookie Names, Values, Domains, Expiration | `TSK_WEB_COOKIE` |
| **Bookmarks** | Full Bookmark Tree Hierarchy & URLs | `TSK_WEB_BOOKMARK` |
| **Autofill** | Web Form Field Names, Values, Counts | `TSK_WEB_AUTOFILL` |
| **Extensions** | Browser Extensions, Versions, Descriptions | `TSK_BROWSER_EXTENSION` |

---

## 🛠️ Repository Layout

```text
Autopsy-AD1-Universal-Suite/
├── AD1_Universal_Extractor.py     # Autopsy Ingest Module (Jython 2.7)
├── extract_ad1.exe                # 64-bit Standalone AD1 Extractor Binary
├── src/
│   └── extract_ad1_fixed.py       # Python 3 source code for the extractor
├── LICENSE                        # Apache License 2.0
├── .gitignore
└── README.md
```

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
