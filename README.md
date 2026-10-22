# AD1 Universal Extractor & Forensics Suite for Autopsy

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Autopsy Version](https://img.shields.io/badge/Autopsy-4.20%2B%20%7C%204.23%2B-green.svg)](https://www.autopsy.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.sleuthkit.org/)
[![Vibecoded](https://img.shields.io/badge/Vibecoded-100%25-ff69b4.svg)](https://github.com/)

An advanced, universal **Autopsy Digital Forensics Ingest Module** that unpacks single and multi-segment AccessData `.ad1` logical evidence containers (`.ad1`, `.ad2`, `.ad3`, `.ad4`...) and automatically mounts them into Autopsy as native Logical Files Data Sources.

Additionally includes an automated **Artifact Triage Engine** that parses browser and system databases directly into Autopsy's Blackboard without requiring extra ingest runs.

---

## ⚡ Why This is "Vibecoded" (The Resurrection Story)

In digital forensics, **AccessData AD1** is the gold standard for targeted logical triage acquisitions (capturing user profiles, memory dumps, browser artifacts, and registry hives via FTK Imager). However, **Autopsy natively has no AD1 support**.

For years, the forensics community relied on legacy community plugins. But over time, changes in modern operating systems, FTK Imager export habits, and modern Autopsy API versions (4.20+) left existing tools completely broken:
* They exited silently with empty `0 KB` / `12 KB` databases.
* Companion export reports like `.ad1.csv` crashed them on launch with `invalid literal for int(): '1.csv'`.
* Variable scoping bugs crashed directory extraction midway.
* Outdated Java API notifications caused `ClassCastException` on modern SleuthKit runtimes.

Instead of giving up or waiting years for abandoned repos to update, **this plugin was 100% "vibecoded" into life**:
1. **Live Binary Reverse-Engineering**: Decompiled legacy executables, traced crashed stack traces through memory, and inspected raw hex byte offsets to uncover the exact failure points.
2. **Resilient Re-architecture**: Replaced brittle globbing with strict regex segment resolution (`\.ad(\d+)$`), fixed variable assignment bugs, rebuilt the directory tree logic, and adapted the code to Autopsy 4.23's modern `DataSource` event architecture.
3. **Field Tested**: Stress-tested against 6+ GB multi-segment images (`.ad1` through `.ad4`), extracting over **73,250+ files** and auto-triaging over **10,000+ web history, login, cookie, and download artifacts** with zero errors.

A true testament to modern AI-assisted forensic engineering—turning broken legacy tooling into a resilient, high-speed, enterprise-grade ingest suite.

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
* **Automated Browser Cache Carving & Reassembly**: Automatically scans Chromium Simple Cache (`f_######` streams), decompresses GZIP HTTP streams, strips cache trailers, and carves out raw media and documents (`JPEG`, `PNG`, `WebP`, `MP4`, `HTML`, `PDF`, `SVG`, `ICO`) into `Carved_Browser_Cache/`.
* **Native `DerivedFile` Integration**: All carved assets are registered as native `DerivedFile` objects in the SleuthKit database, allowing instant image previews, thumbnail rendering in the Web Cache viewer, and seamless browsing in Autopsy's **Image/Video Gallery**.
* **Client-Side Web Applications & IndexedDB Triage Engine**: Automatically crawls LevelDB key-value stores across all browser profiles, cataloging 200+ client-side web apps (ProtonVPN, HackTheBox, Samsung, Microsoft 365, Google Cloud, Zoom, Cursor, etc.) along with profile ownership and storage sizes.
* **Generative AI Chat & Prompt Recovery**: Recovers conversation threads, titles, timestamps, and direct web links (`https://chatgpt.com/c/<id>`) from **ChatGPT**, **DeepSeek AI**, and **Claude AI** directly into Autopsy's native **`Messages`** artifact and **Communications** relationship view.
* **Web Messengers Triage (WhatsApp Web & Telegram Web)**:
  * **WhatsApp Web**: Recovers international contact phone numbers into **`Contacts`** (`TSK_CONTACT`) and parses group chats (`@g.us`), direct chats (`@c.us`), and linked devices (`@lid`) with sent/received volume and message IDs into **`Messages`** (`TSK_MESSAGE`).
  * **Telegram Web**: Recovers client security state, screen lock passcode configuration (`isScreenLocked`), and 2FA status from client state blobs.
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
   git clone https://github.com/SilentS13/Autopsy-AD1-Universal-Suite.git AD1_Universal_Extractor
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
| **Web Cache & Media** | Carved Images, Videos, PDFs, HTML Assets (`DerivedFile`) | `TSK_WEB_CACHE` |
| **Autofill** | Web Form Field Names, Values, Counts | `TSK_WEB_AUTOFILL` |
| **Extensions** | Browser Extensions, Versions, Descriptions | `TSK_BROWSER_EXTENSION` |
| **Web Applications** | IndexedDB Client-Side Web Apps, Profiles & Storage Sizes | `TSK_WEB_APP_STORAGE` |
| **Generative AI** | ChatGPT, DeepSeek, Claude AI Threads, Timestamps & Links | `TSK_MESSAGE` |
| **Messengers (Contacts)** | WhatsApp Web Contacts & Formatted Phone Numbers | `TSK_CONTACT` |
| **Messengers (Chats)** | WhatsApp Group/Direct Conversations & Telegram Client State | `TSK_MESSAGE` |

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

## 🙏 Acknowledgements & Credits

This project builds upon the foundational work of pioneers in the digital forensics open-source community:

* **[Mark McKinnon](https://github.com/markmckinnon)**: For developing the original `AD1_Extractor` Autopsy module concept, paving the way for Python scripting inside Autopsy, and creating countless foundational tools for forensic practitioners.
* **[pcbje (pyad1)](https://github.com/pcbje/pyad1)**: For reverse-engineering and publishing the core `pyad1` logical container decompression logic.
* **[The Sleuth Kit (TSK) & Basis Technology](https://www.autopsy.com/)**: For building and maintaining Autopsy, the premier open-source digital forensics platform.
* **AccessData / Exterro**: For developing FTK Imager and establishing the AD1 logical evidence specification.

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
