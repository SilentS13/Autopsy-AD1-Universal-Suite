# BrowserForensicsAD1 - Autopsy Ingest Module

An advanced **Autopsy Digital Forensics Plugin** that extracts split AccessData `.ad1` logical images (including multi-part `.ad1`, `.ad2`, `.ad3`, `.ad4` containers) and automatically parses browser artifacts across all user profiles into Autopsy's native Blackboard results.

---

## 🚀 Key Features

* **Complete AD1 Multi-Segment Support**: Handles single and segmented custom content images (`.ad1`, `.ad2`, `.ad3`, `.ad4`...) created by FTK Imager.
* **Resilient Segment Parsing**: Properly handles directory companion files (ignores `.ad1.csv`, `.ad1.txt`, and log files without crashing).
* **Multi-Profile Browser Triage**: Recursively parses all browser profiles (`Default`, `Profile 1`, `Profile 2`, `Guest Profile`, etc.).
* **Zero Extra Ingest Steps**: Extracted browser databases (`History`, `Cookies`, `Login Data`, `Bookmarks`, `Web Data`, `Preferences`, `places.sqlite`) are parsed immediately during data source ingestion.
* **Autopsy 4.20+ / 4.23+ Compatible**: Fixes the legacy `ClassCastException` present in older community plugins.

---

## 🌐 Supported Browsers & Artifacts

| Browser Family | Supported Browsers | Artifacts Extracted | Blackboard Type |
|---|---|---|---|
| **Chromium** | Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi | Browsing History & Visits | `TSK_WEB_HISTORY` |
| | | Download History & Target Paths | `TSK_WEB_DOWNLOAD` |
| | | Search Engine Queries | `TSK_WEB_SEARCH_QUERY` |
| | | Web Cookies & Expiration Dates | `TSK_WEB_COOKIE` |
| | | Saved Web Accounts / Logins | `TSK_SERVICE_ACCOUNT` |
| | | Bookmarks Hierarchy | `TSK_WEB_BOOKMARK` |
| | | Form Autofill Data | `TSK_WEB_AUTOFILL` |
| | | Top Sites & Shortcuts | `TSK_WEB_HISTORY` |
| | | Installed Extensions | `TSK_BROWSER_EXTENSION` |
| **Mozilla** | Firefox, Waterfox, LibreWolf | Places History & Bookmarks | `TSK_WEB_HISTORY` / `TSK_WEB_BOOKMARK` |
| | | Downloaded Files | `TSK_WEB_DOWNLOAD` |
| | | Cookies | `TSK_WEB_COOKIE` |
| | | Form History | `TSK_WEB_AUTOFILL` |
| | | Saved Logins (`logins.json`) | `TSK_SERVICE_ACCOUNT` |

---

## 📦 Installation

1. Open **Autopsy**.
2. Navigate to **Tools** → **Python Plugins**.
3. This opens your Autopsy Python modules folder:
   ```text
   %APPDATA%\autopsy\python_modules\
   ```
4. Clone or download this repository into a folder named `BrowserForensicsAD1`:
   ```bash
   cd %APPDATA%\autopsy\python_modules\
   git clone https://github.com/<your-username>/Autopsy-BrowserForensicsAD1.git BrowserForensicsAD1
   ```
5. Restart Autopsy so it detects the new ingest module.

---

## 🔍 How to Use

1. Open or create an Autopsy case.
2. Click **Add Data Source**.
3. Choose **Logical Files** as the data source type (do not choose Disk Image).
4. Browse to and select your `.ad1` file (e.g. `Evidence.ad1`).
5. On the **Configure Ingest Modules** screen, ensure:
   * ☑️ **Browser Forensics AD1 - Extractor** is checked.
6. Click **Finish**.

The plugin will:
1. Unpack all files from the multi-segment AD1 image into your case output directory.
2. Index every file's metadata and hashes into an SQLite catalog.
3. Parse all browser history, downloads, cookies, logins, bookmarks, and autofill directly into the Blackboard.
4. Mount the unpacked file structure as a searchable data source in Autopsy.

---

## 🛠️ Repository Structure

```text
Autopsy-BrowserForensicsAD1/
├── BrowserForensicsAD1.py          # Autopsy Ingest Module (Jython 2.7)
├── extract_ad1.exe                 # 64-bit Standalone AD1 Extractor Binary
├── src/
│   └── extract_ad1_fixed.py        # Python 3 source code for the extractor
├── LICENSE                         # Apache License 2.0
├── .gitignore
└── README.md
```

---

## 🐛 Bug Fixes Over Legacy Plugins

This module resolves major issues found in older AD1 extractor plugins:
1. **Integer Parsing Crash on Companion Files**: Older plugins ran `int(extension.rsplit('.ad', 1)[1])`. When FTK Imager created `Image.ad1.csv` or `Image.ad1.txt`, it attempted `int('1.csv')`, crashing before extracting a single file. Fixed using strict regex matching `\.ad(\d+)$`.
2. **`hashMetadata` Variable Reference Error**: Fixed an uninitialized variable bug that aborted folder entry parsing.
3. **Mangled Directory Hierarchy**: Fixed path concatenation bugs so directory trees are extracted accurately.
4. **Autopsy 4.20+ ClassCastException**: Fixed an invalid file notification loop that threw `ClassCastException` on modern SleuthKit versions.

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
