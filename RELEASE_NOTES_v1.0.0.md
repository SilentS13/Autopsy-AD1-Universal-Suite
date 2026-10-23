# v1.0.0 - Autopsy AD1 Universal Extractor & Forensics Suite

The first official release of the **Autopsy AD1 Universal Extractor & Forensics Suite**, bringing universal AccessData `.ad1` logical evidence container support, multi-segment image handling, and automated deep forensic triage to **Autopsy 4.20+ and 4.23+**.

---

## 🚀 Key Capabilities & Highlights

* **Universal Multi-Segment AD1 Unpacking**: Seamlessly resolves and reconstructs split containers (`.ad1`, `.ad2`, `.ad3`, `.ad4`...) of arbitrary sizes created by FTK Imager.
* **Bug Fixes for Modern Autopsy**:
  * Fixed the `.ad1.csv` / `.ad1.txt` companion report crash (`invalid literal for int()`).
  * Fixed the directory parsing `hashMetadata` variable scoping crash.
  * Fixed folder tree recursive nesting issues.
  * Upgraded Java/Jython data source event notifications, eliminating `ClassCastException`.
* **Automated Browser Cache Carving & Reassembly**:
  * Crawls Chromium Simple Cache streams (`f_######`), decompresses GZIP payloads, and carves raw media/documents (`JPEG`, `PNG`, `WebP`, `MP4`, `PDF`, `HTML`).
  * **Native `DerivedFile` Integration**: All carved assets are registered in the SleuthKit database, enabling instant thumbnail generation in the Web Cache viewer and native browsing in Autopsy's **Image/Video Gallery**.
* **Client-Side Web Applications & IndexedDB Triage Engine**:
  * Automatically inspects LevelDB key-value stores across browser profiles, cataloging 200+ modern web applications (ProtonVPN, HackTheBox, Samsung, Microsoft 365, Google Cloud, Zoom, Cursor, etc.) along with profile ownership and storage footprints (`TSK_WEB_APP_STORAGE`).
* **Generative AI Chat & Prompt Recovery**:
  * Recovers conversation threads, titles, timestamps, and direct web links (`https://chatgpt.com/c/<id>`) from **ChatGPT**, **DeepSeek AI**, and **Claude AI** directly into Autopsy's native **`Messages`** (`TSK_MESSAGE`) artifact and Communications graph.
* **Web Messengers Triage**:
  * **WhatsApp Web**: Recovers international contact phone numbers into **`Contacts`** (`TSK_CONTACT`) and extracts group chats (`@g.us`) and direct chats (`@c.us`) with message volume and IDs into **`Messages`** (`TSK_MESSAGE`).
  * **Telegram Web**: Recovers client security state, screen lock passcode configuration (`isScreenLocked`), and 2FA status.
* **Zero-Config Browser Triage**:
  * **Chromium (Chrome, Edge, Brave, Opera, Vivaldi)**: History, Downloads, Search Queries, Cookies, Saved Web Accounts (`Login Data`), Bookmarks, Autofill, and Extensions.
  * **Mozilla (Firefox, LibreWolf, Waterfox)**: Places (`places.sqlite`), Bookmarks, Downloads, Cookies, Form History, and Logins (`logins.json`).

---

## 📦 Quick Installation

1. Download **`AD1_Universal_Extractor-v1.0.0.zip`** from the Assets below.
2. In Autopsy, navigate to **Tools** → **Python Plugins**.
3. Autopsy will open your local plugin directory:
   ```text
   %APPDATA%\autopsy\python_modules\
   ```
4. Extract `AD1_Universal_Extractor-v1.0.0.zip` directly into that folder (it extracts neatly into a folder named `AD1_Universal_Extractor`).
5. Restart Autopsy.

---

## 🔍 How to Use

1. Create or open an Autopsy case.
2. Click **Add Data Source** and choose **Logical Files**.
3. Select your `.ad1` file (e.g. `Evidence.ad1`).
4. In the Ingest Modules list, check **AD1 Universal Extractor & Forensics Suite**.
5. Click **Finish**.

---

## 🙏 Credits & Acknowledgements
- **Mark McKinnon**: Original pioneer of Autopsy Python modules and the initial `AD1_Extractor` concept.
- **pcbje (pyad1)**: Decompression algorithms and AD1 container structure reverse-engineering.
- **Basis Technology & The Sleuth Kit**: Creators and maintainers of Autopsy.
- **AccessData / Exterro**: Developers of FTK Imager.
