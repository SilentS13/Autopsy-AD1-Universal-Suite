# =============================================================================
# AD1 Universal Extractor & Forensics Suite - Autopsy Ingest Module
# =============================================================================
# Universal extractor for AccessData AD1 logical evidence containers
# (including multi-segment .ad1, .ad2, .ad3, .ad4... images).
#
# Automatically unpacks any AD1 image, mounts it into Autopsy as a
# native Logical Files Data Source, and automatically triages browser
# and system artifacts into Autopsy Blackboard results.
#
# Supports:  Autopsy 4.19+ / 4.20+ / 4.23+ / Jython 2.7
# Author:    Digital Forensics Lab
# Version:   2.0
# =============================================================================

import jarray
import inspect
import os
import json
import shutil
from subprocess import Popen, PIPE

from java.io import File
from java.lang import Class
from java.lang import System
from java.sql import DriverManager, SQLException
from java.util import ArrayList, UUID
from java.util.logging import Level

from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services.FileManager import FileAddProgressUpdater
from org.sleuthkit.autopsy.datamodel import ContentUtils


# =============================================================================
# Helper: Progress Updater for addLocalFilesDataSource
# =============================================================================
class AD1ProgressUpdater(FileAddProgressUpdater):
    """Tracks files as they are registered into the case database."""

    def __init__(self):
        self.files = []

    def fileAdded(self, newFile):
        self.files.append(newFile)

    def getFiles(self):
        return self.files


# =============================================================================
# Timestamp conversion utilities
# =============================================================================
def chrome_time_to_epoch(chrome_ts):
    """Convert Chrome/WebKit timestamp (microseconds since 1601-01-01) to
    Unix epoch seconds. Returns 0 if invalid."""
    try:
        chrome_ts = long(chrome_ts)
        if chrome_ts <= 0:
            return 0
        epoch_diff = 11644473600
        return int(chrome_ts / 1000000) - epoch_diff
    except:
        return 0


def firefox_time_to_epoch(moz_ts):
    """Convert Firefox timestamp (microseconds since Unix epoch) to
    Unix epoch seconds. Returns 0 if invalid."""
    try:
        moz_ts = long(moz_ts)
        if moz_ts <= 0:
            return 0
        if moz_ts > 1000000000000:
            return int(moz_ts / 1000000)
        elif moz_ts > 1000000000:
            return int(moz_ts / 1000)
        else:
            return int(moz_ts)
    except:
        return 0


# =============================================================================
# Data Source Ingest Module - Universal AD1 Extractor & Auto-Triage
# =============================================================================
class AD1UniversalExtractorModuleFactory(IngestModuleFactoryAdapter):
    """Factory for the Universal AD1 Extractor Module."""

    moduleName = "AD1 Universal Extractor & Forensics Suite"

    def __init__(self):
        self.settings = None

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return ("Universal extractor for AccessData AD1/AD2/AD3... logical containers. "
                "Extracts any AD1 evidence image into Autopsy as a Data Source and "
                "automatically triages browser and system artifacts.")

    def getModuleVersionNumber(self):
        return "2.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return AD1UniversalExtractorModule(self.settings)


class AD1UniversalExtractorModule(DataSourceIngestModule):
    """Finds .ad1 files in the data source, extracts them using
    the bundled 64-bit extract_ad1.exe, registers the extracted directory
    tree as a new Data Source, and parses all extracted artifacts."""

    _logger = Logger.getLogger(AD1UniversalExtractorModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.settings = settings
        self.artifacts_created = 0

    def startUp(self, context):
        self.context = context

        # Locate extract_ad1.exe
        self_dir = os.path.dirname(os.path.abspath(__file__))
        self.path_to_exe = os.path.join(self_dir, "extract_ad1.exe")

        if not os.path.exists(self.path_to_exe):
            parent_dir = os.path.dirname(self_dir)
            candidates = [
                os.path.join(parent_dir, "AD1_Universal_Extractor", "extract_ad1.exe"),
                os.path.join(parent_dir, "BrowserForensicsAD1", "extract_ad1.exe"),
                os.path.join(parent_dir, "AD1_Extractor", "extract_ad1.exe")
            ]
            for c in candidates:
                if os.path.exists(c):
                    self.path_to_exe = c
                    break

        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException(
                "extract_ad1.exe not found in plugin directory: " + self_dir)

        self.log(Level.INFO, "extract_ad1.exe located at: " + self.path_to_exe)

    def process(self, dataSource, progressBar):
        self.log(Level.INFO, "Starting AD1 Universal Extraction process")
        progressBar.switchToIndeterminate()

        modDir = os.path.join(
            Case.getCurrentCase().getModulesOutputDirAbsPath(),
            "AD1_Universal_Extractor")
        try:
            if not os.path.isdir(modDir):
                os.makedirs(modDir)
        except Exception as e:
            self.log(Level.INFO, "Output directory notice: " + str(e))

        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        files = fileManager.findFiles(dataSource, "%", "/")
        ad1_count = 0

        for f in files:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            localPath = f.getLocalAbsPath()
            if localPath is None:
                continue
            if f.isDir():
                continue

            if not localPath.lower().endswith(".ad1"):
                continue

            ad1_count += 1
            filename_noext = os.path.splitext(f.getName())[0]
            ad1_output_dir = os.path.join(modDir, filename_noext)
            db_path = os.path.join(modDir, filename_noext + ".db3")

            # Ensure the output directory exists
            try:
                if not os.path.isdir(ad1_output_dir):
                    os.makedirs(ad1_output_dir)
            except:
                pass

            self.log(Level.INFO, "Extracting AD1: " + localPath + " -> " + ad1_output_dir)
            progressBar.progress("Unpacking AD1 Container: " + f.getName())

            # Run extract_ad1.exe <ad1_path> <output_dir> <db_path>
            try:
                pipe = Popen(
                    [self.path_to_exe, localPath, ad1_output_dir, db_path],
                    stdout=PIPE, stderr=PIPE)
                out_text, err_text = pipe.communicate()
                ret_code = pipe.returncode

                self.log(Level.INFO, "extract_ad1.exe exit code: " + str(ret_code))
                if out_text:
                    self.log(Level.INFO, "extract_ad1.exe stdout: " + str(out_text)[:1000])
                if err_text:
                    self.log(Level.WARNING, "extract_ad1.exe stderr: " + str(err_text)[:1000])
            except Exception as e:
                self.log(Level.SEVERE, "Failed to execute extract_ad1.exe: " + str(e))
                continue

            # Verify extraction directory
            if not os.path.isdir(ad1_output_dir):
                self.log(Level.WARNING, "Extraction directory not found: " + ad1_output_dir)
                continue

            extracted_count = 0
            for root, dirs, fnames in os.walk(ad1_output_dir):
                extracted_count += len(fnames)
            self.log(Level.INFO, "Successfully extracted " + str(extracted_count) + " files from " + f.getName())

            # 1. Index all extracted files and metadata from the SQLite catalog
            if os.path.isfile(db_path):
                self._create_ad1_info_artifacts(skCase, f, db_path)

            # 2. Auto-triage: Scan and parse browser and system artifacts directly
            progressBar.progress("Triaging artifacts from " + f.getName())
            self._scan_and_parse_browser_artifacts(f, ad1_output_dir)

            # 3. Mount extracted directory tree as a new Logical Files Data Source
            progressBar.progress("Adding extracted files to Autopsy case")
            self._add_extracted_as_datasource(ad1_output_dir, f.getName())

        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA,
            AD1UniversalExtractorModuleFactory.moduleName,
            "AD1 extraction complete. Processed " + str(ad1_count) +
            " container(s), created " + str(self.artifacts_created) + " artifacts.")
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

    def _create_ad1_info_artifacts(self, skCase, source_file, db_path):
        """Read the SQLite DB created by extract_ad1.exe and create
        AD1_FILE_INFO artifacts for each extracted file."""
        try:
            try:
                art_type_id = skCase.addArtifactType(
                    "TSK_AD1_FILE_INFO", "AD1 Extracted File Info")
            except:
                art_type_id = skCase.getArtifactTypeID("TSK_AD1_FILE_INFO")

            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s" % db_path)
            stmt = dbConn.createStatement()

            sql = ("SELECT file_name, ad1_path_name, date_created, "
                   "date_modified, date_accessed, md5_hash, sha1_hash "
                   "FROM ad1_info WHERE ad1_item_type = '0' OR ad1_item_type = 0")
            rs = stmt.executeQuery(sql)

            moduleName = AD1UniversalExtractorModuleFactory.moduleName

            while rs.next():
                try:
                    art = source_file.newArtifact(art_type_id)
                    attributes = ArrayList()
                    attributes.add(BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME,
                        moduleName, rs.getString("file_name")))
                    attributes.add(BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEMP_DIR,
                        moduleName, rs.getString("ad1_path_name")))
                    attributes.add(BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED,
                        moduleName, rs.getInt("date_created")))
                    attributes.add(BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED,
                        moduleName, rs.getInt("date_modified")))
                    attributes.add(BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED,
                        moduleName, rs.getInt("date_accessed")))

                    md5 = rs.getString("md5_hash")
                    if md5:
                        attributes.add(BlackboardAttribute(
                            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_HASH_MD5,
                            moduleName, md5))
                    sha1 = rs.getString("sha1_hash")
                    if sha1:
                        attributes.add(BlackboardAttribute(
                            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_HASH_SHA1,
                            moduleName, sha1))

                    art.addAttributes(attributes)
                    self._post_to_blackboard(art)
                except Exception as row_ex:
                    pass

            rs.close()
            stmt.close()
            dbConn.close()

        except Exception as e:
            self.log(Level.WARNING, "Error creating AD1 file info artifacts: " + str(e))

    def _add_extracted_as_datasource(self, ad1_output_dir, source_name):
        """Add the extracted directory as a new Logical Files data source
        in Autopsy so all files appear in the data sources tree."""
        try:
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            skcase_data = Case.getCurrentCase()

            dir_list = ArrayList()
            dir_list.add(ad1_output_dir)

            device_id = UUID.randomUUID()
            self.log(Level.INFO, "Adding data source with device ID: " + str(device_id))

            skcase_data.notifyAddingDataSource(device_id)

            progress_updater = AD1ProgressUpdater()

            newDataSource = fileManager.addLocalFilesDataSource(
                str(device_id),
                "AD1 Extracted: " + source_name,
                "",
                dir_list,
                progress_updater)

            try:
                skcase_data.notifyDataSourceAdded(newDataSource, device_id)
            except Exception as notify_ex:
                self.log(Level.INFO, "notifyDataSourceAdded: " + str(notify_ex))

            self.log(Level.INFO, "Successfully added extracted files as new data source")

        except Exception as e:
            self.log(Level.SEVERE, "Failed to add extracted files as data source: " + str(e))

    def _post_to_blackboard(self, art):
        try:
            blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
            blackboard.postArtifact(art, AD1UniversalExtractorModuleFactory.moduleName)
            self.artifacts_created += 1
        except:
            pass

    # =========================================================================
    # Auto-Triage: Automatic scanning and parsing of browser databases
    # =========================================================================
    def _scan_and_parse_browser_artifacts(self, source_file, base_dir):
        """Scan the extracted directory on disk and parse all browser databases."""
        for root, dirs, files in os.walk(base_dir):
            for fname in files:
                fl = fname.lower()
                full_path = os.path.join(root, fname)

                browser_name = self._detect_browser_from_path(root)

                # --- Chrome / Edge History ---
                if fl == "history":
                    self._parse_sqlite_history(source_file, full_path, browser_name)

                # --- Chrome / Edge Cookies ---
                elif fl == "cookies":
                    self._parse_sqlite_cookies(source_file, full_path, browser_name)

                # --- Chrome / Edge Saved Logins ---
                elif fl == "login data":
                    self._parse_sqlite_logins(source_file, full_path, browser_name)

                # --- Chrome / Edge Bookmarks ---
                elif fl == "bookmarks":
                    self._parse_json_bookmarks(source_file, full_path, browser_name)

                # --- Chrome / Edge Top Sites ---
                elif fl == "top sites":
                    self._parse_sqlite_topsites(source_file, full_path, browser_name)

                # --- Chrome / Edge Web Data (Autofill) ---
                elif fl == "web data":
                    self._parse_sqlite_webdata(source_file, full_path, browser_name)

                # --- Chrome / Edge Preferences (Extensions) ---
                elif fl == "preferences":
                    self._parse_json_preferences(source_file, full_path, browser_name)

                # --- Firefox places.sqlite ---
                elif fl == "places.sqlite":
                    self._parse_firefox_places(source_file, full_path)

                # --- Firefox cookies.sqlite ---
                elif fl == "cookies.sqlite":
                    self._parse_firefox_cookies(source_file, full_path)

                # --- Firefox formhistory.sqlite ---
                elif fl == "formhistory.sqlite":
                    self._parse_firefox_formhistory(source_file, full_path)

                # --- Firefox logins.json ---
                elif fl == "logins.json":
                    self._parse_firefox_logins_json(source_file, full_path)

    def _detect_browser_from_path(self, path):
        pl = path.lower()
        if "firefox" in pl or "mozilla" in pl:
            return "Mozilla Firefox"
        elif "edge" in pl:
            return "Microsoft Edge"
        elif "brave" in pl:
            return "Brave Browser"
        elif "opera" in pl:
            return "Opera"
        elif "vivaldi" in pl:
            return "Vivaldi"
        elif "chrome" in pl or "google" in pl:
            return "Google Chrome"
        return "Web Browser"

    def _get_connection(self, db_path):
        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            return DriverManager.getConnection("jdbc:sqlite:%s" % db_path)
        except Exception as e:
            self.log(Level.WARNING, "Cannot open SQLite DB " + db_path + ": " + str(e))
            return None

    def _parse_sqlite_history(self, source_file, db_path, browser_name):
        conn = self._get_connection(db_path)
        if not conn:
            return
        modName = AD1UniversalExtractorModuleFactory.moduleName
        try:
            stmt = conn.createStatement()

            # Visits and URLs
            try:
                rs = stmt.executeQuery(
                    "SELECT u.url, u.title, u.visit_count, u.last_visit_time "
                    "FROM urls u ORDER BY u.last_visit_time DESC")
                while rs.next():
                    url = rs.getString("url") or ""
                    title = rs.getString("title") or ""
                    ts = chrome_time_to_epoch(rs.getLong("last_visit_time"))

                    art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY)
                    attrs = ArrayList()
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, url))
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE, modName, title))
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, modName, ts))
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
                    art.addAttributes(attrs)
                    self._post_to_blackboard(art)
                rs.close()
            except Exception as ex:
                self.log(Level.INFO, "History query notice: " + str(ex))

            # Downloads
            try:
                rs = stmt.executeQuery(
                    "SELECT target_path, tab_url, start_time FROM downloads")
                while rs.next():
                    target = rs.getString("target_path") or ""
                    tab_url = rs.getString("tab_url") or ""
                    ts = chrome_time_to_epoch(rs.getLong("start_time"))

                    art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD)
                    attrs = ArrayList()
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH, modName, target))
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, tab_url))
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, modName, ts))
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
                    art.addAttributes(attrs)
                    self._post_to_blackboard(art)
                rs.close()
            except:
                pass

            # Search Terms
            try:
                rs = stmt.executeQuery(
                    "SELECT k.term, u.url FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id")
                while rs.next():
                    term = rs.getString("term") or ""
                    url = rs.getString("url") or ""

                    art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_SEARCH_QUERY)
                    attrs = ArrayList()
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT, modName, term))
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, url))
                    attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
                    art.addAttributes(attrs)
                    self._post_to_blackboard(art)
                rs.close()
            except:
                pass

            stmt.close()
            conn.close()
        except Exception as e:
            self.log(Level.WARNING, "Error parsing History: " + str(e))

    def _parse_sqlite_cookies(self, source_file, db_path, browser_name):
        conn = self._get_connection(db_path)
        if not conn:
            return
        modName = AD1UniversalExtractorModuleFactory.moduleName
        try:
            stmt = conn.createStatement()
            rs = stmt.executeQuery(
                "SELECT host_key, name, value, path, creation_utc, last_access_utc FROM cookies")
            while rs.next():
                host = rs.getString("host_key") or ""
                name = rs.getString("name") or ""
                val = rs.getString("value") or ""
                path = rs.getString("path") or ""
                created = chrome_time_to_epoch(rs.getLong("creation_utc"))
                accessed = chrome_time_to_epoch(rs.getLong("last_access_utc"))

                art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, host + path))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, modName, name))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, modName, val))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, modName, created))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, modName, accessed))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
            rs.close()
            stmt.close()
            conn.close()
        except Exception as e:
            self.log(Level.WARNING, "Error parsing Cookies: " + str(e))

    def _parse_sqlite_logins(self, source_file, db_path, browser_name):
        conn = self._get_connection(db_path)
        if not conn:
            return
        modName = AD1UniversalExtractorModuleFactory.moduleName
        try:
            stmt = conn.createStatement()
            rs = stmt.executeQuery(
                "SELECT origin_url, action_url, username_value, signon_realm, date_created, date_last_used FROM logins")
            while rs.next():
                origin = rs.getString("origin_url") or ""
                user = rs.getString("username_value") or ""
                realm = rs.getString("signon_realm") or ""
                created = chrome_time_to_epoch(rs.getLong("date_created"))
                used = chrome_time_to_epoch(rs.getLong("date_last_used"))

                art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_SERVICE_ACCOUNT)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, origin))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME, modName, user))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, modName, realm))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, modName, created))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, modName, used))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
            rs.close()
            stmt.close()
            conn.close()
        except Exception as e:
            self.log(Level.WARNING, "Error parsing Logins: " + str(e))

    def _parse_json_bookmarks(self, source_file, file_path, browser_name):
        try:
            with open(file_path, "r") as f_in:
                data = json.load(f_in)
            roots = data.get("roots", {})
            for root_name in ["bookmark_bar", "other", "synced"]:
                if root_name in roots:
                    self._walk_bookmarks(source_file, roots[root_name], root_name, browser_name)
        except Exception as e:
            self.log(Level.WARNING, "Error parsing Bookmarks JSON: " + str(e))

    def _walk_bookmarks(self, source_file, node, folder_path, browser_name):
        if not node:
            return
        ntype = node.get("type", "")
        name = node.get("name", "")
        modName = AD1UniversalExtractorModuleFactory.moduleName

        if ntype == "url":
            url = node.get("url", "")
            ts = chrome_time_to_epoch(node.get("date_added", 0))

            art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_BOOKMARK)
            attrs = ArrayList()
            attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, url))
            attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE, modName, name))
            attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, modName, ts))
            attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
            art.addAttributes(attrs)
            self._post_to_blackboard(art)
        elif ntype == "folder":
            for child in node.get("children", []):
                self._walk_bookmarks(source_file, child, folder_path + "/" + name, browser_name)

    def _parse_sqlite_topsites(self, source_file, db_path, browser_name):
        conn = self._get_connection(db_path)
        if not conn:
            return
        modName = AD1UniversalExtractorModuleFactory.moduleName
        try:
            stmt = conn.createStatement()
            try:
                rs = stmt.executeQuery("SELECT url, title FROM top_sites")
            except:
                rs = stmt.executeQuery("SELECT url, title FROM thumbnails")

            while rs.next():
                url = rs.getString("url") or ""
                title = rs.getString("title") or ""

                art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, url))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE, modName, title))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
            rs.close()
            stmt.close()
            conn.close()
        except:
            pass

    def _parse_sqlite_webdata(self, source_file, db_path, browser_name):
        conn = self._get_connection(db_path)
        if not conn:
            return
        skCase = Case.getCurrentCase().getSleuthkitCase()
        modName = AD1UniversalExtractorModuleFactory.moduleName
        try:
            try:
                art_type_id = skCase.addArtifactType("TSK_WEB_AUTOFILL", "Web Autofill")
            except:
                art_type_id = skCase.getArtifactTypeID("TSK_WEB_AUTOFILL")

            stmt = conn.createStatement()
            rs = stmt.executeQuery("SELECT name, value, count, date_created FROM autofill")
            while rs.next():
                name = rs.getString("name") or ""
                val = rs.getString("value") or ""
                count = rs.getInt("count")
                ts = chrome_time_to_epoch(rs.getLong("date_created"))

                art = source_file.newArtifact(art_type_id)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, modName, name))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, modName, val))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNT, modName, count))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, modName, ts))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
            rs.close()
            stmt.close()
            conn.close()
        except:
            pass

    def _parse_json_preferences(self, source_file, file_path, browser_name):
        try:
            with open(file_path, "r") as f_in:
                data = json.load(f_in)
            exts = data.get("extensions", {}).get("settings", {})
            skCase = Case.getCurrentCase().getSleuthkitCase()
            modName = AD1UniversalExtractorModuleFactory.moduleName

            try:
                art_type_id = skCase.addArtifactType("TSK_BROWSER_EXTENSION", "Browser Extension")
            except:
                art_type_id = skCase.getArtifactTypeID("TSK_BROWSER_EXTENSION")

            for ext_id, ext_data in exts.items():
                if not isinstance(ext_data, dict):
                    continue
                manifest = ext_data.get("manifest", {})
                if not isinstance(manifest, dict):
                    continue
                ext_name = manifest.get("name", ext_id)
                ext_ver = manifest.get("version", "")
                ext_desc = manifest.get("description", "")

                art = source_file.newArtifact(art_type_id)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, modName, ext_name))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VERSION, modName, ext_ver))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT, modName, ext_desc))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, browser_name))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
        except:
            pass

    def _parse_firefox_places(self, source_file, db_path):
        conn = self._get_connection(db_path)
        if not conn:
            return
        modName = AD1UniversalExtractorModuleFactory.moduleName
        try:
            stmt = conn.createStatement()
            rs = stmt.executeQuery(
                "SELECT p.url, p.title, p.last_visit_date FROM moz_places p WHERE p.hidden = 0")
            while rs.next():
                url = rs.getString("url") or ""
                title = rs.getString("title") or ""
                ts = firefox_time_to_epoch(rs.getLong("last_visit_date"))

                art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, url))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE, modName, title))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, modName, ts))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, "Mozilla Firefox"))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
            rs.close()
            stmt.close()
            conn.close()
        except:
            pass

    def _parse_firefox_cookies(self, source_file, db_path):
        conn = self._get_connection(db_path)
        if not conn:
            return
        modName = AD1UniversalExtractorModuleFactory.moduleName
        try:
            stmt = conn.createStatement()
            rs = stmt.executeQuery("SELECT host, name, value, path, creationTime FROM moz_cookies")
            while rs.next():
                host = rs.getString("host") or ""
                name = rs.getString("name") or ""
                val = rs.getString("value") or ""
                path = rs.getString("path") or ""
                ts = firefox_time_to_epoch(rs.getLong("creationTime"))

                art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, host + path))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, modName, name))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, modName, val))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, modName, ts))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, "Mozilla Firefox"))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
            rs.close()
            stmt.close()
            conn.close()
        except:
            pass

    def _parse_firefox_formhistory(self, source_file, db_path):
        conn = self._get_connection(db_path)
        if not conn:
            return
        skCase = Case.getCurrentCase().getSleuthkitCase()
        modName = AD1UniversalExtractorModuleFactory.moduleName
        try:
            try:
                art_type_id = skCase.addArtifactType("TSK_WEB_AUTOFILL", "Web Autofill")
            except:
                art_type_id = skCase.getArtifactTypeID("TSK_WEB_AUTOFILL")

            stmt = conn.createStatement()
            rs = stmt.executeQuery("SELECT fieldname, value, timesUsed, firstUsed FROM moz_formhistory")
            while rs.next():
                field = rs.getString("fieldname") or ""
                val = rs.getString("value") or ""
                cnt = rs.getInt("timesUsed")
                ts = firefox_time_to_epoch(rs.getLong("firstUsed"))

                art = source_file.newArtifact(art_type_id)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, modName, field))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, modName, val))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNT, modName, cnt))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, modName, ts))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, "Mozilla Firefox"))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
            rs.close()
            stmt.close()
            conn.close()
        except:
            pass

    def _parse_firefox_logins_json(self, source_file, file_path):
        try:
            with open(file_path, "r") as f_in:
                data = json.load(f_in)
            modName = AD1UniversalExtractorModuleFactory.moduleName
            for login in data.get("logins", []):
                hostname = login.get("hostname", "")
                created = firefox_time_to_epoch(login.get("timeCreated", 0))

                art = source_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_SERVICE_ACCOUNT)
                attrs = ArrayList()
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, modName, hostname))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, modName, created))
                attrs.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, modName, "Mozilla Firefox"))
                art.addAttributes(attrs)
                self._post_to_blackboard(art)
        except:
            pass
