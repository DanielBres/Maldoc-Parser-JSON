########################################################################################################################
##                                                                                                                    ##
##                                                                                                                    ##
##  __   __       _     _              _____                                                                          ##
## |  \\/  |     | |   | |            |  __ \                                                                         ##
## | \\  / | __ _| | __| | ___   ___  | |__) |_ _ _ __ ___  ___ _ __                                                  ##
## | |\\/| |/ _` | |/ _` |/ _ \ / __| |  ___/ _` | '__/ __|/ _ \ '__|                                                 ##
## | |   | | (_| | | (_| | (_) | (__  | |  | (_| | |  \__ \  __/ |                                                    ##
## |_|   |_|\__,_|_|\___,|\___/ \___| |_|   \__,_|_|  |___/\___|_|                                                    ##
##                                                                                                                    ##
##                                                                                                                    ##
## Author: Daniel Bresler                                                                                             ##
##                                                                                                                    ##
## maldoc_parser is a static analysis tool for common Office formats and PDF files.                                   ##
## The main goal of the tool is to automate static analysis as much as possible.                                      ##
## It currently supports OLE, OOXML, RTF and PDF files.                                                               ##
##                                                                                                                    ##
## Python 3.x                                                                                                         ##
##                                                                                                                    ##
## Usage: maldoc_parser.py [MALDOC_FILE_PATH]                                                                         ##
##                                                                                                                    ##
##                                                                                                                    ##
########################################################################################################################

import re
import os
import sys
import json
import math
import xlrd
import glob
import zlib
import shutil
import struct
import string
import hashlib
import hexdump
import olefile
import os.path
import zipfile
import platform
import binascii
import msoffcrypto
from os import path
from pathlib import Path
from sys import exit
from io import StringIO
# from capstone import *
import xml.etree.ElementTree as ET
from beautifultable import BeautifulTable
from pyxlsb import open_workbook as open_xlsb


class Helpers():
    """
    The Helpers() class has helper methods and regular expressions that are used by all other classes

    """
    my_os = platform.system()
    summary_table = BeautifulTable(maxwidth=200)
    summary_table.headers = (["Indication", "Description"])
    summary_table.columns.width = 100

    json_report = {"findings": {}}

    raw_json_report = {"raw_report": {}}
    raw_data = ""
    # Magic byte regular expressions:
    #################################
    RTF = b'\x7b\x5c\x72\x74'
    OLE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    OOXML = b'\x50\x4b\x03\x04'
    PDF = b'%PDF-'

    # OLE related regular expressions:
    ##################################
    MICROSOFT_EXCEL = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x78\x63\x65\x6c'
    MICROSOFT_OFFICE_WORD = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x4f\x66\x66\x69\x63\x65\x20\x57\x6f\x72\x64'
    OLE_FILE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    EQ_EDIT_CLSID_RE = rb'\x02\xce\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
    EQUATION_EDITOR_RE = rb'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x71\x75\x61\x74\x69\x6f\x6e\x20\x33\x2e\x30'
    equation_regex = r'[[e|E][q|Q][u|U][a|A][t|T][i|I][o|O][n|N]]{8}'
    equation_byte_regex = rb'[\x65\x45\x71\x51\x75\x55\x61\x41\x74\x54\x69\x49\x6F\x4F\x6E\x4E]{8}'
    OLE_DDE_RE = rb'\x13\s*\x44\x44\x45\x41\x55\x54\x4f[^\x14]+'

    # OLE Excel files related regular expressions:
    ##############################################
    BOF_RECORD_RE = rb'\t\x08[\x08|\x10]\x00\x00[\x05|\x06][\x00-\xff]{6}'
    BOF_RECORDS_RE = rb'\t\x08[\x08|\x10]\x00\x00[\x05|\x06][\x00-\xff]{6}'
    EOF_BOF = rb"\x0a\x00\x00\x00\x09\x08"
    BOUNDHSEET_RECORD = rb'\x85\x00[\x01-\x88]\x00[\x00-\xff]{4}[\x00-\x02][\x00|\x01]'
    SHEET_NAME_1 = rb'\x85\x00[\x00-\xff]\x00[\x00-\xff]{5}[\x00|\x01]([\x00-\xff]{1,16})\x85\x00'
    SHEET_NAME_2 = rb'\x85\x00[\x00-\xff]\x00[\x00-\xff]{5}[\x00|\x01]([\x00-\xff]{1,12})'

    # RTF related regular expressions:
    ##################################
    rtf_clean_regex = rb"\x0d|\x0a|\x09|\x20"
    rtf_ole_blob_regex = rb"(\x64\x30\x63\x66\x31\x31\x65[\x00-\x66]+)\}"
    rtf_binary_blob_regex = rb"[A-Z]\}([\x00-\x66]+)\{\\|\x62\x69\x6e([\x00-\x66]+)\}|\}([\x00-\x66]+)\}|\x6d\x61\x74\x68([\x00-\x66]+)\}|\}([\x00-\x5b]+)|[\x61-\x7a]{3,20}([\x00-\x5b\x61-\x7a]+)\{|\\[\x00-\x5b\x61-\x7a]{3,5}([\x00-\x5b\x61-\x7a]+)"
    pe_header_regex = r"4d5a[a-z0-9]{100,500}546869732070726f6772616d"
    pe_magic_str = r"4d5a"

    # PDF related regular expressions:
    ##################################
    obj_regex = rb"\d{1,2} \d obj[\x00-\xff]+?endobj"
    obj_header = rb"\d{1,2} \d obj[\x00-\xff]<<[\x00-\xff]+?>>"
    export_data_regex = rb'this\.exportDataObject\((.*?)\)'
    filespec_regex = rb'/Type /Filespec|/Type/Filespec'
    file_regex = rb'/F \(.*?\)|/F\(.*?\)'
    unc_regex = rb'F\(\\\\\\\\\d{1,3}\.d{1,3}\.d{1,3}\.d{1,3}\\\\.*?\) 0 R'
    uri_regex = rb'URI \(.* ?\)|URI\(.* ?\)'
    emb_file_regex = rb'/Type /EmbeddedFile|/Type/EmbeddedFile'
    file_ref_regex = rb'F (\d{1,2}) 0 R'
    objstm_regex = rb'/Type /ObjStm'
    js_ref_pattern = rb'JS (\d{1,2}) 0 R'
    auto_action_pattern = rb'/AA'
    open_action_regex = rb'/OpenAction'
    o_regex = rb'/O (\d{1,2}) 0 R'
    open_a_ref_regex = rb'/OpenAction 9 0 R'
    launch_regex = rb'/Launch'
    stream_regex = rb'stream([\x00-\xff]+?)endstream'
    goto_regex = rb'/GoTo|/GoToR|/GoToE'
    # goto_remote_regex = rb'/GoToR'
    # goto_emb_regex = rb'/GoToE'
    submitform_regex = rb'/SubmitForm'

    # Generic regular expressions:
    ##############################
    unicode_regex = rb'[\x20-\x7e]\x00[\x20-\x7e]\x00'
    ascii_regex = rb'[\x20-\x7e]{10,1000}'
    base64_regex = r'(?:[A-Za-z\d+/]{4})|(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)'

    # OLE object identifier CLSIDs (the CLSID is at raw offset 0x450 in the OLE file):
    ##################################################################################
    CLSIDS = {
        rb'\x00\x02\x08\x10\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel.Sheet.5',
        rb'\x00\x02\x08\x11\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel.Chart.5',
        rb'\x00\x02\x08\x20\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Microsoft Excel 97-2003 Worksheet (Excel.Sheet.8)',
        rb'\x00\x02\x08\x21\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel.Chart.8',
        rb'\x00\x02\x08\x30\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel.Sheet.12',
        rb'\x00\x02\x08\x32\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel sheet with macro enabled (Excel.SheetMacroEnabled.12)',
        rb'\x00\x02\x08\x33\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel binary sheet with macro enabled (Excel.SheetBinaryMacroEnabled.12)',
        rb'\x00\x02\x09\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Word 6.0-7.0 Document (Word.Document.6)',
        rb'\x00\x02\x09\x06\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Word 97-2003 Document (Word.Document.8)',
        rb'\x00\x02\x09\x07\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Word Picture (Word.Picture.8)',
        rb'\x00\x02\x0C\x01\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x02\x14\x01\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Windows LNK Shortcut file',  #
        rb'\x00\x02\x17\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Equation 2.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)',
        rb'\x00\x02\x26\x01\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x02\x26\x02\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x02\x26\x03\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x02\xCE\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Equation 3.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)',
        rb'\x00\x02\xCE\x02\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Equation 3.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)',
        rb'\x00\x02\xCE\x03\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'MathType Equation Object',
        rb'\x00\x03\x00\x0B\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Equation (Known Related to CVE-2017-11882 or CVE-2018-0802)',
        rb'\x00\x03\x00\x0C\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x03\x00\x0D\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x03\x00\x0E\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x04\x8E\xB4\x3E\x20\x59\x42\x2F\x95\xE0\x55\x7D\xA9\x60\x38\xAF': 'Microsoft Powerpoint.Slide.12',
        rb'\x06\x29\x0B\xD3\x48\xAA\x11\xD2\x84\x32\x00\x60\x08\xC3\xFB\xFC': 'Script Moniker, aka Moniker to a Windows Script Component (may trigger CVE-2017-0199)',
        rb'\x18\xA0\x6B\x6B\x2F\x3F\x4E\x2B\xA6\x11\x52\xBE\x63\x1B\x2D\x22': 'Word.DocumentMacroEnabled.12 (DOCM)',
        rb'\x30\x50\xF4\xD8\x98\xB5\x11\xCF\xBB\x82\x00\xAA\x00\xBD\xCE\x0B': 'HTML Application (may trigger CVE-2017-0199)',
        rb'\x44\xF9\xA0\x3B\xA3\xEC\x4F\x3B\x93\x64\x08\xE0\x00\x7F\x21\xDF': 'Control.TaskSymbol (Known Related to CVE-2015-1642 & CVE-2015-2424)',
        rb'\x46\xE3\x13\x70\x3F\x7A\x11\xCE\xBE\xD6\x00\xAA\x00\x61\x10\x80': 'Forms.MultiPage',
        rb'\x4C\x59\x92\x41\x69\x26\x10\x1B\x99\x92\x00\x00\x0B\x65\xC6\xF9': 'Forms.Image (may trigger CVE-2015-2424)',
        rb'\x64\x81\x8D\x10\x4F\x9B\x11\xCF\x86\xEA\x00\xAA\x00\xB9\x29\xE8': 'Microsoft Powerpoint.Show.8',
        rb'\x64\x81\x8D\x11\x4F\x9B\x11\xCF\x86\xEA\x00\xAA\x00\xB9\x29\xE8': 'Microsoft Powerpoint.Slide.8',
        rb'\x6E\x18\x20\x20\xF4\x60\x11\xCE\x9B\xCD\x00\xAA\x00\x60\x8E\x01': 'ActiveX Control: Forms.Frame',
        rb'\x20\x20\x18\x6E\x60\xF4\xCE\x11\x9B\xCD\x00\xAA\x00\x60\x8E\x01': 'ActiveX Control: Microsoft Forms 2.0 Frame',
        rb'\x88\xD9\x69\xEB\xF1\x92\x11\xD4\xA6\x5F\x00\x40\x96\x32\x51\xE5': 'Msxml2.ServerXMLHTTP.5.0',
        rb'\x88\xD9\x69\xEA\xF1\x92\x11\xD4\xA6\x5F\x00\x40\x96\x32\x51\xE5': 'Msxml2.XMLHTTP.5.0',
        rb'\x88\xD9\x69\xE7\xF1\x92\x11\xD4\xA6\x5F\x00\x40\x96\x32\x51\xE5': 'Msxml2.XMLSchemaCache.5.0',
        rb'\x88\xD9\x69\xE8\xF1\x92\x11\xD4\xA6\x5F\x00\x40\x96\x32\x51\xE5': 'Msxml2.XSLTemplate.5.0',
        rb'\x97\x8C\x9E\x23\xD4\xB0\x11\xCE\xBF\x2D\x00\xAA\x00\x3F\x40\xD0': 'Microsoft Forms 2.0 Label (Forms.Label.1)',
        rb'\xB8\x01\xCA\x65\xA1\xFC\x11\xD0\x85\xAD\x44\x45\x53\x54\x00\x00': 'Adobe Acrobat Document - PDF file',
        rb'\xC0\x8A\xFD\x90\xF2\xA1\x11\xD1\x84\x55\x00\xA0\xC9\x1F\x38\x80': 'ShellBrowserWindow',
        rb'\xC6\x2A\x69\xF0\x16\xDC\x11\xCE\x9E\x98\x00\xAA\x00\x57\x4A\x4F': 'Forms.Form',
        rb'\xCF\x4F\x55\xF4\x8F\x87\x4D\x47\x80\xBB\x58\x08\x16\x4B\xB3\xF8': 'Microsoft Powerpoint.Show.12',
        rb'\xD7\x05\x32\x40\xCE\x69\x11\xCD\xA7\x77\x00\xDD\x01\x14\x3C\x57': 'Microsoft Forms 2.0 CommandButton',
        rb'\xF2\x0D\xA7\x20\xC0\x2F\x11\xCE\x92\x7B\x08\x00\x09\x5A\xE3\x40': 'OLE Package Object (may contain and run any file)',
        rb'\xF4\x14\xC2\x60\x6A\xC0\x11\xCF\xB6\xD1\x00\xAA\x00\xBB\xBB\x58': 'jscript.dll - JScript Language (ProgID: ECMAScript, JavaScript, JScript, LiveScript)',
        rb'\xF4\x75\x4C\x9B\x64\xF5\x4B\x40\x8A\xF4\x67\x97\x32\xAC\x06\x07': 'Microsoft Word Document (Word.Document.12)'}

    def determine_mimetype(self, helpers, data):
        """
        Determine the file type by the magic bytes/signatures.
        Returns a string indicating the file type ("ole"/"ooxml"/"rtf"/"pdf")

        """

        # https://www.garykessler.net/library/file_sigs.html
        try:
            if self.OLE == data[:len(self.OLE)]:
                helpers.raw_data += "[+] Mime type: Object Linking and Embedding (OLE) Compound File (CF)\n"
                return "ole"
            elif self.OOXML == data[:len(self.OOXML)]:
                helpers.raw_data += "[+] Mime type: Microsoft Office Open XML Format (OOXML) Document\n"
                return "ooxml"
            elif self.RTF == data[:len(self.RTF)]:
                helpers.raw_data += "[+] Mime type: RTF (Rich text format) word processing file - \"{\\rtf\"\n"
                return "rtf"
            elif self.PDF == data[:len(self.PDF)]:
                helpers.raw_data += "[+] Mime type: PDF document - \"%PDF-1.x\"\n"
                return "pdf"
        except TypeError:
            return 0

    def scan_for_obj_type(self, helpers, stream_name, data):
        """
        Scans an OLE object to identify its type using the CLSIDS dictionary

        """
        helpers.raw_data += "[+] Attempting to determine the object type\n"

        for clsid in self.CLSIDS:
            if re.findall(clsid, data):
                try:
                    print_string = "Object type: %s" % self.CLSIDS[clsid]
                    helpers.raw_data += print_string
                    helpers.raw_data += "\n"
                except Exception:
                    print_string = "Object type: %s" % self.CLSIDS[clsid]
                    helpers.raw_data += print_string
                    helpers.raw_data += "\n"
                    self.add_summary_if_no_duplicates(print_string, stream_name)
                else:
                    self.add_summary_if_no_duplicates(print_string, stream_name)

    def deduplicate_table(self, string, summary_string):
        """
        Removes duplicates from the final summary table

        """
        no_duplicates = True
        temp1 = list(self.summary_table.rows)
        for row in temp1:
            for c in row:
                try:
                    if string in c:
                        no_duplicates = False
                except TypeError:
                    continue
        return no_duplicates

    def add_summary_if_no_duplicates(self, summary, desc):
        """
        Adds a new row to the summary table if it does not exist in it already.
        It is the only function that adds rows to the final summary table.

        """
        no_duplicates = self.deduplicate_table(desc, summary)
        if no_duplicates:
            self.summary_table.rows.append([summary, desc])
            json_data = {summary: desc}
            self.json_report["findings"].update(json_data)

    def search_indicators_in_string(self, helpers, filename, string):
        """
        Scans a string against multiple known keywords to extract more indications in the analysis report and
        summary table.

        """

        no_duplicates = True

        if "URLMON" in string or "urlmon" in string or "loadToFile" in string:
            if '\x01' in filename:
                clean_filename = filename.strip('\x01')
                summary_string = "Indication of file download in extracted strings from: %s" % clean_filename.strip(
                    '\x01')
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
            else:
                summary_string = "Indication of file download in extracted strings from: %s" % filename
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"

            self.add_summary_if_no_duplicates(summary_string, string)

        if ("http:" in string or "https:" in string) and "crl" not in string and "thawte" not in string and \
                "verisign" not in string and "symantec" not in string and \
                "ocsp" not in string and "openxml" not in string and \
                "theme" not in string and "schema" not in string and \
                "microsoft" not in string:
            if '\x01' in filename:
                clean_filename = filename.strip('\x01')
                summary_string = "URL found in extracted strings, from: %s" % clean_filename
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
            else:
                summary_string = "URL found in extracted strings, from: %s" % filename.strip('\x01')
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"

            self.add_summary_if_no_duplicates(summary_string, string)

        if "CreateFile" in string or "CreateDirectory" in string:
            if '\x01' in filename:
                clean_filename = filename.strip('\x01')
                summary_string = "Indication of file creation in extracted strings, from: %s" % "".join(
                    clean_filename.strip('\x01'))
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
            else:
                summary_string = "Indication of file creation in extracted strings, from: %s" % "".join(
                    filename.strip('\x01'))
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"

            self.add_summary_if_no_duplicates(summary_string, string)

        if "ShellExecute" in string or "Shell32.Shell" in string or "cmd /c" in string or "powershell" in string:
            if '\x01' in filename:
                clean_filename = filename.strip('\x01')
                summary_string = "Indication of shell command execution in file:@ %s" % "".join(
                    clean_filename.strip('\x01'))
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
            else:
                summary_string = "Indication of shell command execution in file: %s" % "".join(filename.strip('\x01'))
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"

            self.add_summary_if_no_duplicates(summary_string, string)

        if (".exe" in string or
            ".EXE" in string or
            ".exe" in string or
            ".sct" in string or
            ".ocx" in string or
            ".php" in string or
            "ProgramData" in string or
            "Desktop" in string or
            "Downloads" in string or
            "C:\\Users" in string or
            ".com" in string or
            ".ocx" in string or
            ".hta" in string or
            ".tmp" in string or
            ".dat" in string or
            ".txt" in string or
            re.findall(r"[a-z]+\.[a-z]", string)) and \
                "theme" not in string and \
                "_rels" not in string and \
                "openxml" not in string and \
                "theme" not in string and \
                "schema" not in string and \
                "crl" not in string and \
                "thawte" not in string and \
                "verisign" not in string and \
                "symantec" not in string and \
                "ocsp" not in string and \
                "openxml" not in string and \
                "theme" not in string and \
                "schema" not in string and \
                "java" not in string and \
                "Java" not in string and \
                "jvm" not in string and \
                "mscoree.dll" not in string and \
                "kernel32.dll" not in string and \
                "gdiplus32.dll" not in string and \
                "gdiplus.dll" not in string and \
                "advapi32.dll" not in string and \
                "native" not in string and \
                "microsoft" not in string:

            if "Ole10Native" in filename:
                summary_string = "Suspicious file path or possible domain found in: %s" % filename.strip('\x01')
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
            else:
                summary_string = "Suspicious file path or possible domain found in: %s" % "".join(
                    filename.strip('\x01'))
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
            if no_duplicates and len(string) < 100:
                self.add_summary_if_no_duplicates(summary_string, string)

        if "This program" in string or "DOS mode" in string:
            if "Ole10Native" in filename:
                summary_string = "Possible PE (Portable Executable) payload in stream: %s" % filename.strip('\x01')
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
                self.add_summary_if_no_duplicates(summary_string, string)

            else:
                summary_string = "Possible PE (Portable Executable) payload in stream: %s" % "".join(
                    filename.strip('\x01'))
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
                self.add_summary_if_no_duplicates(summary_string, string)

        #eq = re.findall(self.equation_regex, string)
        #if eq:
        #    if "Ole10Native" in filename:
        #        summary_string = "Possible Equation Editor exploit: " % filename.strip('\x01')
        #        helpers.raw_data += summary_string
        #        helpers.raw_data += "\n"
        #        self.add_summary_if_no_duplicates(summary_string, string)
        #    else:
        #        summary_string = "Possible Equation Editor exploit: %s" % "".join(filename.strip('\x01'))
        #        helpers.raw_data += summary_string
        #        helpers.raw_data += "\n"
        #        self.add_summary_if_no_duplicates(summary_string, string)

    def find_susp_functions_vba(self, helpers, filename, decompressed):
        """
        Scans decompressed VBA projects for known function keywords to provide nore insight on the code behavior.

        """

        if "Auto_Open" in decompressed or "Document_Open" in decompressed:
            summary_string = "VBA macro auto execution: Auto_Open()/Document_Open() found in: %s" % "\\".join(filename)
            summary_desc = "%s: Auto_Open()/Document_Open() - will execute VBA code when doc is opened" % "\\".join(
                filename)
            unified = summary_string + summary_desc
            helpers.raw_data += unified
            helpers.raw_data += "\n"

            self.add_summary_if_no_duplicates(summary_string, summary_desc)

        if "Auto_Close" in decompressed:
            summary_string = "VBA macro:@ Auto_Close() in: %s" % str("\\".join(filename))
            summary_desc = "%s: Auto_Close() - will execute VBA code when doc is closed" \
                           % "\\".join(filename)
            unified = summary_string + summary_desc
            helpers.raw_data += unified
            helpers.raw_data += "\n"
            self.add_summary_if_no_duplicates(summary_string, summary_desc)

        if "Shell(" in decompressed or "WScript.Shell" in decompressed:
            summary_string = "VBA macro: the code invokes the shell (Shell()\Wscript.Shell) in:@ %s" % \
                             str("\\".join(filename))
            summary_desc = "%s: Shell() - Macro code will invoke the shell to execute code" \
                           % "\\".join(filename)
            unified = summary_string + summary_desc
            helpers.raw_data += unified
            helpers.raw_data += "\n"
            self.add_summary_if_no_duplicates(summary_string, summary_desc)

        if "http" in decompressed:
            summary_string = "VBA macro: URL found in: %s" % str("\\".join(filename))
            self.add_summary_if_no_duplicates(summary_string, re.findall(r'http[s]{0,1}\:\/\/.*\..*\/.*\"',
                                                                         decompressed)[0])
            helpers.raw_data += summary_string
            helpers.raw_data += "\n"

    def find_susp_functions_xlm(self, helpers, filename, decompressed):
        """
        Scans XLM macros in sheets for known function keywords to provide nore insight on the code behavior.

        """

        if "HALT()" in decompressed or "RETURN(" in decompressed or "EXEC()" in decompressed or \
                "WRITE(" in decompressed or "FOR(" in decompressed or "FOR(" in decompressed or \
                "FORMULA(" in decompressed:
            summary_string = "Excel 4.0 (XLM) macro\n XLM macro functions detected in: %s" % \
                             "\\".join(filename.strip('\x01'))
            summary_desc = decompressed[:150]
            unified = summary_string + summary_desc
            helpers.raw_data += unified
            helpers.raw_data += "\n"
            self.add_summary_if_no_duplicates(summary_string, summary_desc)


class VBADecompress:
    '''
    The code of the class methods was taken from oledump by Didier Stevens:
    https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py

    '''

    def __init__(self, data):
        self.data = data

    def MacrosContainsOnlyAttributesOrOptions(self, stream):
        lines = self.SearchAndDecompress(stream).split('\n')
        for line in [line.strip() for line in lines]:
            if line != '' and not line.startswith('Attribute ') and not line == 'Option Explicit':
                return False
        return True

    def P23Ord(self, value):
        if type(value) == int:
            return value
        else:
            return ord(value)

    def ParseTokenSequence(self, data):
        flags = self.P23Ord(data[0])
        data = data[1:]
        result = []
        for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            if len(data) > 0:
                if flags & mask:
                    result.append(data[0:2])
                    data = data[2:]
                else:
                    result.append(data[0])
                    data = data[1:]
        return result, data

    def OffsetBits(self, data):
        numberOfBits = int(math.ceil(math.log(len(data), 2)))
        if numberOfBits < 4:
            numberOfBits = 4
        elif numberOfBits > 12:
            numberOfBits = 12
        return numberOfBits

    def Decompress(self, compressedData, replace=True):
        if self.P23Ord(compressedData[0]) != 1:
            return (False, None)
        remainder = compressedData[1:]
        decompressed = ''
        while len(remainder) != 0:
            decompressedChunk, remainder = self.DecompressChunk(remainder)
            if decompressedChunk == None:
                return (False, decompressed)
            decompressed += decompressedChunk
        if replace:
            return (True, decompressed.replace('\r\n', '\n'))
        else:
            return (True, decompressed)

    def DecompressChunk(self, compressedChunk):
        if len(compressedChunk) < 2:
            return None, None
        header = self.P23Ord(compressedChunk[0]) + self.P23Ord(compressedChunk[1]) * 0x100
        size = (header & 0x0FFF) + 3
        flagCompressed = header & 0x8000
        data = compressedChunk[2:2 + size - 2]

        if flagCompressed == 0:
            return data.decode(errors='ignore'), compressedChunk[size:]

        decompressedChunk = ''
        while len(data) != 0:
            tokens, data = self.ParseTokenSequence(data)
            for token in tokens:
                if type(token) == int:
                    decompressedChunk += chr(token)
                elif len(token) == 1:
                    decompressedChunk += token
                else:
                    if decompressedChunk == '':
                        return None, None
                    numberOfOffsetBits = self.OffsetBits(decompressedChunk)
                    copyToken = self.P23Ord(token[0]) + self.P23Ord(token[1]) * 0x100
                    offset = 1 + (copyToken >> (16 - numberOfOffsetBits))
                    length = 3 + (((copyToken << numberOfOffsetBits) & 0xFFFF) >> numberOfOffsetBits)
                    copy = decompressedChunk[-offset:]
                    copy = copy[0:length]
                    lengthCopy = len(copy)
                    while length > lengthCopy:  # a#
                        if length - lengthCopy >= lengthCopy:
                            copy += copy[0:lengthCopy]
                            length -= lengthCopy
                        else:
                            copy += copy[0:length - lengthCopy]
                            length -= length - lengthCopy
                    decompressedChunk += copy
        return decompressedChunk, compressedChunk[size:]

    def SkipAttributes(self, text):
        oAttribute = re.compile('^Attribute VB_.+? = [^\n]+\n')
        while True:
            oMatch = oAttribute.match(text)
            if oMatch == None:
                break
            text = text[len(oMatch.group()):]
        return text

    def FindCompression(self, data):
        return data.find(b'\x00Attribut\x00e ')

    def SearchAndDecompressSub(self, data):
        position = self.FindCompression(data)
        if position == -1:
            return (False, '')
        else:
            compressedData = data[position - 3:]
        return self.Decompress(compressedData)

    def SearchAndDecompress(self, data, skipAttributes=False):
        result, decompress = self.SearchAndDecompressSub(data)
        if result:
            if skipAttributes:
                return self.SkipAttributes(decompress)
            else:
                return decompress
        else:
            return 0


class OLEParser:
    """
    The OLEParser class will parse an OLE object and conduct an extensive static analysis on its streams/storages.
    Extracts VBA, embedded objects, Excel 4 macros, strings, and more.
    Can detect Equation Editor exploits.

    Has a dedicated parser for OLE Excel files (XLSParser())
    - Parse BOF records (Beginning of File headers)
    - Parse BOUNDSHEET records (sheets)
    - Detect hidden sheets via BOUNDSHEET records
    - Detect if a sheet has XLM macros via BOUNDSHEET records
    - Extract strings from sheets.
    - Extract Shared Strings Table strings.

    """

    def __init__(self, data):
        self.data = data

    def parse_cfb_header(self, helpers, data):
        """
        https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml

        CFB header:
        Header Signature for the CFB format with 8-byte Hex value D0CF11E0A1B11AE1. Gary Kessler notes that the
        beginning of this string looks like "DOCFILE".

        CFB header (Compund File Binary)
          -  16 bytes of zeroes
          -  2-byte Hex value 3E00 indicating CFB minor version 3E
          -  2-byte Hex value 0300 indicating CFB major version 3 or value 0400 indicating CFB major version 4. [Note:
          All XLS files created recently by compilers of this resource (in versions of Excel for MacOS and Windows) and
          examined with a Hex dump utility have been based on CFB major version 3. Comments welcome.]
          -  2-byte Hex value FEFF indicating little-endian byte order for all integer values. This byte order applies
           to all CFB files.
          -  2-byte Hex value 0900 (indicating the sector size of 512 bytes used for major version 3) or 0C00
          (indicating the sector size of 4096 bytes used for major version 4)
          -  480 bytes for remainder of the 512-byte header, which fills the first sector for a CFB of major version 3
          -  For a CFB of major version 4, the rest of the first sector, 3,584 bytes of zeroes

        """
        # Prepare CFB header table.
        cfb_table = BeautifulTable(maxwidth=100)
        cfb_table.headers = (["Field", "Value"])

        # Carve CFB header magic bytes from data.
        cfb_header = data[:8]
        cfb_table.rows.append(["CFB Header magic", cfb_header])

        # Parse CFB header minor version
        cfb_minor_version = data[24:26]
        if str(binascii.hexlify(cfb_minor_version)) == "3E00":
            cfb_table.rows.append(["CFB Minor Version", "Version 3E / 0x3E)" + str(cfb_minor_version)])

        # Parse CFB header major version
        cfb_major_version = data[26:28]
        if str(binascii.hexlify(cfb_major_version)) == "3000":
            cfb_table.rows.append(["CFB Major Version", "(Version 3 / 0x3)" + str(cfb_major_version)])

        if cfb_major_version == b'\x03\x00':
            cfb_table.rows.append(["CFB Minor Version", "Little-endian integers (0x3)"])

        # Parse CFB sector size.
        sector_size = data[30:32]
        if sector_size == b'\x09\x00':
            cfb_table.rows.append(["CFB sector length", "512 bytes"])
            cfb_table.rows.append(["CFB sector remainder size", "480 bytes - in major version 3 (512 -32)"])

        elif sector_size == b'\x0c\x00':
            # remainder = data[32:4096]  # in major version 4 (512 + 3,584).
            cfb_table.rows.append(["CFB sector length", "4096 bytes"])
            cfb_table.rows.append(["CFB sector remainder size", "4,064 bytes - in major version 3 (4096 -32)"])

        # Prepare and print CFB header table.
        cfb_table.columns.alignment = BeautifulTable.ALIGN_LEFT
        print(cfb_table)
        helpers.raw_data += str(cfb_table)

    def extract_embedded_ole(self, helpers, stream_name, fname):
        """
        The main method of OLEParser().
        Executes all OLE related analysis methods

        """
        stream_table = BeautifulTable()
        stream_table.headers = (["Stream", "Comments"])
        stream_table.maxwidth = 500

        try:
            # Parse input file as OLE to analyze its streams/storages.
            try:
                ole = olefile.OleFileIO(fname)
            except TypeError as e:
                return

            # Read input file data.
            f = open(fname, "rb")
            file_data = f.read()

            # Iterate over each stream in the OLE file.
            for stream in ole.listdir():
                # Check if document is protected.
                if 'StrongEncryptionDataSpace' in stream or "Encryption" in stream or "EncryptedPackage" in stream:
                    self.decrypt_cdfv2(helpers, fname)

                # Open current stream and read its data.
                ole_stream = ole.openstream(stream)
                stream_data = ole_stream.read()

                # Search for Equation Editor fingerprints.
                self.eqnedt32_detect(helpers, stream, stream_data, file_data)

                # Look and process embedded/internal files.
                self.inline_ole(helpers, stream, stream_data)

                for s in stream:
                    if str(s) not in stream[:len(stream) - 1]:
                        # Extract and decompress VBA macros from stream data.
                        decompress_obj = VBADecompress(stream_data)
                        decompressed = decompress_obj.SearchAndDecompress(stream_data)

                        if decompressed == 0:
                            # Nothing was decompressed, no VBA macros in stream.
                            # Ignore default/special streams.
                            if "CompObj" not in s and "Summary" not in s:
                                # Create temp file for analysis.
                                #f = open("test.bin", "ab")
                                #f.write(stream_data)
                                # #print("\n[+] Extracting generic strings from stream: %s" % s)

                                # Extract strings from stream.
                                self.extract_unicode_and_ascii_string(helpers, s, stream_data)
                                f.close()

                        else:
                            # VBA macros were detected.
                            # VBA macros output filename.
                            outfile_name = s + "_vbamacros"

                            # Prepare content for printing and tables.
                            print_string = "Found VBA macros in stream \'%s\'@\n---------\n%s" % (str("\\".join(stream)), decompressed)
                            helpers.raw_data += print_string
                            helpers.raw_data += "\n"

                            summary_string = "Found VBA macros in stream \'%s\\%s\'" % (
                            str(stream_name), str("\\".join(stream)))
                            helpers.raw_data += summary_string
                            helpers.raw_data += "\n"

                            # Scan macros code against known function names and keywords.
                            helpers.find_susp_functions_vba(helpers, stream, decompressed)

                            # Add VBA macros indication to final summary table.
                            helpers.add_summary_if_no_duplicates(summary_string, decompressed[:100])

                            # Add indication to analysis report stream table.
                            stream_table.rows.append([str("\\".join(stream)), print_string])
                            f.close()
                    else:
                        f.close()
                        continue
            f.close()
            stream_table.columns.alignment = BeautifulTable.ALIGN_LEFT
            helpers.raw_data += str(stream_table)

        except OSError:
            pass

    def eqnedt32_detect(self, helpers, stream, stream_data, file_data):
        """
        Detect Equation Editor exploit:
        - Scans objects for Equation object CLSID.
        - Scans for Equation known keywords.

        """
        eqedit32 = re.findall(helpers.EQ_EDIT_CLSID_RE, stream_data)
        equation_editor = re.findall(helpers.EQUATION_EDITOR_RE, stream_data)

        if (eqedit32 or equation_editor) and len(stream_data) > 50:
            # #print("[!] Indication of Equation Editor exploit detected in stream: % s " % "".join(stream)[1:].strip('\x01'))
            # md = Cs(CS_ARCH_X86, CS_MODE_32)
            if bool(eqedit32) and bool(equation_editor):
                summary_string = "Detected Equation Editor CLSID\n"
                summary_desc = 'Equation Editor\n%s\nPossible exploitation of CVE-2017-11882 in stream: %s\n' \
                               '%s\nCLSID: %s' % (
                               "".join(stream).strip('\x01'), stream, equation_editor[0], eqedit32[0])
                unified = summary_string + summary_desc
                helpers.raw_data += unified
                helpers.raw_data += "\n"
                helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            elif eqedit32:
                summary_string = "Indication of Equation Editor CLSID.\n Possible exploitation of CVE-2017-11882 in " \
                                 "stream: %s" % stream
                summary_desc = 'Equation Editor\n\'%s\'' % "".join(stream).strip('\x01')
                unified = summary_string + summary_desc
                helpers.raw_data += unified
                helpers.raw_data += "\n"
                helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            elif equation_editor:
                summary_string = "Detected Equation Editor CLSID.\n Possible exploitation of CVE-2017-11882 in " \
                                 "stream: %s\n\'%s\'" % \
                                 (stream, equation_editor[0])
                summary_desc = 'Equation Editor\n\'%s\'' % "".join(stream).strip('\x01')
                helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            # if "CompObj" not in "".join(stream):
            # #print("[!] Possible Equation Editor exploit in stream: %s" % "".join(stream).strip('\x01'))

            # #print("\nDisassembly: %s\n--------------------------" % ("".join(stream)))
            # disassembly = md.disasm(stream_data, 0x00)

            # for i in disassembly:
            #    if i.mnemonic is "jmp" and int(i.op_str, 16) < 4096:
            #        #print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            #    else:
            #        #print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    def extract_unicode_and_ascii_string(self, helpers, filename, data):
        """
        Extract ASCII and wide char strings.

        """
        unicode_final_decoded = ''
        ascii_final_decoded = ''

        # wide char string matches.
        unicode_matches = re.findall(helpers.unicode_regex, data)

        # ASCII string matches.
        ascii_matches = re.findall(helpers.ascii_regex, data)

        # Join all strings into one string.
        for match in unicode_matches:
            unicode_final_decoded += match.decode('utf-8')
            helpers.raw_data += match.decode('utf-8')
            helpers.raw_data += "\n"

        # split strings properly.
        splitted_strings = unicode_final_decoded.split(" ")

        for match in ascii_matches:
            ascii_final_decoded += match.decode('utf-8')
            helpers.raw_data += match.decode('utf-8')
            helpers.raw_data += "\n"

            if len(match.decode('utf-8')) > 8:

                if len(match) > 500:
                    helpers.search_indicators_in_string(helpers, filename, match.decode('utf-8')[:1000])
                else:
                    helpers.search_indicators_in_string(helpers, filename, match.decode('utf-8'))
        # Print final ASCII strings.
        if len(ascii_final_decoded) > 2000:
            helpers.raw_data += ascii_final_decoded[:1000]
            helpers.raw_data += "\n"
        else:
            helpers.raw_data += unicode_final_decoded
            helpers.raw_data += "\n"

        # Search base64 encoded strings.
        base64_matches = re.findall(helpers.base64_regex, ascii_final_decoded)
        if base64_matches:
            summary_desc = []

            for m in base64_matches:
                if len(m) > 50:
                    summary_desc.append(m)
                    helpers.raw_data += str(m)

            if summary_desc:
                summary_string = "[!] Possible Base64 encoded strings found in stream"
                helpers.raw_data += summary_string
                helpers.raw_data += "\n"
                helpers.add_summary_if_no_duplicates(summary_string, summary_desc[:20])

    def inline_ole(self, helpers, stream, stream_data):

        if len(stream_data):

            ole_regex = rb'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
            MICROSOFT_EXCEL = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x78\x63\x65\x6c'
            MICROSOFT_OFFICE_WORD = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x4f\x66\x66\x69\x63\x65\x20\x57\x6f\x72\x64'
            WORD_DOCUMENT = b'\x57\x6F\x72\x64\x2E\x44\x6F\x63\x75\x6D\x65\x6E\x74'

            if re.findall(ole_regex, stream_data):
                helpers.raw_data += "\n\n[!!!] Found OLE file %s!\n" % str("\\".join(stream))
                summary_string = "Found OLE file %s\n" % str("\\".join(stream))
                summary_desc = "Embedded OLE file\n%s" % str("\\".join(stream))
                unified = summary_string + " " + summary_desc
                helpers.raw_data += unified
                helpers.raw_data += "\n"
                helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                self.parse_cfb_header(helpers, stream_data)

                with open("temp.bin", "ab") as f:

                    f.write(stream_data)
                    self.extract_embedded_ole(helpers, str("\\".join(stream)), f.name)
                    if MICROSOFT_EXCEL in stream_data:
                        xls_parser = XLSParser(stream_data)
                        xls_parser.parse_boundsheet_record(helpers, stream_data)
                        xls_parser.parse_bof_records(helpers, stream_data)
                        xls_parser.extract_sheets(helpers, f.name)
                        decompress_obj = VBADecompress(stream_data)
                        decompressed = decompress_obj.SearchAndDecompress(stream_data)
                        xls_parser.parse_sst(helpers, stream_data)
                        f.close()
                        os.remove(f.name)
                        helpers.raw_data += "\n\n[+] Continuing original file analysis:\n" + ("=" * 50) + "\n"

                    elif MICROSOFT_OFFICE_WORD in stream_data or WORD_DOCUMENT in stream_data:
                        doc_parser = DocParser(stream_data)
                        helpers.raw_data += "\n\n[+] Continuing original file analysis:\n" + ("=" * 50) + "\n"
                        pass
        else:
            pass

    def decrypt_cdfv2(self, helpers, filename):

        file = msoffcrypto.OfficeFile(open(filename, "rb"))

        # Use password (default password)
        file.load_key(password="VelvetSweatshop")
        decrypted_outfile = "DECRYPTED"

        try:
            file.decrypt(open(decrypted_outfile, "wb"))
            helpers.raw_data += "Used default password: VelvetSweatshop\n"
            helpers.raw_data += "Saved decrypted document to file: %s\n" % decrypted_outfile
            helpers.raw_data += "Please check the decrypted file, rerun the tool and use the decrypted file\n"
            exit(0)
        except msoffcrypto.exceptions.InvalidKeyError:
            helpers.raw_data += "[-] Could not decrypt protected document - password is not the default...\nRun the document in a sandbox"
            exit(0)
            return


class XLSParser:
    """
    The XLSParser() class is a helper class for the OLEParser class.
    It specifically handles OLE Excel files, as those have additional parsing and logic that needs to be applicaed
    to fully parse/analyze the file.

    The class will:
    - Parse BOF records (Beginning of File headers)
    - Parse BOUNDSHEET records (sheets)
    - Detect hidden sheets via BOUNDSHEET records
    - Detect if a sheet has XLM macros via BOUNDSHEET records
    - Extract strings from sheets.
    - Extract Shared Strings Table strings.

    """

    def __init__(self, data):
        self.data = data

    # Used later for XLM macro methods.
    xlm_flag = None
    # Used later for hidden sheet detection.
    hidden_sheet_flag = None

    # Assign bas BoF record offset with temporary integer value.
    base_bof_record = 0

    def strings(self, filename, min=7):
        """
        UNIX strings implementation in python
        https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility
        """
        with open(filename, errors="ignore") as f:  # Python 3.x
            # with open(filename, "rb") as f:       # Python 2.x
            result = ""
            for c in f.read():
                if c in string.printable:
                    result += c
                    continue
                if len(result) >= min:
                    yield result
                result = ""
            if len(result) >= min:  # catch result at EOF
                yield result

    def parse_base_bof_offset(self, helpers, data):

        # Save the offset of the base BoF record.
        base_bof_record = re.search(helpers.BOF_RECORD_RE, data)
        # Return BoF record offset (start offset)
        return base_bof_record.start()

    def parse_base_bof_record(self, helpers, data, bof_table):
        """
        https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml

        BoF (beginning of file) record for the mandatory Workbook Globals Substream, which must be the first substream
        in a BIFF8 XLS file:
          -  2-byte BoF record number field. Hex value 0908. 09 indicates a BoF record. 08 indicates the BIFF version.
          -  2 bytes unspecified
          -  BoF record data, starting with 2-byte Hex value 0006, indicating BIFF8
          -  2-byte Hex value 0500, indicating that the substream stream for which this is the record data is the
          mandatory Workbook Globals Substream
        """
        # Parse base BoF record as the start offset of all other BoF records (aligned one after the other).
        self.base_bof_record = self.parse_base_bof_offset(helpers, data)

        # Add base BoF offset to BoF table
        bof_table.rows.append(["Offset in file", str(hex(self.base_bof_record))])

        # Parse BoF chunk size (of the entire file)
        bof_chunk_size = len(data[self.base_bof_record:re.search(helpers.EOF_BOF,
                                                                 data[self.base_bof_record:]).start() + 4])
        # Add base BoF block size to BoF table.
        print_string = "%d bytes" % bof_chunk_size
        bof_table.rows.append(["BOF file chunk size", print_string])

        # Parse BoF record length
        biff_header_length = struct.unpack("<H", data[self.base_bof_record + 2:self.base_bof_record + 4])[0]

        # Add BoF record length to BoF table.
        bof_table.rows.append(["BOF record length", str(biff_header_length)])

        # Parse BIFF version of the file.
        biff_version = data[self.base_bof_record + 5:self.base_bof_record + 6]

        # The carved bytes from the BoF record will be parsed in the check_biff_version method.
        self.check_biff_version(helpers, biff_version, bof_table)

        # Parse the XLM flag.
        xlm = data[self.base_bof_record + 6]

        # Parse and check the XLM flag.
        self.check_xlm_flag_in_bof(helpers, xlm, bof_table)

        # Extract all following BoF records using regex.
        # The regex scans the data starting from the end of the base BoF (end of first file).
        bof_headers = re.findall(helpers.BOF_RECORD_RE, data[self.base_bof_record:])

        # Return a list of BoF records and the offset of the base BoF record.
        return bof_headers, self.base_bof_record

    def parse_rest_of_bofs(self, helpers, data, bof_table, bof_headers, position):
        """
        https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml

        BoF (beginning of file) record for the mandatory Workbook Globals Substream, which must be the first substream
        in a BIFF8 XLS file:
          -  2-byte BoF record number field. Hex value 0908. 09 indicates a BoF record. 08 indicates the BIFF version.
          -  2 bytes unspecified
          -  BoF record data, starting with 2-byte Hex value 0006, indicating BIFF8
          -  2-byte Hex value 0500, indicating that the substream stream for which this is the record data is the
          mandatory Workbook Globals Substream
        """

        for i in range(1, len(bof_headers)):

            # Get offset of bof record in relation to the base BoF record offset
            loc = re.search(bof_headers[i], data[position:])

            if loc:

                # Calculate base BoF's end offset to determine the start of the second record.
                bof_offset_record_end = position + loc.start() + 12

                # Calculate the end offset of the current BoF record.
                end_of_bof = re.search(helpers.EOF_BOF, data[bof_offset_record_end:])

                if not end_of_bof:
                    # if BoF end of file record was not found, it is the last record.
                    end_offset = len(data)
                else:
                    # Else, calculate the end offset for the current BoF file (end of file / EOF).
                    end_offset = end_of_bof.end() + bof_offset_record_end

                # After BoF chunk start and end offsets are calculated, the BoF record is parsed
                helpers.raw_data += "\nBOF (Beginning of File) record:\n"

                # Add record offset as new row to final summary table.
                bof_table.rows.append(["Offset in file", str(hex(bof_offset_record_end - 12))])

                # Calculate BoF chunk size (entire file)
                bof_chunk_size = end_offset - bof_offset_record_end
                # Add chunk size as new row to final summary table.
                bof_table.rows.append(["BOF file block size", str(bof_chunk_size)])

                # Parse BIFF header length.
                biff_header_length = struct.unpack("<H", data[bof_offset_record_end + 2:bof_offset_record_end + 4])[0]
                bof_table.rows.append(["BOF record length", str(biff_header_length)])

                # Parse BIFF version bytes.
                biff_version = data[data.find(bof_headers[i]) + 5:data.find(bof_headers[i]) + 6]
                # Determine BIFF version by cheking byte values.
                self.check_biff_version(helpers, biff_version, bof_table)

                # Parse XLM byte from record.
                xlm = data[bof_offset_record_end - 6]

                # Determine XLM 4 macros existence by checking byte values.
                self.check_xlm_flag_in_bof(helpers, xlm, bof_table)

                # Used to calculate the next BoF's end offset in the nex iteration.
                position = bof_offset_record_end + 12

                # Prepare and print BoF table.
                bof_table.columns.alignment = BeautifulTable.ALIGN_LEFT
                # #print(bof_table)
                #helpers.raw_data += str(bof_table)

                # Clear table for next record.
                bof_table.clear()

            else:
                helpers.raw_data += "failed getting BOF header location, fix regex...\n"

    def parse_bof_records(self, helpers, data):
        """
        Wraps all functions related to BoF records parsing.
        First parses the base BoF record offset.
        then proceeds to the rest of the records.
        For each record it will print a table showing the record fields/values.

        """
        helpers.raw_data += "\nBOF (Begining of File) Records\n" + ("=" * 30) + "\n"
        helpers.raw_data += "\nBase BOF (Begining of File) record:\n"

        # create BoF table
        bof_table = BeautifulTable(maxwidth=100)

        # Parse base BoF record, return list of all other records.
        bof_headers, position = self.parse_base_bof_record(helpers, data, bof_table)

        # Prepare BoF table and print it.
        bof_table.columns.alignment = BeautifulTable.ALIGN_LEFT

        # BoF table for current record.
        helpers.raw_data += str(bof_table)

        # Clear the table for next BoF record.
        bof_table.clear()

        # After parsing the base BoF record, proceed to parsing all the rest.
        # The base BoF record offset is used to calculate offsets of following records.
        self.parse_rest_of_bofs(helpers, data, bof_table, bof_headers, position)

    def check_biff_version(self, helpers, biff_version_bytes, bof_table):
        """
        https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml

        BoF (beginning of file) record for the mandatory Workbook Globals Substream, which must be the first substream
        in a BIFF8 XLS file:
          -  2-byte BoF record number field. Hex value 0908. 09 indicates a BoF record. 08 indicates the BIFF version.
          -  2 bytes unspecified
          *  BoF record data, starting with 2-byte Hex value 0006, indicating BIFF8
          *  2-byte Hex value 0500, indicating that the substream stream for which this is the record data is the
          mandatory Workbook Globals Substream
        """

        # Hex value 0006, indicating BIFF 5/7
        if biff_version_bytes is b'\x05':
            bof_table.rows.append(["BIFF version", "5/7"])

        # Hex value 0006, indicating BIFF8
        elif biff_version_bytes is b'\x06':
            bof_table.rows.append(["BIFF version", "8"])

    def check_xlm_flag_in_bof(self, helpers, xlm_bytes, bof_table):
        """
        Checks for XLM 4 macros presence by checking the value in the parsed XLM flag from the BoF record.
        - 0x10 - BOF record is a WorkSheet
        - 0x05 - BOF record for mandatory Workbook Globals Substream
        - 0x40 - BOF of a substream that contains XLM Macros

        """
        # Hex value 0x40, indicating the sheet contains XLM 4 macros.
        if xlm_bytes is 0x40:
            self.xlm_flag = True

            # Prepare to add row to bof table.
            print_string = "XLM Macros"
            print_desc = "(XLM byte: 0x40) BOF of a substream that contains XLM Macros"
            bof_table.rows.append([print_string, print_desc])

            # Add row to final summary table.
            helpers.add_summary_if_no_duplicates(print_string, "XLM 4.0 macros found in sheets")

        # Add to table just for full parsing.
        elif xlm_bytes is 0x05:
            bof_table.rows.append(["XLM Macros", "(0x05) BOF record for mandatory Workbook Globals Substream"])

        # Add to table just for full parsing.
        elif xlm_bytes is 0x10:
            bof_table.rows.append(["XLM Macros", "(0x10) BOF record is a WorkSheet"])

    def carve_sheet_name(self, helpers, data, raw_record):
        """
        Carve sheet names when iterating over BOUNDSHEET records.
        Returns the sheet name.

        """
        if raw_record in data:
            loc = data.find(raw_record)
            sheet_chunk = data[loc:loc + 42]

            try:
                try:
                    sheet_name = re.findall(helpers.SHEET_NAME_1, sheet_chunk)[0]
                    clean_sheet_name = []

                    for byte in sheet_name:

                        if 31 < byte < 128:
                            clean_sheet_name += chr(byte)

                    name = "".join(clean_sheet_name)
                    return name

                except IndexError:
                    sheet_name = re.findall(helpers.SHEET_NAME_2,
                                            sheet_chunk)[0]
                    clean_sheet_name = []

                    for byte in sheet_name:
                        if byte > 12 and byte < 128:
                            clean_sheet_name += chr(byte)
                    name = "".join(clean_sheet_name)
                    return name

            except IndexError:
                return 0

    def parse_boundsheet_record(self, helpers, data):
        """
        Parse BOUNDSHEET records.
        https://www.loc.gov/preservation/digital/formats/digformatspecs/Excel97-2007BinaryFileFormat(xls)Specification.pdf

        """
        # #print("\nExcel Sheets (BoundSheet records):@\n" + "=" * 40)
        helpers.raw_data += "\nExcel Sheets (BoundSheet records):\n" + ("=" * 40) + "\n"

        # Parse base BoF record offset.
        base_bof_offset = self.parse_base_bof_offset(helpers, data)

        # Create sheets table.
        sheets_table = BeautifulTable(maxwidth=100)

        # Extract all BOUNDSHEET records.
        regex = re.compile(helpers.BOUNDHSEET_RECORD)
        boundsheet_records = re.findall(regex, data)
        i = 0

        for record in boundsheet_records:
            if record[3] is b"\x00" or (record[9] is b"\x00" or record[9] is b"\x01"):
                continue
            else:
                # get sheet name
                sheet_name = self.carve_sheet_name(helpers, data, record)

                # Loop exit flag.
                # If the BoF is the last record, it is set to True.
                # The function will also parse the record and extract findings.
                flag = self.handle_sheet_parsing(helpers, i, sheet_name, record, base_bof_offset, data, boundsheet_records,
                                                 sheets_table)
                if flag:
                    break
                i += 1
                if i > len(boundsheet_records):
                    break
                else:
                    break

        # If hidden flag is True, add to summary table.
        if self.hidden_sheet_flag:
            print_string = "Hidden sheets detected in workbook"
            helpers.add_summary_if_no_duplicates(print_string,
                                                      "Hidden sheets usually hide malicious strings/XLM macros")

    def handle_sheet_parsing(self, helpers, i, sheet_name, record, base_bof_offset, data, boundsheet_records, sheets_table):
        """
        Parses a sheet, using a provided sheet name, base BoF offset, data and carved BOUNDSHEET records.
        For each sheet it will create a table with the parsed record fields/values.

        """
        # exit flag
        flag = False

        # Check if sheet name os not None and validate input.
        if sheet_name and not re.search('[\\\/\?\*\[\]]', sheet_name):

            # flag that states whether current sheet is the last sheet.
            last_sheet = False

            # Parse sheet's BoF record offset.
            sheet_bof_offset = struct.unpack('<I', record[4:8])[0] + base_bof_offset

            # Check if the BoF record is not out of range and not to small.
            if sheet_bof_offset > len(data) or sheet_bof_offset < 512:
                flag = True
                return True

            try:
                # Calculate next BOUNDSHEET record offset.
                next_record = re.search(boundsheet_records[i + 1], data)

                # Check if next record offset is not None
                if next_record:
                    # Assign next BOUNDSHEET record offset to final variable
                    final_next_record = next_record.start()
                else:
                    # If next record offset could not be calculated, its the last sheet.
                    last_sheet = True
                    # Calculate end offset for sheet.
                    end_offset = re.search(helpers.EOF_BOF, data)
                    final_end_offset = end_offset.start() + 4

            except IndexError:
                # If boundsheet_records[i + 1] does not exist, its the last sheet.
                last_sheet = True
                # Calculate end offset for sheet.
                end_offset = re.search(helpers.EOF_BOF, data)
                final_end_offset = end_offset.start() + 4

            if last_sheet:
                # If this is the last sheet, the start of next sheet is actually the end of the file.
                next_sheet_offset = final_end_offset
            else:
                # Next sheet start offset is the end of the current sheet
                next_sheet_offset = final_next_record

            helpers.raw_data += "\nSheet Name: \'%s\'\n" % str(sheet_name)

            # Parse base BoF record offset
            base_bof_record = self.parse_base_bof_offset(helpers, data)

            # Add sheet's associated BoF record start offset to sheets table.
            sheets_table.rows.append(["Sheet associated BOF record start offset", str(hex(sheet_bof_offset))])

            # Carve sheet chunk from data.
            sheet_chunk = data[sheet_bof_offset:sheet_bof_offset + next_sheet_offset]

            # Calculate sheet size (start of next sheet - start of current sheet).
            sheet_size = hex(next_sheet_offset - sheet_bof_offset)
            sheets_table.rows.append(["Sheet size", str(sheet_size)])

            # Check if sheet is hidden.
            print_string = self.get_visible_flag(helpers, i, sheet_name, boundsheet_records)
            sheets_table.rows.append(["Sheet visibility", print_string])

            # Set hidden flag if sheet is HIDDEN or VERY HIDDEN.
            if "Sheet is hidden" in print_string or "Sheet is VERY hidden" in print_string:
                self.hidden_sheet_flag = True

            # Append an XLM 4 macros indication to the sheets table.
            print_string = self.detect_xlm_macros(helpers, i, boundsheet_records, sheet_name)
            sheets_table.rows.append(["Excel 4.0 Macros", print_string])

            # #print(hexdump.hexdump(sheet_chunk[:100]))

            # Prepare sheets table before printing.
            sheets_table.columns.alignment = BeautifulTable.ALIGN_LEFT
            helpers.raw_data += str(sheets_table)
            helpers.raw_data += "\n"

            # Clear sheets table for next record (each record is printed in a separate table).
            sheets_table.clear()

    def detect_xlm_macros(self, helpers, sheet_index, boundsheet_records, sheet_name):
        """
        Receives a sheet index number, BOUNDHSEET records and a sheet name.
        Pasrses the relevant XLM flag byte from the BOUNDSHEET record and compares it to known constants.
        Returns a string indicating whether XLM 4 macros is present.

        Constants:
        - 0x00 - no macros
        - 0x01 - Has XLM 4 macros

        """
        # Carve XLM flag byte from the boundsheet record.
        xlm_macros = boundsheet_records[sheet_index][9:10]

        # Check for Excel 4.0 XLM Macros.
        if xlm_macros == b"\x00":
            return "Sheet does not contain Excel 4.0 Macros\n"

        elif xlm_macros == b"\x01":
            return "Sheet contains Excel 4.0 Macros"

    def extract_sheets(self, helpers, fname):

        try:
            book = xlrd.open_workbook(fname)

            # #print("\nStrings from sheets:@" + "\n" + "=" * 20)
            helpers.raw_data += "\nStrings from sheets:" + "\n" + ("=" * 20) + "\n"

            for i in range(0, len(book.sheets())):
                helpers.raw_data += "\nSheet name: \"%s\"\n" % str(book.sheet_by_index(i).name)
                helpers.raw_data += "[+] Searching Excel 4.0 Macros (XLM) in sheet cells\n"

                # Print non-empty cells.
                for row in range(book.sheet_by_index(i).nrows):
                    for col in range(book.sheet_by_index(i).ncols):
                        cell_obj = book.sheet_by_index(i).cell(row, col)

                        if cell_obj.value is '':
                            continue
                        else:
                            helpers.raw_data += str(cell_obj.value)
                            helpers.raw_data += "\n"

                helpers.raw_data += "\n[+] Extracting generic strings from sheet: %s\n" % str(book.sheet_by_index(i).name)

                # strings implementation in python
                # https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility
                sl = list(self.strings(fname))

                # Print each string and scan it against known keywords/indicators.
                for s in sl:
                    if len(s) > 15:
                        helpers.raw_data += s
                        helpers.raw_data += "\n"
                        helpers.search_indicators_in_string(helpers, fname, s)

        except IndexError as e:
            helpers.raw_data += "\n[-] For some reason, failed to read data from the Excel sheets (\"xlrd.open_workbook(fname)\")....\n"
            pass

    def get_visible_flag(self, helpers, sheet_index, sheet_name, boundsheet_records):

        # Get sheet hidden flag.
        sheet_hidden = boundsheet_records[sheet_index][8:9]

        # Check if sheet is hidden.
        if int.from_bytes(sheet_hidden, "little") & 0x03 == 0x00:
            return "Sheet is visible"

        elif int.from_bytes(sheet_hidden, "little") & 0x03 == 0x01:
            return "Sheet is hidden"

        elif int.from_bytes(sheet_hidden, "little") & 0x03 == 0x02:
            return "Sheet is VERY hidden"

    def unhide_sheets(self, helpers, xls_file):

        # #print("\nUnhiding hidden sheets...")
        helpers.raw_data += "\nUnhiding hidden sheets...\n"
        data = xls_file.read()

        boundsheet_records = re.findall(helpers.BOUNDHSEET_RECORD, data)

        patched_name = ".\\clean\\patched_unhidden.xls"

        try:
            patched_file = open("patched_unhidden.xls", "xb")
        except FileExistsError:
            patched_file = open("patched_unhidden.xls", "r+b")

        patched_file.write(data)

        for record in boundsheet_records:

            loc = data.find(record)

            if record[len(record) - 2] is not 0:

                xls_file.seek(loc + 8)
                sheet_name = self.carve_sheet_name(helpers, data, record)
                helpers.raw_data += "Sheet: \"%s\" - Patching file at offset %s with \\x00 byte. Patched XLS file: %s" \
                                         % (str(sheet_name), str(hex(loc + 8)), patched_name)
                patched_file.write(b'\x00')

            else:
                continue
        xls_file.close()
        patched_file.close()

    def parse_sst(self, helpers, data):

        """
        https://www.openoffice.org/sc/excelfileformat.pdf

         Shared Strings Table Structure:
         -------------------------------
         Abs. stream offset Rel. rec. offset Contents    Description
         ----------------------------------------------------------------------------------------
         00020000H           0000H           00FCH       SST identifier
         00020002H           0002H           1000H       Size of the SST record
         00020004H           0004H           00000011H   Total number of strings in the document
         00020008H           0008H           00000011H   Number of unique strings following
         0002000CH           000CH           String 0    (total size = 0100H bytes)
         0002010CH           010CH           String 1    (total size = 0200H bytes)
         0002030CH           030CH           String 2    (total size = 0100H bytes)
         00020800H           0800H           String 8    (total size = 0100H bytes)
         00021004H           0000H           003CH       CONTINUE identifier
         00021006H           0002H           0320H       Size of the CONTINUE record
         00021008H           0004H                       Continuation of string 14 (size = 0020H bytes)
         00021028H           0024H                       String 15 (total size = 0100H bytes)
         00021128H           0124H                       String 16 (total size = 0200H bytes)
         00021328H           0000H           00FFH       EXTSST identifier
         0002132AH           0002H           001AH       Size of the EXTSST record
         0002132CH           0004H           0008H       8 strings in each portion
         0002132EH           0006H           0002000CH   Absolute stream position of string 0
         00021332H           000AH           000CH       Relative record position of string 0 (in SST)
         00021334H           000CH           0000H       Not used
         00021336H           000EH           00020800H   Absolute stream position of string 8
         0002133AH           0012H           0800H       Relative record position of string 8 (in SST)
         0002133CH           0014H           0000H       Not used
         0002133EH           0016H           00021128H   Absolute stream position of string 16
         00021342H           001AH           0124H       Relative record position of string 16 (in CONTINUE)
         00021344H           001CH           0000H       Not used
        """

        helpers.raw_data += "\nShared String Table (SST):\n"

        sst_table = BeautifulTable(maxwidth=100)
        sst_table.columns.alignment = BeautifulTable.ALIGN_RIGHT
        sst_table.headers = (["Field", "Value"])
        sst_table.rows.append(["Field", "Value"])

        sst_offset = re.search(rb'\xfc\x00[\x00-\xff]{2}', data)
        sst_sector_size = struct.unpack("<h", data[sst_offset.start() + 2:sst_offset.start() + 4])[0]

        if sst_sector_size > 0:

            sst_table.rows.append(["SST offset in file", str(hex(sst_offset.start()))])
            sst_table.rows.append(["SST sector size", str(sst_sector_size)])

            sst_strings_offset = sst_offset.start() + 12
            sst_table.rows.append(["SST strings offset", str(hex(sst_strings_offset))])

            sst_chunk = data[sst_strings_offset:sst_strings_offset + sst_sector_size]

            # carve each string by string length:
            test = sst_chunk[:3]

            sst_table.columns.alignment = BeautifulTable.ALIGN_LEFT
            helpers.raw_data += str(sst_table)

            try:
                str_length = struct.unpack("<hb", test)[0]

                helpers.raw_data += "Length of first string: %d" % str_length
                helpers.raw_data += "\n"
                first_string = sst_chunk[3:3 + str_length]
                try:
                    helpers.raw_data += first_string.decode('utf-8')
                    helpers.raw_data += "\n"

                except UnicodeDecodeError:
                    pass

                offset = 0
                while True:

                    curr_str_start = offset
                    try:
                        curr_str_start += str_length + 3
                        offset = curr_str_start

                        test = sst_chunk[offset:offset + 3]
                        str_length = struct.unpack("<hb", test)[0]

                        helpers.raw_data += "String Length: %d" % str_length
                        helpers.raw_data += "\n"

                        string = sst_chunk[offset + 3:offset + str_length + 3]
                        try:
                            helpers.raw_data += string.decode('utf-8')
                            helpers.raw_data += "\n"

                        except UnicodeDecodeError:
                            continue

                    except IndexError:
                        break

            except struct.error:
                return 0
        else:
            helpers.raw_data += "[-] Couldn't find a valid Shared Strings Table...\n"


class OOXMLParser:
    """
    The OOXML() class parses and analyzes Office Open XML documents.
    It specifically handles OLE Excel files, as those have additional parsing and logic that needs to be applicaed
    to fully parse/analyze the file.

    The class will:
    - Extract and read data from all XML and binary files in the OOXML zip container
    - Extract VBA macros
    - Extract and recursively analyze embedded objects (OLEParser/XLSParser)
    - Detect potential Equation Editor exploitation
    - Print sheet cells contents to a table
    - Extract strings from sheets
    - Extract Shared Strings Table strings
    - Detect DDE usage
    - Detect Office template injections
    - Detect URLs in external relationships
    - Detect ActiveX OLE objects and analyze them (OLEParser)
    - Detect potential exploitation of the MSHTML engine

    """
    binary_ooxml = False
    doc_type = ""

    def __init__(self,  data):
        self.data = data

    def zip_extrcat(self, helpers, filename):
        extract_path = "unzipped"
        # #print("\n- Extracting archive to: %s" % extract_path)
        zip = zipfile.ZipFile(filename)
        zip.extractall(extract_path)

        if helpers.my_os == "Windows":
            path = ".\\" + extract_path
        else:
            path = "./" + extract_path
        return path

    def list_archive_files(self, helpers, data, filename):

        path = self.zip_extrcat(helpers, filename)

        if helpers.my_os == "Windows":
            files = glob.glob(path + "**\\**\\**\\*.*", recursive=True)
        if helpers.my_os == "Linux":
            files = glob.glob(path + "**/**/**/*.*", recursive=True)
        files = list(dict.fromkeys(files))
        return files

    def detect_emb_ole(self, helpers, data, filename):

        files = self.list_archive_files(helpers, data, filename)
        helpers.raw_data += "\nOOXML Archive files:\n"
        for f in files:
            helpers.raw_data += str(f.replace(".\\unzipped", ""))
            if "\\word\\" in f:
                self.doc_type = "word"
            elif "\\xl\\" in f:
                self.doc_type = "excel"
            elif "\\ppt\\" in f:
                self.doc_type = "ppt"
            else:
                continue

        helpers.raw_data += "\nAnalyzing files in archive\n"
        indicators = BeautifulTable()
        indicators.headers = ["Indication", "Description"]
        indicators.columns.width = [50, 70]

        for file in files:

            with open(file, "rb") as file_handle:
                file_data = file_handle.read()

                if ".bin" in file or helpers.OLE_FILE_MAGIC in file_data[:len(helpers.OLE_FILE_MAGIC)]:
                    ms_ole = OLEParser(file_data)
                    self.parse_ole_file(helpers, file, ms_ole)
                    ms_ole.extract_embedded_ole(helpers, file, file)
                    file_handle.close()

                elif re.findall(r".*\.rels", file):
                    xml_data = open(file, "r").read()
                    reference = self.find_ext_references(helpers, xml_data, file)
                    if reference:
                        print_string = "External relationships in file: %s" % file
                        indicators.rows.append([print_string, reference])
                    #file_handle.close()

                elif re.findall(r".*sharedStrings.xml", file):
                    tree = ET.parse(file)
                    root = tree.getroot()
                    clean_sst_strings = []

                    for child in root:
                        for attrib in child:
                            if attrib.text is not None:
                                clean_sst_strings.append(attrib.text)

                    if clean_sst_strings:
                        print_line = "Shared Strings Table Strings"
                        indicators.rows.append([print_line, ", ".join(clean_sst_strings)])
                        helpers.add_summary_if_no_duplicates(print_line, ", ".join(clean_sst_strings))
                    #file_handle.close()

                elif "webSettings.xml" in file:
                    try:
                        xml_data = open(file, "r").read()
                        frame = re.findall(r'frame\" Target=\".*\" TargetMode=\"External\"\/\>\<\/Relationships\>',
                                           xml_data)

                        if frame:
                            print_line = "Detected external relationship to MSHTML frame in file: %s" % file.strip('\x01')
                            helpers.add_summary_if_no_duplicates(print_line, frame)
                        #file_handle.close()

                    except UnicodeDecodeError as e:
                        helpers.raw_data += "[-] Error reading %s: %s\n" % (str(file), str(e))
                        continue

                elif "document.xml" in file or "workbook.xml" in file:
                    try:
                        xml_data = open(file, "r").read()
                        dde_command = self.detect_dde(helpers, xml_data, file)
                        if dde_command:
                            print_line = "Detected DDE usage in file: %s" % file.strip('\x01')
                            indicators.rows.append([print_line, dde_command])
                            helpers.add_summary_if_no_duplicates(print_line, dde_command)

                        if "&lt" in xml_data:
                            possible_payload = re.findall(r">&lt(.*)", xml_data)
                            print_line = "Possible payload in file: %s" % file.strip('\x01')
                            indicators.rows.append([print_line, possible_payload])
                            helpers.add_summary_if_no_duplicates(print_line, possible_payload[:100])
                        #file_handle.close()

                    except UnicodeDecodeError as e:
                        #file_handle.close()
                        continue

                elif "macrosheets" in file or "worksheets" in file:

                    xml_data = open(file, "r", errors="ignore").read()
                    emb_ole_tag_data = self.detect_emb_ole_tag(xml_data)
                    if emb_ole_tag_data:
                        print_line = "reference to embedded OLE object in file: %s" % file.strip('\x01')
                        indicators.rows.append([print_line, emb_ole_tag_data])
                        helpers.add_summary_if_no_duplicates(print_line, emb_ole_tag_data)
                    #file_handle.close()

                #elif not re.findall(r".*\.xml", file) and not re.findall(r".*\.bin", file) and not re.findall(r".*\.xml\.rels", file):
                #    ms_ole = OLEParser(file_data)
                #    self.parse_ole_file(helpers, file_data, file)
                #    ms_ole.extract_embedded_ole(helpers, file, file)

                else:
                    file_handle.close()
                    continue



        indicators.columns.alignment = BeautifulTable.ALIGN_LEFT
        helpers.raw_data += str(indicators)



    def find_ext_references(self, helpers, data, filename):

        mshtml = re.findall(r'oleObject\" Target=\"mhtml:.*TargetMode=\"External\"', data)
        ext_template = re.findall(r'attachedTemplate\" Target=\"http.*TargetMode=\"External\"', data)
        hyperlinks = re.findall(r'hyperlink\" Target=\".*\"\ TargetMode=\"External\"', data)
        external_oleobj = re.findall(r'oleObject\" TargetMode=\"External\" Target=\".*\"', data)

        if mshtml:
            mshtml_string = str(", ".join(mshtml))
            summary_string = "Found Possible MSHTML abuse in file: %s" % filename.replace("\\unzipped", "")
            helpers.raw_data += summary_string + " " + mshtml_string
            helpers.add_summary_if_no_duplicates(summary_string, mshtml_string)
            return mshtml_string

        if ext_template:
            reference = str(", ".join(ext_template))
            if helpers.my_os == "Windows":
                summary_string = "Found external relationship to OLE object in file: %s" % filename.replace("\\unzipped", "")
                helpers.raw_data += summary_string + " " + reference
            if helpers.my_os == "Linux":
                summary_string = "Found external relationship to OLE object in file: %s" % filename.replace("/unzipped", "")
                helpers.raw_data += summary_string + " " + reference
            helpers.add_summary_if_no_duplicates(summary_string, reference)
            return reference

        if hyperlinks:
            links = str(", ".join(hyperlinks))
            summary_string = "Found hyperlinks in file: %s" % filename.replace("\\unzipped", "")
            helpers.raw_data += summary_string + " " + links
            helpers.add_summary_if_no_duplicates(summary_string, links)
            return links

        if external_oleobj:
            oleobj = str(", ".join(external_oleobj))
            # #print("\n[!] Found external reference to OLE object in file:@ %s" % filename)
            summary_string = "Found external relationship to OLE object in file: %s" % filename.replace("\\unzipped", "")
            helpers.raw_data += summary_string + " " + oleobj
            helpers.add_summary_if_no_duplicates(summary_string, oleobj)
            return oleobj

    def extract_strings_sst(self, helpers, data, filename):
        # <t>(.*)</t>
        shared_strings = re.findall('<t>(.*)</t>', data)
        if shared_strings:
            helpers.raw_data += "\n[+] Shared strings table found in file: %s\n%s\n" % (filename, str(shared_strings))
        else:
            pass

    def parse_ole_file(self, helpers, filename, ms_ole):
        #ms_ole = OLEParser(data)
        ms_ole.extract_embedded_ole(helpers, filename, filename)
        if open(filename):
            fd = os.open(filename, os.O_WRONLY)
            os.close(fd)

    def detect_eqedit32(self, helpers, data):
        """
        https://www.forcepoint.com/blog/x-labs/assessing-risk-office-documents-part-3-exploited-%E2%80%9Cweaponized%E2%80%9D-rtfs

        """
        eqedit32_clsid = re.findall(helpers.EQ_EDIT_CLSID_RE, data)
        if eqedit32_clsid:
            return eqedit32_clsid
        else:
            return "    Did not detect an Equation Editor CLSID..."

    def detect_activex(self, helpers, filename):

        path = self.zip_extrcat(helpers, filename)
        activex_dir = path + "\\xl\\activeX"
        files = glob.glob(activex_dir + "\\*.*", recursive=False)
        if files:
            #print("\nSearching for ActiveX OLE objects")
            helpers.raw_data += "\nSearching for ActiveX OLE objects\n"
            activex_ole_files = []

            for file in files:
                if ".bin" in file:
                    file_data = open(file, "rb").read()
                    ms_ole = OLEParser(file_data)
                    activex_ole_files.append(file)
                    self.parse_ole_file(helpers, file, ms_ole)

            if activex_ole_files:
                summary_string = "ActiveX objects in file: %s" % filename
                helpers.add_summary_if_no_duplicates(summary_string, ", ".join(activex_ole_files))

            return activex_ole_files

    def detect_dde(self, helpers, data, filename):

        DDE_PATTERN = "DDEAUTO.*|INCLUDE.*"

        dde = re.findall(DDE_PATTERN, data)
        if dde:

            if ".xml" in filename:
                tree = ET.parse(filename)
                root = tree.getroot()

                for child in root:
                    dde_command = self.inline_xml(child)

                final_dde_command = "".join(dde_command)
                return final_dde_command

    def detect_emb_ole_tag(self, data):

        EMB_OLE_TAG_PATTERN = r"\<oleObjects\>.*\<\/oleObjects\>"
        emb_ole_tag = re.findall(EMB_OLE_TAG_PATTERN, data)

        if emb_ole_tag:
            return emb_ole_tag

    def inline_xml(self, child):

        clean_string = []

        for attrib in child:
            for val in attrib:
                y = filter(lambda v: v.text is not None, val)
                [clean_string.append(x.text) for x in list(y)]

        return clean_string


class OOXML_Excel(OOXMLParser):
    """
    The OOXML_Excel() class is a sub class of the OOXMLParser() class.
    It exports methods that handle and read data from Excel sheets and specific methods for binary Excel worksheets.

    """

    # Prepare a sheets table
    sheet_cells = BeautifulTable(maxwidth=100)
    sheet_cells.headers = ["Cell #", "Cell Content"]

    def read_sheets(self, helpers, filename, read_macros=True):

        helpers.raw_data += "\nReading Excel sheets:\n"
        path = self.zip_extrcat(helpers, filename)
        sheets_dir = path + "\\xl\\worksheets"
        sheet_types = ["worksheet"]
        macros_sheets = ""

        if read_macros:
            sheet_types.append("macrosheets")
            macros_dir = path + "\\xl\\macrosheets"
            macros_sheets = glob.glob(macros_dir + "\\*.*", recursive=False)

        sheets = glob.glob(sheets_dir + "\\*.*", recursive=False)

        for type in sheet_types:

            if type == "macrosheets":
                self.sheet_cells.columns.alignment = BeautifulTable.ALIGN_LEFT
                helpers.raw_data += str(self.sheet_cells)
                helpers.raw_data += "\n"
                self.sheet_cells.clear()

                sheets = macros_sheets
                self.print_cells(helpers, filename, sheets)
                self.sheet_cells.columns.alignments = BeautifulTable.ALIGN_LEFT
                helpers.raw_data += str(self.sheet_cells)

                break

            self.print_cells(helpers, filename, sheets)

    def print_cells(self, helpers, filename, sheets):

        for sheet in sheets:
            if ".xml" in sheet:
                tree = ET.parse(sheet)
                root = tree.getroot()
                helpers.raw_data += "[+] Sheet: %s\n" % sheet
                for child in root:
                    m = filter(self.inline_cell(helpers, filename, child, self.sheet_cells), root)

    def inline_cell(self, helpers, filename, child, sheet_cells):

        if "sheetData" in child.tag:
            for attrib in child:
                for val in attrib:
                    y = filter(lambda v: v.text is not "0", val)
                    for x in list(y):
                        sheet_cells.rows.append([val.attrib.get("r"), x.text])
                        helpers.search_indicators_in_string(helpers, filename, x.text)

    def read_binary_excel_sheets(self, helpers, file):

        sheet_binary_table = BeautifulTable(maxwidth=200)
        sst_table = BeautifulTable(maxwidth=100)
        content = []

        with open_xlsb(file) as wb:
            sheets = wb._sheets

            for sheet_name, sheet_path in sheets:
                if sheet_path:
                    with wb.get_sheet(sheet_name) as s:
                        for row in s.rows():
                            for item in row:
                                if item.v is not None and item.v is not False and type(item.v) is str and len(item.v) \
                                        > 1:
                                    content.append(item.v)
                                    sheet_binary_table.rows.append(["Cell at row:" + str(item.r) + ", col:" +
                                                                    str(item.c), item.v.replace("\x00", "")])

                                    helpers.search_indicators_in_string(sheet_name, item.v)
                else:
                    continue

                sheet_binary_table.columns.alignment = BeautifulTable.ALIGN_LEFT
                helpers.raw_data += "\nSheet name: %s\n" % sheet_name
                helpers.raw_data += str(sheet_binary_table)
                helpers.raw_data += "\n"

            self.print_binary_sst(file, sst_table)

    def print_binary_sst(self, helpers, file, sst_table):
        with open_xlsb(file) as wb:
            sst_table.rows.append(["Shared Strings Table", " , ".join(wb.stringtable._strings)])
            sst_table.columns.alignment = BeautifulTable.ALIGN_LEFT
            helpers.raw_data += str(sst_table)

    # def list_contents(self, helpers, filename):
    #
    #    indicators = BeautifulTable(maxwidth=100)
    #    path = self.zip_extrcat(filename)
    #    files = glob.glob(path + "**\\**\\**\\*.*", recursive=True)
    #    if files:
    #        for file in files:
    #
    #            file_data = open(file, "rb").read()
    #            eqedit32 = self.detect_eqedit32(file_data)
    #
    #            if helpers.OLE_FILE_MAGIC in file_data[:len(helpers.OLE_FILE_MAGIC)]:
    #
    #                ms_ole = OLEParser(file_data)
    #                ms_ole.extract_embedded_ole(file)
    #
    #                if eqedit32:
    #                    print_string = "[!] Detected Equation Editor CLSID"
    #                    indicators.rows.append([print_string, file])
    #
    #            if "vbaProject.bin" in file:
    #                self.parse_ole_file(file_data, file)
    #                continue
    #
    #        indicators.columns.alignment = BeautifulTable.ALIGN_LEFT
    #        #print(indicators)


class OOXML_PowerPoint(OOXMLParser):
    """
    This class is not used.
    If PowerPoint OOXML specific functionality will be added, it will be here.

    """

    def search_slides(self):
        pass


class OOXML_Word(OOXMLParser):
    """
    This class is not used.
    If Word OOXML specific functionality will be added, it will be here.

    """


class RTF:
    """
    The RTF() class parses and analyzes RTF documents.
    RTF document usually embed a malicious OLE object that can very from:
    - Equation Editor exploit (Eqution object containing shellcode or a shell command).
    - Office document (Excel/Word/PowerPoint) containing macros
    - Packages/scripts
    - PE files
    - etc.

    The class will:
    - Attempt to scan for hex data and construct all blobs it finds.
    - Print blobs to the console in hex
    - If it finds an OLE file, it will initiate the OLEParser class for recursive analysis
    - Gather indicators such as URLs, known code strings (scripts), PE magic bytes, etc.
    """

    def __init__(self, data):
        self.data = data

    def clean_hex_data(self, helpers, data):
        """
        Remove all \x0d, \x0a, \x09 and \x20" bytes from RTF hex blobs.
        In many cases, the malicious RTF documents are embedded with hexadecimal data. The data is added with
        additional junk bytes that break its hexadecimal representation and need to be removed,

        """
        # rb"\x0d|\x0a|\x09|\x20"
        clean = re.sub(helpers.rtf_clean_regex, b"", data)
        return clean

    def search_ole_obj(self, helpers, data):
        """
        This is the main method in the class and executes the main functionality.
        It searches for embedded objects and arbitrary hex data and analyzes them.

        It will:
          - Analyze OLE files if it finds any and manages to parse them (ole blobs).
          - If failed parsing data as OLE, will process it as arbitrary blob (blobs).

        """
        # Extract OLE blobs (CFB header was detected in hex).
        ole_blobs = re.findall(helpers.rtf_ole_blob_regex, data)

        # Extract hex blobs, regardless of OLE magic.
        blobs = re.findall(helpers.rtf_binary_blob_regex, data)

        filename = "obj.bin"
        f = open(filename, "w+b")

        # Save lengths of lists.
        len_ole_blobs = len(ole_blobs)
        len_blobs = len(blobs)

        # Process OLE blobs
        self.analyze_ole_blob(helpers, ole_blobs, len_ole_blobs, filename)

        # Process arbitrary hex blobs.
        self.analyze_blob(helpers, blobs, len_blobs, f, filename, data)
        try:
            os.remove("obj.bin")
        except PermissionError as e:
            remove = open(e.filename)
            remove.close()
            os.remove(e.filename)

    def analyze_ole_blob(self, helpers, ole_blobs, length, filename):
        """
        For each extracted OLE hex blob in the list (ole_blobs), unhexlifies and further analyzes it.

        """
        # Initial check if the list is empty.
        if length > 0:
            # Handle each object in the list.
            for obj in ole_blobs:
                # Verify if object has meaningful data/not empty.
                if obj is not b'' and len(obj) > 200:
                    try:
                        # Unhexlify object data ("01" --> b'\x01') and convert all to uppercase.
                        obj_data = binascii.unhexlify(obj.upper())
                    except Exception:
                        # Unhexlify and keep in lowercase.
                        obj_data = binascii.unhexlify(obj)

                    # Initiate the OLEParser() class with the object hex bytes.
                    ms_ole = OLEParser(obj_data)
                    f = open(filename, "w+b")
                    f.write(obj_data)

                    helpers.raw_data += "\n[!] Found \'d0cf11e0\' magic in the RTF file contents\n"
                    helpers.raw_data += "[+] Saved OLE file contents to: %s\n" % f.name

                    # Add indication of OLE magic bytes to final summary table.
                    summary_string = "OLE file magic bytes in file %s\n" % filename
                    summary_desc = "Found \'d0cf11e0\' magic in file: %s\n" % filename
                    helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

                    f.close()

                    # Start of OLE recursive static analysis.
                    helpers.raw_data += "Starting analysis on OLE object\n"
                    helpers.raw_data += "Starting analysis on OLE object\n"

                    # Run OLEParser() methods on object.
                    ms_ole.extract_embedded_ole(helpers, f.name, f.name)

                    # Create file and write object's hex data to it.
                    self.prepare_blob_file(helpers, f, filename, obj_data)

    def analyze_blob(self, helpers, blobs, length, f, filename, data):
        """
        Any hex data that was found but was unsuccessfully parsed as OLE, will be handled by this method.

        Checks for Equation Editor fingerprints and any potential malicious code/scripts.
        Prints further recommendations on how to further examine arbitrary hex data.

        It has an auxiliary code section in the conditional flow that is triggered when initial hex blob extracting
        regular expressions failed to find any blobs.

        """
        # Initial check if the list is empty.
        if length > 0:
            # #print("\n[+] Starting analysis on binary streams@")
            helpers.raw_data += "\n[+] Starting analysis on binary streams\n"
            # Flag is used to tell in general if any blobs were found.
            blob_flag = True

            # Flag is used to tell in general if any blobs were found.
            auxiliary_used = False

            # Iterate over each hex blob and analyze it.
            for blob in blobs:
                # Each blob is a list of smaller streams, therefore, iterate over each stream in the inline list.
                for b in blob:
                    # Save stream length.
                    b_len = len(b)

                    # Only process blobs that have enough data to be meaningful.
                    if b_len > 200:
                        try:
                            blob_data = binascii.unhexlify(b.upper())
                        except binascii.Error:
                            # Could not unhexlify uppercase data.
                            try:
                                # Unhexlify in lowercase.
                                blob_data = binascii.unhexlify(b)
                            except binascii.Error:
                                # Binascii could not unhexlify data because its length is not even (len(b) % 2 != 0)
                                # Therefore, check if auxiliary code was used before proceeding to it.
                                if auxiliary_used:
                                    break

                                # Auxiliary Code:
                                # ---------------
                                # Triggered when initial hex blob extracting regular expressions failed to find any
                                # blobs.

                                # Set flag that tells if auxiliary code was used to True.
                                auxiliary_used = True

                                # Use auxiliary regex to find hex blobs.
                                helpers.raw_data += "Using auxiliary regex to find data blobs...\n"
                                aux_regex = rb"[A-Z]\}([\x00-\x66]+)\{\\|[A-Z]\}|[a-z]([\x00-\x66]+)"
                                aux_matches = re.findall(aux_regex, data)

                                # Iterate over matches from the auxiliary regex.
                                for t in aux_matches:
                                    # Each match is a list, therefore have to add another for loop...
                                    for m in t:
                                        # Process blobs that have enough data to be meaningful.
                                        if len(m) > 200:
                                            try:
                                                # Convert hex to UPPERCASE and unhexlify.
                                                blob_data = binascii.unhexlify(m.upper())

                                                # Print blob in hex view, search functions, extract ASCII/wide
                                                # char strings. Then Create file and write blob data to it.
                                                self.arbitrary_blob_analysis(helpers, f, filename, blob_data)
                                            except binascii.Error:
                                                # Could not unhexlify hex data in uppercase
                                                try:
                                                    # Unhexlify hex data as lowercase.
                                                    blob_data = binascii.unhexlify(m)
                                                except binascii.Error:
                                                    helpers.raw_data += "Using auxiliary regex to find data blobs...\n"

                                                    # Print blob data anyway.
                                                    # #print(m)
                                                    helpers.raw_data += str(m)
                                                    helpers.raw_data += "\n"
                                                    continue
                                                else:
                                                    # Hex data was successfully unhexlified in lowercase.
                                                    # Print blob in hex view, search functions, extract ASCII/wide
                                                    # char strings. Then Create file and write blob data to it.
                                                    self.arbitrary_blob_analysis(helpers, f, filename, blob_data)
                            else:
                                # Hex data was successfully unhexlified in lowercase and now is analyzed.
                                # Print hex view of blob, search for Equation Editor exploit, extract ASCII/wide char
                                # strings
                                self.arbitrary_blob_analysis(helpers, f, filename, data)

                        else:
                            # Hex data was successfully unhexlified in UPPERCASE and now is analyzed.
                            # Print hex view of blob, search for Equation Editor exploit, extract ASCII/wide char
                            # strings
                            self.arbitrary_blob_analysis(helpers, f, filename, blob_data)

            if blob_flag:
                # Add to summary table if any blobs were found.
                summary_string = "Arbitrary Data (Possibly shellcode)"
                summary_desc = "A binary stream of bytes was found in the RTF document.\n" \
                               "It was not detected as an OLE file.\n" \
                               "You should check the printed disassembly to verify if there is some shellcode.\n\n" \
                               "- Paste the contents of \"obj.bin\" (tool's directory) in CyberChef (\"from x86 " \
                               "disassemble\" as filter).\n" \
                               "--- Change to \"x86\" in the disassembly mode.\n" \
                               "- You can use any quick online/offline disassembler you are femiliar with.\n" \
                               "- If identified as shellcode:\n--- Run in a debugger using an emulator " \
                               "(like \"blob_runner.exe\" utility).\n" \
                               "--- *** This requires you to know the start offset of the shellcode in the data " \
                               "and carve " \
                               "it out manually.\n--- If it is Equation Editor exploit shellcode, EQNEDT32.exe needs " \
                               "to be debugged in x86 mode."

                helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

    def arbitrary_blob_analysis(self, helpers, f, filename, data):
        """
        This method takes hex data after it was unhexlified and analyzes it.

        Relevant only for arbitrary hex blobs.
        Blobs that were identified as OLE files will be processed using the OLEParser() class.

        """
        # Initiate the OLEParser() class with the blob data.
        ms_ole = OLEParser(data)

        # Extract and decode ASCII / wide char strings.
        ms_ole.extract_unicode_and_ascii_string(helpers, f.name, data)

        # Search for Equation Editor exploit fingerprints.
        self.search_eqnedt32(helpers, data, filename)

        # Check for functions in data.
        if b'Function' in data or b'Sub ' in data:
            func_regex = rb'Function [a-zA-z0-9]{3,20}'
            func_string = re.findall(func_regex, data)

            summary_string = "Scripting in file: %s" % filename
            summary_desc = "Possible function detected in stream: %s" % func_string
            helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

        # Create file and write blob data to it.
        self.prepare_blob_file(helpers, f, filename, data)

    def prepare_blob_file(self, helpers, f, filename, data):
        """
        Creates the hex blob file on disk and writes the data to it.
        Closes the file when finished.

        Used both for OLE object and arbitrary hex blobs.

        """
        if f.closed:
            f = open(filename, "w+b")
        f.write(data)
        f.close()

    """
    def disassembly(self, helpers, data):
    """
    #    Disassembles hex data as opcodes/byte code.
    #    Uses the Capstone engine.

    """
        try:
            #print("\nDisassembly: %s\n--------------------------" % ("".join(f.name)))
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            disassembly = md.disasm(data, 0x00)
            for i in disassembly:
                if i.mnemonic is "jmp" and int(i.op_str, 16) < 4096:
                    #print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                else:
                    #print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

        except Exception:
            #print(sys.exc_info()[1])
    """

    def search_eqnedt32(self, helpers, data, filename):
        """
        Search Equation Editor exploit fingerprints in hex blobs.

        """
        equation = re.findall(helpers.equation_byte_regex, data)
        # equation1 = re.findall(helpers.equation_regex, data)
        # summary_desc = ""
        if equation:
            summary_string = "Indication of Equation Editor exploit " "(CVE-2017-11882) in stream:@ %s" % filename

            if equation:
                summary_desc = "Found \'%s\' in binary data stream" % equation
                unified = summary_string + summary_desc
                helpers.raw_data += unified


class PDF:
    """
    PDF() class will parse the PDF document file data and analyze each object separately.
    It will print a object table showing all the PDF objects and their types.
    Run multiple checks for common PDF weaponizing vectors.

    """

    def __init__(self, data):
        self.data = data

    def enum_objects(self, helpers, data):

        """
        Enumerate all objects in the PDF document.
        The main method in the class, running all other methods.
        Analyzes each object separately using the PDF() methods.
        """

        # Prepare PDF object table before populating it
        obj_table = BeautifulTable(maxwidth=100)
        obj_table.headers = (["Object", "Type"])
        obj_table.rows.append(["Object", "Type"])

        helpers.raw_data += "\n[+] Enumerating PDF objects\n"
        # Extract all objects to a list for later processing
        objects = re.findall(helpers.obj_regex, data)

        # Print a short list of all objects and their types before analyzing each object
        self.print_obj_short(helpers, objects, obj_table)

        # The previous function populated the objects table, no print it to the terminal
        obj_table.columns.alignment = BeautifulTable.ALIGN_LEFT
        helpers.raw_data += str(obj_table)

        # Loop over all objects. Each "obj" the object binary string (b'').
        for obj in objects:
            readable_obj = ""
            for char in obj:
                # Add each char to the readable_obj string to later pretty-print the object.
                readable_obj += chr(char)

            # Carve the object number from the object binary string.
            obj_num_bin = obj[:2]
            helpers.raw_data += "\n\nObject %s:\n" % obj_num_bin
            helpers.raw_data += "=" * len("Object %s:" % obj_num_bin)
            helpers.raw_data += "\n"
            helpers.raw_data += "[+] Readable object (first 1,000 bytes):\n"

            # Check obj size before printing to avoid overflowing the terminal
            if len(readable_obj) > 1000:

                try:
                    helpers.raw_data += readable_obj[:1000]
                    helpers.raw_data += "\n"
                except UnicodeError as e:
                    pass

            else:
                try:
                    helpers.raw_data += str(readable_obj)
                    helpers.raw_data += "\n"
                except UnicodeError as e:
                    helpers.raw_data += str(e)
                    helpers.raw_data += "\n"

            # Extract all URIs to list
            uris = self.extract_uri(helpers, obj)

            # If there are any /URI in the document, it will enter the for loop to log it and add it to the
            # summary table.
            for uri in uris:
                helpers.raw_data += "[+] Found URI in object %s:\n%s\n" % (obj_num_bin, uri.decode('utf-8'))
                summary_string = ("Found URI in object %s:@" % obj_num_bin)
                summary_desc = "%s" % uri.decode('utf-8')
                helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            # Extract all embedded files ("\EmbeddedFile") to list
            emb_files = self.find_emb_files(helpers, obj)
            # If there are any /EmbeddedFile in the document, it will enter the for loop to log it and add it to the
            # summary table.
            for emb_file in emb_files:
                helpers.raw_data += "\n[+] Found embedded file in object %s:\n%s\n" % (
                obj_num_bin, emb_file.decode('utf-8'))
                summary_string = "Found embedded file in object %s:" % obj_num_bin
                summary_desc = "%s" % emb_file.decode('utf-8')
                helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            # Find object streams
            obj_stm = self.find_objstm(helpers, obj)

            # If there are any /ObjStm in the document, it will enter the for loop to log it and add it to the
            # summary table.
            for stm in obj_stm:
                helpers.raw_data += "\n[+] Found object stream (ObjStm) in object %s:\n%s\n" % (
                obj_num_bin, stm.decode('utf-8'))
                summary_string = "Found object stream (ObjStm) in object %s:@" % obj_num_bin
                summary_desc = "%s" % stm.decode('utf-8')
                helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            # Run additional checks on the object data.

            # find JavaScript references from one object to another
            self.find_js_reference(helpers, obj, obj_num_bin)

            # find /OpenAction
            self.open_action(helpers, obj, obj_num_bin)

            # find /Launch
            self.find_launch(helpers, obj, obj_num_bin)

            # find /FileSpec
            self.find_filespec(helpers, obj)

            # find "this.exportDataObject" (embedded files)
            self.find_export_data_obj(helpers, obj)

            # This function will check if there is a potential hex blob that can be decoded to see if there is any
            # interesting data or files.
            self.validate_hex_data(helpers, obj)

            # Find potential UNC paths (shares) - can indicate NTLM hash leaking via connecting to a attacker
            # controlled SMB share (sends NTLM hash to target as part of authentication)
            self.find_unc_path(helpers, data, obj_num_bin)

            # Find GoTo references (file/object within the document, remote or embedded object)
            self.find_goto_ref(helpers, data, obj_num_bin)

            # Find /SubmitForm - a form which will send data to a URL
            self.find_submitform(helpers, data, obj_num_bin)

            # If there is a stream in the object
            if b"stream" in obj:
                # Extract the stream contents from the object.
                stream_data = re.findall(helpers.stream_regex, obj)[0]

                # Try to LZW decompress it
                try:
                    decompressed = self.lzw_decode(helpers, stream_data)
                    helpers.raw_data += '\n[+] Decompressed stream (LZW decompression):\n'
                    helpers.raw_data += decompressed
                    helpers.raw_data += "\n"

                    # If decompression succeeded and the file is RTF, initiate the RTF class for inline analysis of
                    # the RTF document.
                    if helpers.determine_mimetype(decompressed) == 'rtf':
                        rtf = RTF(decompressed)
                        summary_string = "Embedded document"
                        summary_desc = "Found RTF document"
                        helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                        clean = rtf.clean_hex_data(helpers, decompressed)
                        rtf.search_ole_obj(helpers, clean)

                    # If decompression succeeded and the file is OLE, initiate the OLEParser class for inline
                    # analysis of the OLE file.
                    elif helpers.determine_mimetype(decompressed) == 'ole':
                        ms_ole = OLEParser(decompressed)
                        ms_ole.extract_embedded_ole(helpers, "ole_temp", "ole_temp")

                except AttributeError:
                    pass

                decompressed = self.flate_decode(helpers, stream_data, obj_num_bin)
                mimetype = helpers.determine_mimetype(helpers, decompressed)
                try:
                    # Check if there is any code in the object. If there is, print the entire object
                    if b"var " in decompressed or b"function" in decompressed:
                        helpers.raw_data += decompressed.decode('utf-8')
                        helpers.raw_data += "\n"
                    else:
                        helpers.raw_data += decompressed[:1000]
                        helpers.raw_data += "\n"

                        # If decompression succeeded and the file is RTF, initiate the RTF class for inline analysis of
                        # the RTF document.
                        if mimetype == 'rtf':
                            rtf = RTF()
                            summary_string = "Embedded document@"
                            summary_desc = "Found RTF document"
                            helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                            clean = rtf.clean_hex_data(helpers, decompressed)
                            rtf.search_ole_obj(helpers, clean)

                        # If decompression succeeded and the file is OLE, initiate the OLEParser class for inline
                        # analysis of the OLE file.
                        elif mimetype is 'ole':
                            ms_ole = OLEParser(data)
                            with open("ole_temp.bin", "ab") as f:
                                f.write(decompressed)
                                ms_ole.extract_embedded_ole(helpers, "ole_temp.bin", "ole_temp.bin")
                                f.close()
                                os.remove("ole_temp.bin")
                except TypeError:

                    # If decompression succeeded and the file is RTF, initiate the RTF class for inline analysis of
                    # the RTF document.
                    if mimetype == 'rtf':
                        rtf = RTF(data)
                        summary_string = "Embedded document@"
                        summary_desc = "Found RTF document"
                        helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                        clean = rtf.clean_hex_data(helpers, decompressed)
                        rtf.search_ole_obj(helpers, clean)

                    # If decompression succeeded and the file is OLE, initiate the OLEParser class for inline
                    # analysis of the OLE file.
                    elif mimetype is 'ole':
                        ms_ole = OLEParser(data)
                        f = open("ole_temp.bin", "ab")
                        f.write(decompressed)
                        ms_ole.extract_embedded_ole(helpers, "ole_temp.bin", "ole_temp.bin")
                        f.close()
                except UnicodeError:
                    # If .decode('utf-8') on the decompressed data failed
                    helpers.raw_data += decompressed
                    helpers.raw_data += "\n"

                    # If decompression succeeded and the file is RTF, initiate the RTF class for inline analysis of
                    # the RTF document.
                    if mimetype == 'rtf':
                        rtf = RTF()
                        summary_desc = "Found RTF document"
                        helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                        clean = rtf.clean_hex_data(helpers, decompressed)
                        rtf.search_ole_obj(helpers, clean)

                    # If decompression succeeded and the file is OLE, initiate the OLEParser class for inline
                    # analysis of the OLE file.
                    elif mimetype is 'ole':
                        ms_ole = OLEParser(data)
                        f = open("ole_temp.bin", "r+b")
                        f.write(decompressed)
                        ms_ole.extract_embedded_ole(helpers, f.name, f.name)
                        f.close()

    def print_obj_short(self, helpers, objects, obj_table):

        """
        Prints a short list of the objects and their types..
        """

        for obj in objects:
            headers = re.findall(helpers.obj_header, obj)
            for header in headers:
                try:
                    obj_table.rows.append(["Object %s" % obj[:2].decode('utf-8'), header.decode('utf-8')])
                    helpers.raw_data += "Object %s\n" % obj[:2].decode('utf-8')
                    helpers.raw_data += header.decode('utf-8')
                    helpers.raw_data += "\n"
                except UnicodeError:
                    try:
                        obj_table.rows.append(["Object %s" % obj[:2].decode('utf-8'), header])
                        helpers.raw_data += "Object %s" % obj[:2].decode('utf-8')
                        helpers.raw_data += str(header)
                    except UnicodeError:
                        obj_table.rows.append(["Object %s" % obj[:2], header])
                        helpers.raw_data += "Object %s" % obj[:2]
                        helpers.raw_data += header

    def flate_decode(self, helpers, data, obj_num_bin):

        """
        Decompresses Zlib Inflated streams.
        """
        try:
            data = data.strip(b'\r\n')
            decompressed = zlib.decompress(data)  # Here you have your clean decompressed stream
            helpers.raw_data += "\n[+] Decompressed stream (Zlib Inflate):\n"
            return decompressed

        except zlib.error as e:
            return 0

    def lzw_decode(self, helpers, data):

        """
        Decompresses LZW compressed streams.
        """
        # Build the dictionary.
        dict_size = 256
        dictionary = dict((i, chr(i)) for i in range(dict_size))
        result = StringIO()
        w = chr(data.pop(0))
        result.write(w)
        for k in data:
            if k in dictionary:
                entry = dictionary[k]
            elif k == dict_size:
                entry = w + w[0]
            else:
                raise ValueError('Bad compressed k: %s' % k)
            result.write(entry)

            # Add w+entry[0] to the dictionary.
            dictionary[dict_size] = w + entry[0]
            dict_size += 1

            w = entry
        return result.getvalue()

    def find_export_data_obj(self, helpers, data):
        """
        Another approach to find embedded files - this.exportDataObject().
        """
        export_data_objects = re.findall(helpers.export_data_regex, data)
        for exp in export_data_objects:
            helpers.raw_data += "\n[+] Found embedded file/object:\n"
            helpers.raw_data += exp.decode('utf-8')
            helpers.raw_data += "\n"
            helpers.add_summary_if_no_duplicates("Found embedded file/object", exp.decode('utf-8'))
            break

    def find_filespec(self, helpers, data):
        """
        Find embedded files - /FileSpec
        """
        if re.findall(helpers.filespec_regex, data):
            filespec = re.findall(helpers.file_regex, data)
            for file in filespec:
                helpers.raw_data += "\n[+] Found file reference:\n"
                helpers.raw_data += file.decode('utf-8')
                helpers.raw_data += "\n"
                if b'downl.SettingContent-ms' in file:
                    helpers.raw_data += "[!] Possible abuse of SettingContent-ms file to download malicious content.\n"
                    helpers.add_summary_if_no_duplicates("Found embedded file/object", file.decode('utf-8'))
                break

    def find_unc_path(self, helpers, data, obj_num_bin):
        """
        Find UNC paths (shares)
        Can indicate possible exploitation of CVE-2018-4993
        """
        unc = re.findall(helpers.unc_regex, data)
        for p in unc:
            helpers.raw_data += "\n[!] Found UNC path (possible Adobe Reader NTLM hash leak vulnerability CVE-2018-4993) in object %s,to path: %s\n" % (
            obj_num_bin, p)
            helpers.add_summary_if_no_duplicates(
                'Found UNC path (possible Adobe Reader NTLM hash leak vulnerability CVE-2018-4993)', p)

    def extract_uri(self, helpers, data):
        """
        Find /URI
        """
        uris = re.findall(helpers.uri_regex, data)
        return uris

    def find_emb_files(self, helpers, data):
        """
        Find /Type /EmbeddedFile
        """
        emb_files = re.findall(helpers.emb_file_regex, data)

        if re.findall(helpers.emb_file_regex, data):
            helpers.raw_data += "\n[+] Found file reference:\n"
            file_ref = re.findall(helpers.file_ref_regex, data)
            for file in file_ref:
                helpers.raw_data += file.decode('utf-8')
                helpers.raw_data += "\n"
                if b'downl.SettingContent-ms' in file:
                    helpers.raw_data += "[!] Possible abuse of SettingContent-ms file to download malicious content.\n"
                break
        return emb_files

    def find_objstm(self, helpers, data):
        """
        Find /Objstm
        """
        emb_files = re.findall(helpers.objstm_regex, data)
        return emb_files

    def find_js_reference(self, helpers, data, obj_num_bin):
        """
        Find "/JS <obj_num> 0 R" - references to objects with JavaScript
        """
        js_ref_regex = re.compile(helpers.js_ref_pattern)
        for match in re.finditer(js_ref_regex, data):
            referred_obj = data[match.span(0)[0]:match.span(0)[1]][12:14]
            helpers.raw_data += "\n[!] Found JS reference in object %s, to object %s\n" % (obj_num_bin, referred_obj)

    def open_action(self, helpers, data, obj_num_bin):

        """
        Find "/AA and /OpenAction" - automatic actions that are executed when the document is opened.
        """
        # /AA and /OpenAction
        aa_regex = re.compile(helpers.auto_action_pattern)
        openaction_regex = re.compile(helpers.open_action_regex)
        o_regex = re.compile(helpers.o_regex)

        for match in re.finditer(aa_regex, data):
            helpers.raw_data += "\n[!] Found automatic action /AA in object %s\n" % obj_num_bin

        for match in re.finditer(openaction_regex, data):
            helpers.raw_data += "\n[!] Found OpenAction in object %s\n" % obj_num_bin

        for match in re.finditer(o_regex, data):
            # print("\n[!] Found /O actions dictionary in object %s" % obj_num_bin)
            helpers.raw_data += "\n[!] Found /O actions dictionary in object %s\n" % obj_num_bin

        for match in re.finditer(helpers.open_a_ref_regex, data):
            referred_obj = data[match.span(0)[0]:match.span(0)[1]][12:14]
            helpers.raw_data += "[!] Found OpenAction reference in object %s, to object: %s\n" % (
            obj_num_bin, referred_obj.decode('utf-8'))

    def find_launch(self, helpers, data, obj_num_bin):
        """
        Find "/Launch" - execute other applications.
        """
        # /Launch
        aa_regex = re.compile(helpers.auto_action_pattern)
        for match in re.finditer(aa_regex, data):
            helpers.raw_data += "\n[!] Found \"/Launch\" in object %s\n" % obj_num_bin
            helpers.raw_data += match
            helpers.raw_data += "\n"

    def find_goto_ref(self, helpers, data, obj_num_bin):

        """
        Find /GoTo* references:
        GoTo: “Go-to” a destination within the document
        GoToR: “Go-to remote” destination
        GoToE: “Go-to embedded” destination
        """
        try:
            goto_ref = re.findall(helpers.goto_regex, data)[0]
        except IndexError:
            return 0
        else:
            for ref in goto_ref:
                helpers.raw_data += "\n[!] Found \"/Goto*\" in object %s\n" % obj_num_bin
                helpers.raw_data += ref

    def find_submitform(self, helpers, data, obj_num_bin):
        """
        Find /SubmitForm
        """
        try:
            submit_form = re.findall(helpers.submitform_regex, data)[0]
        except IndexError:
            return 0
        else:
            for sub in submit_form:
                helpers.raw_data += "\n[!] Found \"/SubmitForm\" in object %s\n" % obj_num_bin
                helpers.raw_data += sub

    def validate_hex_data(self, helpers, data):
        """
        Attempts to clean hex data found in "ASCIIHexDecode streams.
        If there is valid hex data, it is decoded and the magic bytes are checked.
        If the decoded data is an OLE or RTF file, maldoc_parser will recursively analyze the data using the OLEParser
        or RTF classes.
        """
        if b'ASCIIHexDecode' in data or b'ASCII85HexDecode' in data:
            try:
                stream_data = re.findall(helpers.stream_regex, data)[0]
            except IndexError:
                return 0
            else:
                # check if there are any non-hexadecimal characters in the stream data.
                clean = re.sub(b' ', b'', stream_data)
                clean = re.sub(b'\r\n', b'', clean)
                test = re.findall(rb'^[A-Fa-f0-9]+', clean)

                for hex in test:
                    if len(hex) > 1:
                        helpers.raw_data += binascii.unhexlify(test[0]).decode('utf-8')
                        helpers.raw_data += "\n"
                        hex_data = binascii.a2b_hex(hex)
                        chunk = hex_data[:4]

                        if b'\\rt' in chunk:
                            rtf = RTF(hex_data)
                            summary_string = "Embedded document"
                            summary_desc = "Found RTF document"
                            helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                            # Find and "clean" hex data
                            clean = rtf.clean_hex_data(helpers, hex_data)
                            # Search any OLE files and binary blobs in the "cleaned" hex data.
                            rtf.search_ole_obj(helpers, clean)
                        break


class DocParser:

    def __init__(self, data):
        self.data = data

    # MS_OFFICE_WORD = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x4f\x66\x66\x69\x63\x65\x20\x57\x6f\x72\x64'
    # MS_EXCEL = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x78\x63\x65\x6c'


def main():
    # check if a file path was provided to the tool
    if len(sys.argv) < 2:
        exit(0)
    helpers = Helpers()
    filename = sys.argv[1]

    helpers.raw_data += "[+] Parsing file: %s\n" % filename

    # Read the file binary data
    # IF YOU WANT THE FILE TO BE SENT TO THE SCRIPT AS BYTES FROM THE NETWORK/REMOTE HOST, USE io.BytesIO.
    # -----------------------------------------------------------------------------------------------------
    file = open(filename, 'r+b')
    data = file.read()

    # Calculate SHA256 hash
    readable_hash = hashlib.sha256(data).hexdigest()
    helpers.raw_data += "[+] File sha256: %s\n" % str(readable_hash)

    helpers.raw_data += "\n\nStatic Analysis Report\n\n"

    # Determine file type via magic bytes/signature
    mimetype = helpers.determine_mimetype(helpers, data)

    json_file_info = {"file_info": {"filename": filename, "hash": readable_hash, "file type": mimetype}}
    helpers.json_report.update(json_file_info)

    # If the file is OLE
    if mimetype == "ole":
        # Initiate the OLEParser class
        ms_ole = OLEParser(data)
        # Parse CFB header, extract all streams and analyze them
        ms_ole.extract_embedded_ole(helpers, filename, filename)

        # If the OLE file is Excel, apply more parsing and logic
        if helpers.MICROSOFT_EXCEL in data:

            # Initiate the XLSParser class
            xls_parser = XLSParser(data)

            # Parse BOF records
            xls_parser.parse_bof_records(helpers, data)

            # Parse BOUNDSHEET records (sheet headers)
            xls_parser.parse_boundsheet_record(helpers, data)

            # Unhide hidden sheets via BOUNDSHEET record patching
            #xls_parser.unhide_sheets(helpers, file)

            # Extract data from sheets (XLM 4 macros)
            xls_parser.extract_sheets(helpers, filename)

            # Attempt to extract VBA macros if there are any
            decompressed = None
            try:
                decompress_obj = VBADecompress(data)
                decompressed = decompress_obj.SearchAndDecompress(data)
            except TypeError:
                pass

            # Extract strings from Shared Strings table (SST)
            xls_parser.parse_sst(helpers, data)

        elif helpers.MICROSOFT_OFFICE_WORD in data:
            # the DocParser() class has no use.
            # If there will be any Word specific functionality for OLE files it will be executed under this statement.
            doc_parser = DocParser(data)
            pass

    # If the file is RTF
    elif mimetype == "rtf":
        # Initiate the RTF() class with the document data.
        rtf = RTF(data)

        # Find and "clean" hex data
        clean = rtf.clean_hex_data(helpers, data)

        # Search any OLE files and binary blobs in the "cleaned" hex data.
        rtf.search_ole_obj(helpers, clean)

    # If the file is Office Open XML
    elif mimetype == "ooxml":

        # Initiate the OOXMLParser() class
        ooxml_obj = OOXMLParser(data)

        # Find and extract embedded OLE files.
        helpers.raw_data += "[+] Looking for embedded OLE files in OOXML ZIP container\n"
        ooxml_obj.detect_emb_ole(helpers, data, filename)

        # If the OOXML file is Excel
        if ooxml_obj.doc_type == "excel":
            # Initiate a OOXML_Excel class using the already initiated OOXMLParser object
            ooxml_excel = OOXML_Excel(ooxml_obj)

            # check file extension to know how to read sheets
            if "xlsx" or "xlsm" in filename:
                # The below method is specific to reading data from sheets in binary Excel worksheets
                ooxml_excel.read_sheets(helpers, filename)
            # If the Excel is a binary worksheet (.xlsb)
            if "xlsb" in filename:
                # The below method is specific to reading data from sheets in binary Excel worksheets
                ooxml_excel.read_binary_excel_sheets(helpers, filename)

        if ooxml_obj.doc_type == "ppt":
            # ooxml_ppt = OOXML_PowerPoint(ooxml_obj)
            # ooxml_ppt.search_slides(filename)
            pass

        #ms_ole = OLEParser(data)
        #ooxml_obj.parse_ole_file(helpers, data, filename)
        #ooxml_obj.parse_ole_file(helpers, data, ms_ole)
        ooxml_obj.detect_activex(helpers, filename)

    # If the file is a PDF document
    elif mimetype == 'pdf':
        # Initiate the PDF() class.
        pdf_parser = PDF(data)

        # List and analyze all PDF objects
        pdf_parser.enum_objects(helpers, data)

    # Prepare and print final summary analysis table
    helpers.summary_table.columns.alignment = BeautifulTable.ALIGN_LEFT

    helpers.raw_data += "\n\nStatic Analysis Summary\n\n"
    helpers.raw_data += str(helpers.summary_table)
    helpers.raw_json_report["raw_report"] = helpers.raw_data
    helpers.json_report.update(helpers.raw_json_report)
    json_object_pretty = json.dumps(helpers.json_report, indent=2)

    # Print final JSON report
    print(json_object_pretty)

    if path.isdir('unzipped'):
        try:
            shutil.rmtree("unzipped")
        except PermissionError as e:
            try:
                opened_path = Path(e.filename)
                opened_path.close()
                os.remove(e.filename)
                #f = open(e.filename)
                #f.close()
                #os.remove(e.filename)
                shutil.rmtree("unzipped")
            except:
                pass

if __name__ == "__main__":
    main()
