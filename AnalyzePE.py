#!/usr/bin/env python

# AnalyzePE.py was created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
#		@hiddenillusion
# Version 0.1.4 
# Date: 10-15-2012

"""
Usage:
------
	1) Set up the correct paths to clamscan, hachoir-subfile, PEiD's userdb.txt file and your YARA signatures
	2) Scan your PE file(s)

Requirements:
-------------
	- Adobe Malware Classifier
	- Hachoir-subfile
	- pescanner (modified version included on my github)
	- pefile (newer version), peutils
	- verify sigs' fingerprint.py
	- python-magic
	- pyasn1
	- m2crypto
	- pydasm

To-do:
------
	- yara/clamav scanning working?
	- recursive processing of a folder?
	- import directly instead of subprocess?
		- hachoir-subfile
		- AdobeMalwareClassifier
		- pylibemu or use 'sc' from pyew
	- string extraction?
		- hdive
	- URL extraction has extra 0's at end of them.  Also need to make sure they're only listed once
	- show whats in .reloc section?
	- print the language
"""

import os
import subprocess
import shutil
import sys
import argparse
import binascii
import re
import shutil 
import hashlib
import string
import time
try:
    import pefile
    import peutils
    import fingerprint
    # To find other REMnux scripts to import
    sys.path.insert(0, '/usr/local/bin')
    sys.path.insert(0, '/usr/local/pyew')
    from pescanner import PEScanner
    # In REMnux, most are located in /usr/bin
    from hachoir_subfile.search import SearchSubfile
    from hachoir_core.stream import FileInputStream
    import hachoir_subfile
    from pyew_core import CPyew
    from plugins import * # Pyew plugins that is
except ImportError as e:
    print "[!] Couldn't import: ",e
    sys.exit()

parser = argparse.ArgumentParser(description='Wraps around various tools to produce a centralized report of a PE file.')
parser.add_argument('-m','--move', help='Directory to move files triggering YARA hits to', required=False)
parser.add_argument('Path', help='Path to directory/file(s) to be scanned')
parser.add_argument('-v', '--verbose', help='Add additional information to analysis output', action='store_true', required=False)
args = vars(parser.parse_args())

# Set the path to file(s)
file = args['Path']

# Configure some stuff...
wine = '/path/to/wine'
sigcheck = '/path/to/sigcheck.exe'
subfile = '/path/to/hachoir-subfile'
# These get passed to PEScanner
yrules = '/path/to/rules.yara'
peid = '/path/to/userdb.txt'
clamscan_path = '/path/to/clamscan' 

# Sanity check just to make sure it's a legit PE file before trying to analyze
try:
    pe = pefile.PE(file)
except Exception, msg:
    print msg
    sys.exit() # will this exit everything if there's a directory being analyzed?
pyew = CPyew()

if args['verbose'] == True:
    verb = True
else:
    verb = False

def header(msg):
    return msg + "\n" + ("=" * 90)

def subTitle(msg):
    return "\n" + msg + "\n" + ("-" * 40)

def analyze(file):
    """
    filename, size, type, md5, sha1, ssdeep, timestamp, Entry Point, CRC, packers, flag on suspicious EP sections, yara, clamav, TLS callbacks, resource section, imports, suspicious IAT alerts, sections w/ virtual adddress, size, entropy, version info
    """ 
    pescan = PEScanner([file], yrules, peid)
    pescan.collect(verb)

def embed(file):
    """
    Runs hachoir-subfile against the PE to see if anything it detected within the PE file
    """
    try:
        with open(file, "rb") as f:
            data = f.read()
    except:
        pass
    cmd = subfile + ' ' + file
    p = subprocess.Popen(cmd,stderr=subprocess.PIPE,stdout=subprocess.PIPE,shell=True)
    (stdout, stderr) = p.communicate()
    if stdout:
        """
        Check to make sure the found embedded file isn't just actually the file itself
        ...because that's not really what we are looking to determine here
        """
        if len(stdout.split('\n')) <= 2:
            if re.findall('File at 0 size=', stdout):
                val = re.split('=', stdout)
                if int(val[1].split()[0]) == len(data): 
                    return
        else:
            resp = "Yes"
            if verb == True:
                ret = []
                line = stdout.split('\n')
                for l in line:
                    ret.append('\t' + l)
                    embeds = '\n'.join(ret)
                    resp = resp + '\n' + embeds
            return resp
    #subfile = SearchSubfile()
    #subfile.main()

def adobe_classifer(file):
    """
    source  : http://sourceforge.net/projects/malclassifier.adobe/
    scoring : 0 = clean, 1 = dirty or unkown
    """
    cmd = 'python AdobeMalwareClassifier.py' + ' ' + '-f' + ' ' + file
    p = subprocess.Popen(cmd,stderr=subprocess.PIPE,stdout=subprocess.PIPE,shell=True)
    (stdout, stderr) = p.communicate()
    if stdout:
        if "0" in stdout: return "Clean"
        elif "1" in stdout: return "Dirty"
        # ! repetitive print here but don't want to stop the analysis if something goes wrong
        elif "UNKNOWN" in stdout: return "Unknown"

def sigchecker(file):
    print (header("Digital Signature Info.:"))

    """
    sigcheck - not as useful compared to when on M$ platforms of course, but can provide info.
    """
    opts = " -q -a "
    cmd = wine + ' ' + sigcheck + opts + file
    #cmd = 'wine ' + '/path/to/sigcheck.exe' + opts + file
    p = subprocess.Popen(cmd,stderr=subprocess.PIPE,stdout=subprocess.PIPE,shell=True)
    (stdout, stderr) = p.communicate()
    if stdout:
        print "[-] Sigcheck:"
        print stdout
    else: print stderr

    """
    Verify-sigs - requires pyasn1 & m2crypto (apt-get insatll python-pyasn1 python-m2crypto)
    """
    print "[-] Verify-sigs:"
    with open(file, 'rb') as f:
        fingerprinter = fingerprint.Fingerprinter(f)
        is_pecoff = fingerprinter.EvalPecoff()
        fingerprinter.EvalGeneric()
        results = fingerprinter.HashIt()
        #print fingerprint.FormatResults(file_obj, results)
        if is_pecoff:
            # using a try statement here because of: http://code.google.com/p/verify-sigs/issues/detail?id=2
            try:
                fingerprint.FindPehash(results)
            except Exception, msg:
                print "[!] ERROR: %s" % msg
        else: print "Doesn't appear to be a PE/COFF file"

    print

def antidbg(file):
    antidbgs = ['CheckRemoteDebuggerPresent', 'FindWindow', 'GetWindowThreadProcessId', 'IsDebuggerPresent', 'OutputDebugString', 'Process32First', 'Process32Next', 'TerminateProcess',  'UnhandledExceptionFilter', 'ZwQueryInformation']

    ret = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if (imp.name != None) and (imp.name != ""):
                for anti in antidbgs:
                    if imp.name.startswith(anti):
                        ret.append("\t[+] %s %s" % (hex(imp.address),imp.name))
    if len(ret):
        resp = "Yes"
        if verb == True:
            antis = '\n'.join(ret)
            resp = resp + '\n' + antis
        return resp

def antivm(file):
    """
    source: https://code.google.com/p/pyew
    """
    tricks = {
        "Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
        "VirtualPc trick":"\x0f\x3f\x07\x0b",
        "VMware trick":"VMXh",
        "VMCheck.dll":"\x45\xC7\x00\x01",
        "VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
        "Xen":"XenVMM",
        "Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
        "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
        "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
          }
    ret = []
    with open(file,"rb") as f:
        buf = f.read()
        for trick in tricks:
            pos = buf.find(tricks[trick])
            if pos > -1:
                ret.append("\t[+] 0x%x %s" % (pos, trick))

    if len(ret):
        resp = "Yes"
        if verb == True:
            antis = '\n'.join(ret)
            resp = resp + '\n' + antis
        return resp

def urlcheck(file):
    """
    source: https://code.google.com/p/pyew/
    notes:  loading a file in pyew may take some time if it has to analyze all of the functions
    """
    #pyew.codeanalysis = False # ... will shows initial hex dump
    #pyew.loadFile(file) # from pyew_core ... will load file & give basic overview
    #pyew.loadFile(file) # from pyew_core ... will load file & give basic overview
    #pyew.plugins["url"](pyew)(file)
    #ret = []
    #check = pyew.plugins["url"](pyew)
    #if len(check):
    #    resp = "Yes"
    #    if verb == True:
    #        for site in check: 
    #            ret.append('\t' + site)
    #        urls = '\n'.join(ret)
    #        resp = resp + '\n' + urls
    #    return resp

    def doFind(x, buf):
        ret = []
        for l in x.findall(buf, re.IGNORECASE | re.MULTILINE):
            for url in l:
                if len(url) > 8 and url not in ret:
                    ret.append(url)
        return ret

    url_regex = [
        re.compile("((http|ftp|mailto|telnet|ssh)(s){0,1}\:\/\/[\w|\/|\.|\#|\?|\&|\=|\-|\%]+)+", re.IGNORECASE | re.MULTILINE)
    ]

    with open(file, 'rb') as f:
        f.seek(0)
        buf = f.read()
        ret = []
        urls = []

        # ASCII check
        for x in url_regex:
            ret += doFind(x, buf)

        # UNICODE check
        buf = buf.replace("\x00", "")
        for x in url_regex:
            ret += doFind(x, buf)

    # Uniquely print them so no duplicates from ASCII/UNICODE
    if len(ret):
        resp = "Yes"
        if verb == True:
            all_urls = []
            for site in list(set(ret)):
                    urls.append('\t[+] ' + site)
            all_urls = '\n'.join(urls)
            resp = resp + '\n' + all_urls
        return resp

def shellcode(file):    
    """
    import pylibemu
    instructions: http://blog.xanda.org/2012/05/16/installation-of-libemu-and-pylibemu-on-ubuntu/
    """
    print (header("Shellcode test:"))
    pyew.loadFromBuffer(file)
    pyew.plugins["sc"](pyew)
    #import pylibemu
    #emulator = pylibemu.Emulator()
    #emulator.run(ifile)
    print

def anomalies(file):
    """
    source: http://securityxploded.com/exe-scan.php
    notes:  using the peutils version from : http://malware-analysis.googlecode.com/svn-history/r74/trunk/MalwareAnalysis/malware_analysis/pe_struct/peutils.py
    """
    ret = []

    # Entropy based check.. imported from peutils
    pack = peutils.is_probably_packed(pe)
    if pack == 1:
        ret.append("Based on the sections entropy check, the file is possibly packed")

    # SizeOfRawData Check.. some times size of raw data value is used to crash some debugging tools.
    nsec = pe.FILE_HEADER.NumberOfSections
    for i in range(0,nsec-1):
        if i == nsec-1:
            break
	else:
            nextp = pe.sections[i].SizeOfRawData + pe.sections[i].PointerToRawData
            currp = pe.sections[i+1].PointerToRawData
            if nextp != currp:
                ret.append("The Size Of Raw data is valued illegal... The binary might crash your disassembler/debugger")
                break
            else:
                pass
					
    # Non-Ascii or empty section name check	
    for sec in pe.sections:
        if not re.match("^[.A-Za-z][a-zA-Z]+",sec.Name):
            ret.append("Non-ASCII or empty section names detected")
            break
		
    # Size of optional header check
    if pe.FILE_HEADER.SizeOfOptionalHeader != 224:
        ret.append("Illegal size of optional Header")
		
    # Zero checksum check
    if pe.OPTIONAL_HEADER.CheckSum == 0:
        ret.append("Header Checksum is zero")
		
    # Entry point check	
    enaddr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    vbsecaddr = pe.sections[0].VirtualAddress
    ensecaddr = pe.sections[0].Misc_VirtualSize
    entaddr = vbsecaddr + ensecaddr
    if enaddr > entaddr:
        ret.append("Enrty point is outside the 1st(.code) section. Binary is possibly packed")
		
    # Number of directories check	
    if pe.OPTIONAL_HEADER.NumberOfRvaAndSizes != 16:
        ret.append("Optional Header NumberOfRvaAndSizes field is valued illegal")
		
    # Loader flags check	
    if pe.OPTIONAL_HEADER.LoaderFlags != 0:
        ret.append("Optional Header LoaderFlags field is valued illegal")
			
    # TLS (Thread Local Storage) callback function check
    if hasattr(pe,"DIRECTORY_ENTRY_TLS"):
        ret.append("TLS callback functions array detected at 0x%x" % pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
        callback_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        ret.append("Callback Array RVA 0x%x" % callback_rva)

    # Service DLL check
    if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):
        exp_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if re.match('ServiceMain', exp.name):
                ret.append("ServiceMain exported, looks to be a service")
        # EXE file with exports check
        import magic # ! this is a repetetive task from info within pescanner
        try:
            with open(file, "rb") as f:
                data = f.read()
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            if not re.match('.*\(DLL\)\s\(GUI\).*', ms.buffer(data)) and exp_count > 1:
                ret.append("EXE file with exports")
            else:
                # DLL without an export for either of ServiceMain or DllMain check
                dll_ep = [e for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if re.match('ServiceMain|DllMain', e.name)]
                if not dll_ep: 
                    ret.append("DLL doesn't contain either of ServiceMain or DllMain")
        except Exception, msg:
            print msg
            pass

    # Empty FileInfo check
    if hasattr(pe, "VS_VERSIONINFO"):
        if hasattr(pe, "FileInfo"):
            for entry in pe.FileInfo:
                if hasattr(entry, 'StringTable'):
                    for st_entry in entry.StringTable:
                        for str_entry in st_entry.entries.items():
                             if 'CompanyName' in str_entry and len((str_entry[1])) == 0:
                                 ret.append("Emtpy Company Name field")
                             elif 'FileDescription' in str_entry and len((str_entry[1])) == 0:
                                 ret.append("Emtpy File Description field")
    else:
        ret.append("No Version Info attribs")

    if len(ret):
        resp = "Yes"
        if verb == True:
            anoms = []
            for i in ret:
                    anoms.append('\t[+] ' + i)
            anoms = '\n'.join(anoms)
            resp = resp + '\n' + anoms
        return resp

def main():
    """
    Return the results...
    """
    analyze(file)
    #shellcode(file) -> does this work?
    sigchecker(file)
    results = []
    results.append(header("Misc. Info"))
    results.append("Adobe Malware Classifier: %s" % adobe_classifer(file))
    results.append("Anomalies/Flags\t\t: %s" % anomalies(file))
    results.append("Anti-VM\t\t\t: %s" % antivm(file))
    results.append("Anti-Dbg\t\t: %s" % antidbg(file))
    results.append("Embedded File(s)\t: %s" % embed(file))
    results.append("URLs\t\t\t: %s" % urlcheck(file))
    results.append("")
    print '\n'.join(results)

if __name__ == "__main__":
    '''
    if os.path.isdir(f):
        # Recursivly walk the supplied path and process files accordingly
        for root, dirs, files in os.walk(f):
            for name in files:
                file = os.path.join(root, name)
    elif os.path.isfile(f):
        file = f
    '''
    main()
