#!/usr/bin/env python
# Copyright (C) 2010 Michael Ligh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# [NOTES] -----------------------------------------------------------
# 1) Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
# 2) The only requirement is pefile, other modules just add extra info
# 3) There are various versions of python-magic and pyssdeep - we try to support both
# original : http://code.google.com/p/malwarecookbook/source/browse/trunk/3/8/pescanner.py
#--------------------------------------------------------------------
# Changes made by Glenn P. Edwards Jr.
#   http://hiddenillusion.blogspot.com
#       @hiddenillusion
# Date: 10-15-2012

import hashlib
import time
import binascii
import string
import os, sys
import commands
import re
import collections
try:
    import pefile
    import peutils
except ImportError:
    print 'pefile not installed, see http://code.google.com/p/pefile/'
    sys.exit()

try:
    import magic
except ImportError:
    print 'python-magic is not installed, file types will not be available'
    
try:
    import yara
except ImportError:
    print 'yara-python is not installed, see http://code.google.com/p/yara-project/'

try:
    import pydasm
except ImportError:
    print 'pydams is not installed, see http://code.google.com/p/libdasm/'

def header(msg):
    return "\n" + msg + "\n" + ("=" * 90)

def subTitle(msg):
    return msg + "\n" + ("-" * 40)

# suspicious APIs to alert on 
# updated version from: http://code.google.com/p/peframe/
alerts_api = ['accept', 'AddCredentials', 'bind', 'CertDeleteCertificateFromStore', 'CheckRemoteDebuggerPresent', 'closesocket', 'connect', 'ConnectNamedPipe', 'CopyFile', 'CreateFile', 'CreateProcess', 'CreateToolhelp32Snapshot', 'CreateFileMapping', 'CreateRemoteThread', 'CreateDirectory', 'CreateService', 'CreateThread', 'CryptEncrypt', 'DeleteFile', 'DeviceIoControl', 'DisconnectNamedPipe', 'DNSQuery', 'EnumProcesses', 'ExitThread', 'FindWindow', 'FindResource', 'FindFirstFile', 'FindNextFile', 'FltRegisterFilter', 'FtpGetFile', 'FtpOpenFile', 'GetCommandLine', 'GetThreadContext', 'GetDriveType', 'GetFileSize', 'GetFileAttributes', 'GetHostByAddr', 'GetHostByName', 'GetHostName', 'GetModuleHandle', 'GetProcAddress', 'GetTempFileName', 'GetTempPath', 'GetTickCount', 'GetUpdateRect', 'GetUpdateRgn', 'GetUserNameA', 'GetUrlCacheEntryInfo', 'GetComputerName', 'GetVersionEx', 'GetModuleFileName', 'GetStartupInfo', 'GetWindowThreadProcessId', 'HttpSendRequest', 'HttpQueryInfo', 'IcmpSendEcho', 'IsDebuggerPresent', 'InternetCloseHandle', 'InternetConnect', 'InternetCrackUrl', 'InternetQueryDataAvailable', 'InternetGetConnectedState', 'InternetOpen', 'InternetQueryDataAvailable', 'InternetQueryOption', 'InternetReadFile', 'InternetWriteFile', 'LdrLoadDll', 'LoadLibrary', 'LoadLibraryA', 'LockResource', 'listen', 'MapViewOfFile', 'OutputDebugString', 'OpenFileMapping', 'OpenProcess', 'Process32First', 'Process32Next', 'recv', 'ReadProcessMemory', 'RegCloseKey', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue', 'RegEnumKey', 'RegOpenKey', 'send', 'sendto', 'SetKeyboardState', 'SetWindowsHook', 'ShellExecute', 'Sleep', 'socket', 'StartService', 'TerminateProcess', 'UnhandledExceptionFilter', 'URLDownload', 'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx', 'WinExec', 'WriteProcessMemory', 'WriteFile', 'WSASend', 'WSASocket', 'WSAStartup', 'ZwQueryInformation']

alerts_imp = ['ntoskrnl.exe', 'hal.dll', 'ndis.sys']

# legit entry point sections
good_ep_sections = ['.text', '.code', 'CODE', 'INIT', 'PAGE']

# path to clamscan (optional)
clamscan_path = '/usr/bin/clamscan'

def convert_char(char):
    if char in string.ascii_letters or \
       char in string.digits or \
       char in string.punctuation or \
       char in string.whitespace:
        return char
    else:
        return r'\x%02x' % ord(char)

def convert_to_printable(s):
    return ''.join([convert_char(c) for c in s])

def get_filetype(data):
    """There are two versions of python-magic floating around, and annoyingly, the interface 
    changed between versions, so we try one method and if it fails, then we try the other.
    NOTE: you may need to alter the magic_file for your system to point to the magic file."""
    if sys.modules.has_key('magic'):
        try:
            ms = magic.open(magic.MAGIC_NONE) 
            ms.load() 
            return ms.buffer(data)
        except:
            try:
                return magic.from_buffer(data)
            except magic.MagicException:
                magic_custom = magic.Magic(magic_file='C:\windows\system32\magic')
                return magic_custom.from_buffer(data)
    return ''

def get_ssdeep(filename):
    """There are two Python bindings for ssdeep, each with a different interface. So we try
    Jose's pyssdeep first and if it fails, try the one from pypi. Just install one or the other:
    http://code.google.com/p/pyssdeep/
    http://pypi.python.org/packages/source/s/ssdeep/ssdeep-2.5.tar.gz#md5=fd9e5271c01ca389cc621ae306327ab6
    """
    try:
        from ssdeep import ssdeep 
        s = ssdeep()
        return s.hash_file(filename)
    except:
        try:
            import ssdeep
            return ssdeep.hash_from_file(filename)
        except:
            pass
    return ''

class PEScanner:
    def __init__(self, files, yara_rules=None, peid_sigs=None):
        self.files = files
        
        # initialize YARA rules if provided 
        if yara_rules and sys.modules.has_key('yara'):
            self.rules = yara.compile(yara_rules)
        else:
            self.rules = None
            
        # initialize PEiD signatures if provided 
        if peid_sigs:
            self.sigs = peutils.SignatureDatabase(peid_sigs)
        else:
            self.sigs = None
        
    def check_ep_section(self, pe):
        """ Determine if a PE's entry point is suspicious """
        name = ''
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pos = 0
        for sec in pe.sections:
            if (ep >= sec.VirtualAddress) and \
               (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
                name = sec.Name.replace('\x00', '')
                break
            else: 
                pos += 1
        return (ep, name, pos)

    def check_verinfo(self, pe):
        """ Determine the version info in a PE file """
        ret = []
        
        if hasattr(pe, 'VS_VERSIONINFO'):
            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                # yes... it annoyed me that much .. ocd whatttt
                                if 'OriginalFilename' in str_entry:
                                    ret.append(convert_to_printable(str_entry[0]) + ': ' + convert_to_printable(str_entry[1]) )
                                else:
                                    ret.append(convert_to_printable(str_entry[0]) + '\t: ' + convert_to_printable(str_entry[1]) )
                    elif hasattr(entry, 'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, 'entry'):
                                ret.append(convert_to_printable(var_entry.entry.keys()[0]) + '\t: ' + var_entry.entry.values()[0])
        return '\n'.join(ret)

    def check_tls(self, pe):
        callbacks = []
        if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
                    pe.DIRECTORY_ENTRY_TLS and \
                    pe.DIRECTORY_ENTRY_TLS.struct and \
                    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
            callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase 
            idx = 0
            while True:
                func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                if func == 0: 
                    break
                callbacks.append(func)
                idx += 1
        return callbacks

    def check_rsrc(self, pe):
        ret = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            i = 0
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = "%s" % resource_type.name
                else:
                    name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = "%d" % resource_type.struct.Id
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                filetype = get_filetype(data)
                                lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                                sublang = pefile.get_sublang_name_for_lang( resource_lang.data.lang, resource_lang.data.sublang )
                                ret[i] = (name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, filetype, lang, sublang)
                                i += 1
        return ret  
                          
    def get_lang(self, pe):
        resources = self.check_rsrc(pe)
        ret = []
        lang_holder = []
        for rsrc in resources.keys():
            (name,rva,size,type,lang,sublang) = resources[rsrc]
            lang_holder.append(lang)
            lang_count = collections.Counter(lang_holder)
            lang_common = lang_count.most_common(1)
            for lang_likely,occur in lang_common:
                ret = lang_likely.split('_')[1]
        return ret

    def check_imports(self, pe):
        ret = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ret
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for entry in alerts_imp:
                if re.search(lib.dll, entry, re.I):
                    ret.append(lib.dll)
            for imp in lib.imports:
                if (imp.name != None) and (imp.name != ""):
                    for alert in alerts_api:
                        if imp.name.startswith(alert):
                            ret.append(imp.name)
        return ret

    def get_timestamp(self, pe):
        val = pe.FILE_HEADER.TimeDateStamp
        ts = '0x%-8X' % (val)
        try:
            ts += ' [%s UTC]' % time.asctime(time.gmtime(val))
            that_year = time.gmtime(val)[0]
            this_year = time.gmtime(time.time())[0]
            if that_year < 2000 or that_year > this_year:
                ts += " [SUSPICIOUS]"
        except:
            ts += ' [SUSPICIOUS]'
        return ts

    def check_packers(self, pe):
        packers = []
        if self.sigs:
            matches = self.sigs.match(pe, ep_only = True)
            if matches != None:
                for match in matches:
                    packers.append(match)
        return packers

    def check_yara(self, data):
        ret = []
        if self.rules:
            yarahits = self.rules.match(data=data)
            if yarahits:
              for hit in yarahits:
                ret.append("YARA: %s" % hit.rule)
                #for key, val in hit.strings.iteritems():
                for (key,stringname,val) in hit.strings:
                    makehex = False
                    for char in val:
                        if char not in string.printable:
                            makehex = True
                            break
                    if makehex == True:
                        ret.append("\t%s => %s" % (hex(key), binascii.hexlify(val)))
                    else:
                        ret.append("\t %s => %s" % (hex(key), val))
        return '\n'.join(ret)

    def check_clam(self, file):
        if os.path.isfile(clamscan_path):
            status, output = commands.getstatusoutput("%s %s" % (clamscan_path, file))
            if status != 0:
                return "Clamav: %s" % output.split("\n")[0]
        return ''


    def collect(self, verb):
        count = 0

        for file in self.files:
            out = []

            try:
                FILE = open(file, "rb")
                data = FILE.read()
                FILE.close()
            except:
                continue

            if data == None or len(data) == 0:
                out.append("Cannot read %s (maybe empty?)" % file)
                out.append("")
                continue
                
            try:
                pe = pefile.PE(data=data, fast_load=True)
                pe.parse_data_directories( directories=[ 
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            except:
                out.append("Cannot parse %s (maybe not PE?)" % file)
                out.append("")
                continue

            # source: https://code.google.com/p/pyew/
            def get_filearch(data):
                if pe.FILE_HEADER.Machine == 0x14C: # IMAGE_FILE_MACHINE_I386
                    processor="intel"
                    type = 32
                    return "32 Bits binary"
                elif pe.FILE_HEADER.Machine == 0x8664: # IMAGE_FILE_MACHINE_AMD64
                    processor="intel"
                    type = 64
                    return "64 Bits binary"

            out.append(("#" * 90) + "\n[%d] File: %s\n" % (count, file) + ("#" * 90))
            out.append(header("Meta-data"))
            out.append("Size\t\t: %d bytes" % len(data))
            out.append("Type\t\t: %s" % get_filetype(data)) 
            out.append("Architecture\t: %s" % get_filearch(data)) 
            out.append("MD5\t\t: %s"  % hashlib.md5(data).hexdigest())
            out.append("SHA1\t\t: %s" % hashlib.sha1(data).hexdigest())
            out.append("ssdeep\t\t: %s" % get_ssdeep(file))
            out.append("Date\t\t: %s" % self.get_timestamp(pe))
            out.append("Language\t: %s" % self.get_lang(pe))

            crc_claimed = pe.OPTIONAL_HEADER.CheckSum
            crc_actual  = pe.generate_checksum()
            out.append("CRC:\t(Claimed) : 0x%x, (Actual): 0x%x %s" % (
                crc_claimed, crc_actual, "[SUSPICIOUS]" if crc_actual != crc_claimed else ""))

            packers = self.check_packers(pe)
            if len(packers):
                out.append("Packers\t\t: %s" % ','.join(packers))
         
            # Alert if the EP section is not in a known good section or if its in the last PE section
            (ep, name, pos) = self.check_ep_section(pe)
            ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
            s = "Entry Point\t: %s %s %d/%d" % (hex(ep_ava), name, pos, len(pe.sections))
            if (name not in good_ep_sections) or pos == len(pe.sections):
                s += " [SUSPICIOUS]"
            out.append(s)

            # Dism. the first 100 bytes of the Entry Point
            s = ("=" * 16 + '\n' + subTitle("Offset | Instructions"))
            data = pe.get_memory_mapped_image()[ep:ep+100]
            offset = 0
            while offset < len(data):
                i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                s += "\n%d\t%s" % (offset,pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset))
                offset += i.length
            out.append(s)

            verinfo = self.check_verinfo(pe)
            if len(verinfo):
                out.append(header("Version info"))
                out.append(verinfo)

            if sys.modules.has_key('yara'):
                yarahits = self.check_yara(data)
            else:
                yarahits = []
                
            clamhits = self.check_clam(file)
            
            if len(yarahits) or len(clamhits):
                out.append(header("Signature scans"))
                out.append(yarahits)
                out.append(clamhits)
                    
            callbacks = self.check_tls(pe)
            if len(callbacks):
                out.append(header("TLS callbacks"))
                for cb in callbacks:
                    out.append("    0x%x" % cb)
                
            out.append(header("Sections"))
            out.append("%-10s %-12s %-12s %-10s %-12s %27s" % ("Name", "VirtAddr", "VirtSize", "RawSize", "MD5", "Entropy"))
            out.append("-" * 90)
            
            for sec in pe.sections:
                s = "%-10s %-12s %-12s %-10s %-12s %-12f" % (
                    ''.join([c for c in sec.Name if c in string.printable]), 
                    hex(sec.VirtualAddress), 
                    hex(sec.Misc_VirtualSize), 
                    hex(sec.SizeOfRawData),
                    sec.get_hash_md5(),
                    sec.get_entropy())
                if sec.SizeOfRawData == 0 or (sec.get_entropy() > 0 and sec.get_entropy() < 1) or sec.get_entropy() > 7:
                    s += "[SUSPICIOUS]"
                out.append(s)

            resources = self.check_rsrc(pe)
            if len(resources):
                out.append(header("Resource entries"))
                names_holder = []
                for rsrc in resources.keys():
                    (name,rva,size,type,lang,sublang) = resources[rsrc]
                    names_holder.append(name)
                    names_count = collections.Counter(names_holder)
                    names_common = names_count.most_common()
                out.append("%-18s %-8s" % ("Resource type", "Total"))
                out.append("-" * 25)
                for name,occur in names_common:
                    out.append("%-18s : %-8s" % (name,occur))
                if verb == True:
                    out.append("-" * 90)
                    out.append("%-18s %-8s %-8s %-12s %-24s Type" % ("Name", "RVA", "Size", "Lang", "Sublang"))
                    out.append("-" * 90)
                    for rsrc in resources.keys():
                        (name,rva,size,type,lang,sublang) = resources[rsrc]
                        out.append("%-18s %-8s %-8s %-12s %-24s %s" % (name, hex(rva), hex(size), lang, sublang, type)) 
                 
            # source: https://code.google.com/p/pyew/
            imports_total = len(pe.DIRECTORY_ENTRY_IMPORT)
            if imports_total > 0:
                c = 1
                out.append(header("Imports"))
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    out.append("[%s] %s" % (c,entry.dll))
                    if verb == True:
                        for imp in entry.imports:
                            if (imp.name != None) and (imp.name != ""):
                                out.append("\t%s %s" % (hex(imp.address),imp.name))
                    c += 1
 
            imports = self.check_imports(pe)
            if len(imports):
                ret = []
                out.append(header("Suspicious IAT alerts"))
                for imp in imports:
                    ret.append(imp)
                c = 1
                for i in sorted(set(ret)):
                    out.append("[%s] %s" % (c,i))
                    c += 1

            # Grab the exports info , if available
            if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):
                c = 1
                out.append(header("Exports"))
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if verb == True:
                        out.append("[%s] %s %s" % (c,hex(exp.address),exp.name))
                    else:
                        out.append("[%s] %s" % (c,exp.name))
                    c += 1

            out.append("")
            print '\n'.join(out)
            count += 1
            
if __name__ == "__main__":
        
    if len(sys.argv) != 2:
      print "Usage: %s <file|directory>\n" % (sys.argv[0])
      sys.exit()
      
    object = sys.argv[1]
    files  = []
    
    if os.path.isdir(object):
        for root, dirs, filenames in os.walk(object):
            for name in filenames:
                files.append(os.path.join(root, name))
    elif os.path.isfile(object):
        files.append(object)
    else:
        print "You must supply a file or directory!"
        sys.exit()
    
    verb = False
    # You should fill these in with a path to your YARA rules and PEiD database
    pescan = PEScanner(files, '/path/to/rules.yara', '/path/to/userdb.txt')
    pescan.collect(verb)
