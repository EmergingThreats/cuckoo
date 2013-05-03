# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import subprocess

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)
class Suricata(Processing):
    """Suricata processing."""
    def cmd_wrapper(self,cmd):
        #print("running command and waiting for it to finish %s" % (cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout,stderr = p.communicate()
        return (p.returncode, stdout, stderr)

    def run(self):
        """Run Suricata.
        @return: hash with alerts 
        """
        self.key = "suricata"
        SURICATA_BIN = self.options.get("bin", None)
        SURICATA_CONF = self.options.get("conf", None)
        SURICATA_FAST = self.options.get("alertlog",None)
        SURICATA_TLS = self.options.get("tlslog",None)
        SURICATA_HTTP_LOG = self.options.get("httplog",None)
        SURICATA_FILE_LOG = self.options.get("fileslog",None)
        SURICATA_FILES_DIR = self.options.get("filesdir",None)
        Z7_PATH = self.options.get("7zbin",None)
        FILES_ZIP_PASS = self.options.get("zippass",None)

        suricata = {}
        suricata["alerts"]=[]
        suricata["alert_cnt"] = 0
        suricata["tls"]=[]
        suricata["tls_cnt"] = 0
        suricata["perf"]=[]
        suricata["files"]=[]
        suricata["http"]=[]      
        suricata["http_cnt"]= 0 
       
        SURICATA_FAST_FULL_PATH = "%s/%s" % (self.logs_path,SURICATA_FAST)
        SURICATA_TLS_FULL_PATH = "%s/%s" % (self.logs_path,SURICATA_TLS)
        SURICATA_HTTP_LOG_FULL_PATH = "%s/%s" % (self.logs_path,SURICATA_HTTP_LOG)
        SURICATA_FILE_LOG_FULL_PATH = "%s/%s" % (self.logs_path,SURICATA_FILE_LOG)
        SURICATA_FILES_DIR_FULL_PATH = "%s/%s" % (self.logs_path,SURICATA_FILES_DIR)

        if not os.path.exists(SURICATA_CONF):
            log.warning("Unable to Run Suricata: Conf File %s Does Not Exist" % (SURICATA_CONF))
            return suricata["alerts"]
        
        if not os.path.exists(SURICATA_BIN):
            log.warning("Unable to Run Suricata: Bin File %s Does Not Exist" % (SURICATA_CONF))
            return suricata["alerts"]       
        try:
            cmd = "%s -c %s -l %s -r %s" % (SURICATA_BIN,SURICATA_CONF,self.logs_path,self.pcap_path)
            ret,stdout,stderr = self.cmd_wrapper(cmd)
            if ret == 0:
                if os.path.exists(SURICATA_FAST_FULL_PATH):
                    f = open(SURICATA_FAST_FULL_PATH).readlines()
                    for l in f:
                        suricata["alerts"].append(l)
                        suricata["alert_cnt"] = suricata["alert_cnt"] + 1 
                else:
                    log.warning("Suricata: Failed to find alert log at %s" % (SURICATA_FAST_FULL_PATH))
                if os.path.exists(SURICATA_TLS_FULL_PATH):
                    f = open(SURICATA_TLS_FULL_PATH).readlines()
                    for l in f:
                        suricata["tls"].append(l)
                        suricata["tls_cnt"] = suricata["tls_cnt"] + 1
                else:
                    log.warning("Suricata: Failed to find TLS log at %s" % (SURICATA_TLS_FULL_PATH))

                if os.path.exists(SURICATA_HTTP_LOG_FULL_PATH):
                    f = open(SURICATA_HTTP_LOG_FULL_PATH).readlines()
                    for l in f:
                        suricata["http"].append(l)
                        suricata["http_cnt"] = suricata["http_cnt"] + 1
                else:
                    log.warning("Suricata: Failed to find http log at %s" % (SURICATA_HTTP_LOG_FULL_PATH))

                if os.path.exists(SURICATA_FILE_LOG_FULL_PATH):
                    f = open(SURICATA_FILE_LOG_FULL_PATH).readlines()
                    for l in f:
                        suricata["files"].append(l)
                else:
                    log.warning("Suricata: Failed to find file log at %s" % (SURICATA_FILE_LOG_FULL_PATH))
                if os.path.exists(SURICATA_FILES_DIR_FULL_PATH) and os.path.exists(Z7_PATH):
                    #/usr/bin/7z a -pinfected -y files.zip files files-json.log
                    cmd = "cd %s && %s a -p%s -y files.zip %s %s" % (self.logs_path,Z7_PATH,FILES_ZIP_PASS,SURICATA_FILE_LOG,SURICATA_FILES_DIR)
                    ret,stdout,stderr = self.cmd_wrapper(cmd)
                    if ret != 0:
                        log.warning("Suricata: Failed to create Zip File" % (SURICATA_FILES_DIR_FULL_PATH))
                else:
                    log.warning("Suricata: Failed to find file log at %s" % (SURICATA_FILES_DIR_FULL_PATH))
            else:
                log.warning("Suricata returned a Exit Value Other than Zero %s" % (stderr))
        except Exception,e:
            log.warning("Unable to Run Suricata: %s" % e)
        Database().suri_stats(int(self.task["id"]), suricata["alert_cnt"], suricata["http_cnt"], suricata["tls_cnt"]) 
        return suricata 
