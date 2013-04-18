# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import subprocess
import re

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)
MOLOCH_CAPTURE_BIN = "/data/moloch/bin/moloch-capture"
MOLOCH_CAPTURE_CONF = "/data/moloch/etc/config.ini"
CUCKOO_INSTANCE_TAG = "Java6"
class NetworkMoloch(Processing):
    """Suricata processing."""
    def cmd_wrapper(self,cmd):
        #print("running command and waiting for it to finish %s" % (cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout,stderr = p.communicate()
        return (p.returncode, stdout, stderr)
        
    def run(self):
        """Run Moloch to import pcap
        @return: hash with alerts 
        """
        self.key = "moloch"
        MOLOCH_CAPTURE_BIN = self.options.get("capture", None)
        MOLOCH_CAPTURE_CONF = self.options.get("captureconf",None)
        CUCKOO_INSTANCE_TAG = self.options.get("node",None)

        results = {}
        m = re.search(r"\/(?P<task_id>\d+)\/logs$",self.logs_path)
        if m == None:
            log.warning("Unable to find task id from %s" % (self.logs_path))
            return results  
        else:
            task_id = m.group("task_id")

        if not os.path.exists(MOLOCH_CAPTURE_BIN):
            log.warning("Unable to Run moloch-capture: BIN File %s Does Not Exist" % (MOLOCH_CAPTURE_BIN))
            return results 
        
        if not os.path.exists(MOLOCH_CAPTURE_CONF):
            log.warning("Unable to Run moloch-capture Conf File %s Does Not Exist" % (MOLOCH_CAPTURE_CONF))
            return results        
        try:
            cmd = "%s -c %s -r %s -n %s -t %s" % (MOLOCH_CAPTURE_BIN,MOLOCH_CAPTURE_CONF,self.pcap_path,CUCKOO_INSTANCE_TAG,task_id)
            ret,stdout,sderr = self.cmd_wrapper(cmd)
            if ret == 0:
               log.warning("moloch: imported pcap %s" % (self.pcap_path))
            else:
                log.warning("moloch-capture returned a Exit Value Other than Zero %s" % (stderr))
        except Exception,e:
            log.warning("Unable to Run moloch-capture: %s" % e)

        return results 
