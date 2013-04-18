#!/usr/bin/python
import os
import logging
import subprocess
import re
import glob
import time
log = logging.getLogger(__name__)
MOLOCH_CAPTURE_BIN = "/data/moloch/bin/moloch-capture"
MOLOCH_CAPTURE_CONF = "/data/moloch/etc/config.ini"
CUCKOO_INSTANCE_TAG = "Java6"
PATH_TO_PCAPS="../storage/analyses/*/dump.pcap"
def cmd_wrapper(cmd):
    print("running command and waiting for it to finish %s" % (cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout,stderr = p.communicate()
    return (p.returncode, stdout, stderr)

def importpcaps():
    """Run Moloch to import pcap
    @return: hash with alerts 
    """
    pcaps = glob.glob(PATH_TO_PCAPS)
    for pcap in pcaps:
        print pcap
        m = re.search(r"\/(?P<task_id>\d+)\/dump.pcap$",pcap)
        if m == None:
            return 0
        else:
            task_id = m.group("task_id")

        if not os.path.exists(MOLOCH_CAPTURE_BIN):
            print("Unable to Run moloch-capture: BIN File %s Does Not Exist" % (MOLOCH_CAPTURE_BIN))
            return 0

        if not os.path.exists(MOLOCH_CAPTURE_CONF):
            print("Unable to Run moloch-capture Conf File %s Does Not Exist" % (MOLOCH_CAPTURE_CONF))
            return 0
        try:
            cmd = "%s -c %s -r %s -n %s -t %s" % (MOLOCH_CAPTURE_BIN,MOLOCH_CAPTURE_CONF,pcap,CUCKOO_INSTANCE_TAG,task_id)
            ret,stdout,sderr = cmd_wrapper(cmd)
            time.sleep(1)
            if ret == 0:
                print("moloch: imported pcap %s" % (pcap))
            else:
                print("moloch-capture returned a Exit Value Other than Zero %s" % (stderr))
        except Exception,e:
            print("Unable to Run moloch-capture: %s" % e)

importpcaps()     
