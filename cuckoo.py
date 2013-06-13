#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import logging
import argparse

try:
    from lib.cuckoo.common.logo import logo
    from lib.cuckoo.common.constants import CUCKOO_VERSION
    from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooDependencyError
    from lib.cuckoo.core.startup import *
    from lib.cuckoo.core.scheduler import Scheduler
    from lib.cuckoo.core.resultserver import Resultserver
except (CuckooDependencyError, ImportError) as e:
    sys.exit("ERROR: Missing dependency: %s" % e)

log = logging.getLogger()

def write_pid(pidfile):
    pid = str(os.getpid())
    try:
        file(pidfile, 'w').write(pid)
    except Exception as e:
        sys.stderr.write("Failed to write pid %s to file %s:%s\n" % (pid,pidfile,e))
        return 1
    return 0

def remove_pid(pidfile):
    if os.path.isfile(pidfile):
        try:
            os.remove(pidfile)
        except:
            sys.stderr.write("Failed to remove pid file %s\n" % pidfile)
            return 1
    else:
        sys.stderr.write("Pid file does not exist %s\n" % pidfile)
        return 1
    return 0

def main():
    logo()
    check_working_directory()
    check_configs()
    check_version()
    create_structure()

    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-v", "--version", action="version", version="You are running Cuckoo Sandbox %s" % CUCKOO_VERSION)
    parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
    parser.add_argument("-P", "--pid", help="Write pid to this file", action="store", required=False)
    args = parser.parse_args()

    if args.pid:
        write_pid(args.pid) 


    if args.artwork:
        import time
        try:
            while True:
                time.sleep(1)
                logo()
        except KeyboardInterrupt:
            if args.pid:
                remove_pid(args.pid)
            return

    init_logging()

    if args.quiet:
        log.setLevel(logging.WARN)
    elif args.debug:
        log.setLevel(logging.DEBUG)

    init_modules()

    Resultserver()

    try:
        sched = Scheduler()
        sched.start()
    except KeyboardInterrupt:
        sched.stop()
        if args.pid:
            remove_pid(args.pid)
 

if __name__ == "__main__":
    try:
        main()
    except CuckooCriticalError as e:
        message = "%s: %s" % (e.__class__.__name__, e)
        if len(log.handlers) > 0:
            log.critical(message)
        else:
            sys.stderr.write("%s\n" % message)

        sys.exit(1)
