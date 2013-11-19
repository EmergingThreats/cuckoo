#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import argparse
try:
    from jinja2.loaders import FileSystemLoader
    from jinja2.environment import Environment
except ImportError:
    sys.stderr.write("ERROR: Jinja2 library is missing")
    sys.exit(1)
try:
    from bottle import route, run, static_file, redirect, request, HTTPError, hook, response
except ImportError:
    sys.stderr.write("ERROR: Bottle library is missing")
    sys.exit(1)

logging.basicConfig()
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.utils import store_temp_file
from lib.cuckoo.common.config import Config

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


# Templating engine.
env = Environment()
env.loader = FileSystemLoader(os.path.join(CUCKOO_ROOT, "data", "html"))
# Global db pointer.
db = Database()
redirectors=[]
rddict={}
pools=[]

try:
    pcfg = Config(cfg=os.path.join(CUCKOO_ROOT,"conf","redirectors.conf"))
    rddict = pcfg.get('redirectors')
    for entry in rddict:
        redirectors.append(entry)
except:
    redirectors = None
    print("failed to get redirectors")

try:
    pcfg = Config(cfg=os.path.join(CUCKOO_ROOT,"conf","processing.conf"))
    suricfg = pcfg.get('suricata')
    molochcfg = pcfg.get('network-moloch')
except:
    suricfg = None
    molochcfg = None
    print("failed to get suri/moloch config blocks")

try:
    pools=open(os.path.join(CUCKOO_ROOT,"conf","pools.txt")).read().splitlines()
except Exception as e:
    print("failed to read pools config %s" % (e))

@hook("after_request")
def custom_headers():
    """Set some custom headers across all HTTP responses."""
    response.headers["Server"] = "Machete Server"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Expires"] = "0"

@route("/")
def index():
    context = {}
    template = env.get_template("submit.html")
    return template.render({"context" : context, "pools": pools, "redirectors" : redirectors})

@route("/browse")
def browse():
    rows = db.list_tasks(args.limit)

    tasks = []
    for row in rows:
        task = {
            "id" : row.id,
            "target" : row.target,
            "category" : row.category,
            "status" : row.status,
            "added_on" : row.added_on,
            "surialert_cnt": row.surialert_cnt,
            "surihttp_cnt": row.surihttp_cnt,
            "suritls_cnt": row.suritls_cnt,
            "processed" : False
        }

        if os.path.exists(os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["id"]), "reports", "report.html")):
            task["processed"] = True

        if row.category == "file":
            try:
                sample = db.view_sample(row.sample_id)
                task["md5"] = sample.md5
            except:
                task["md5"] = "unknown"

        tasks.append(task)

    template = env.get_template("browse.html")

    return template.render({"rows" : tasks, "os" : os, "suricfg" : suricfg, "molochcfg" : molochcfg})

@route("/static/<filename:path>")
def server_static(filename):
    return static_file(filename, root=os.path.join(CUCKOO_ROOT, "data", "html"))

@route("/submit", method="POST")
def submit():
    context = {}
    errors = False

    package  = request.forms.get("package", "")
    options  = request.forms.get("options", "")
    priority = request.forms.get("priority", 1)
    timeout  = request.forms.get("timeout", "")
    url      = request.forms.get("url","")
    urlrd    = request.forms.get("urlrd","")
    pool_id  = request.forms.get("pool_id","default")
    data = request.files.file

    try:
        priority = int(priority)
    except ValueError:
        context["error_toggle"] = True
        context["error_priority"] = "Needs to be a number"
        errors = True

    if pool_id not in pools:
        context["error_toggle"] = True
        context["error_pool_id"] = "Invalid Pool"
        errors = True
        print "poolid %s not in %s" % (pool_id,pools)

    # File or URL mandatory
    if (data == None or data == "") and (url == None or url == ""):
        context["error_toggle"] = True
        context["error_file"] = "Mandatory"
        errors = True
    
    if url and url != "":
        if urlrd != None and urlrd != "" and urlrd != "None":
            if rddict.has_key(urlrd):
               url = "%s%s" % (rddict[urlrd],url)
            else:
               context["error_toggle"] = True
               context["error_urlrd"] = "Invalid Redirector"
               errors = True
               print("urlrd %s not in %s" % (urlrd,rddict))
        if errors:
            template = env.get_template("submit.html")
            return template.render({"timeout" : timeout,
                                    "priority" : priority,
                                    "options" : options,
                                    "package" : package,
                                    "context" : context,
                                    "pool_id" : pool_id})
        else:
            task_id = db.add_url(url,
                                 package=package,
                                 timeout=timeout,
                                 options=options,
                                 priority=priority,
                                 pool_id=pool_id)
        
        template = env.get_template("success.html")
        return template.render({"taskid" : task_id,
                                "url" : url.decode("utf-8")})


    else:
        temp_file_path = store_temp_file(data.file.read(), data.filename)

        task_id= db.add_path(file_path=temp_file_path,
                             timeout=timeout,
                             priority=priority,
                             options=options,
                             package=package,
                             pool_id=pool_id)

        template = env.get_template("success.html")
        return template.render({"taskid" : task_id,
                                "submitfile" : data.filename.decode("utf-8")})

@route("/view/<task_id>")
def view(task_id):
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "reports", "report.html")

    if not os.path.exists(report_path):
        return HTTPError(code=404, output="Report not found")

    return open(report_path, "rb").read()

@route("/pcap/<task_id>")
def pcap(task_id):
    # Check if the specified task ID is valid
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    pcap_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
    #print pcap_path
    # Check if the HTML report exists
    if not os.path.exists(pcap_path):
        return HTTPError(code=404, output="Report not found")

    # Return content of the HTML report
    return static_file("dump.pcap", root=pcap_path, download="%s.pcap" % (task_id))

@route("/surihttp/<task_id>")
def surihttp(task_id):
    # Check if the specified task ID is valid
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    suri_http_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id,"logs",suricfg['httplog'])
    #print suri_http_path
    # Check if the HTML report exists
    if not os.path.exists(suri_http_path):
        return HTTPError(code=404, output="Report not found")
    response.set_header('Content-Type', 'text/plain; charset=UTF-8')
    # Return content of the HTML report
    return open(suri_http_path, "rb").read()

@route("/surialert/<task_id>")
def surialert(task_id):
    # Check if the specified task ID is valid
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    suri_alert_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id,"logs",suricfg['alertlog'])
    #print suri_alert_path
    # Check if the HTML report exists
    if not os.path.exists(suri_alert_path):
        return HTTPError(code=404, output="Report not found")
    response.set_header('Content-Type', 'text/plain; charset=UTF-8')
    # Return content of the HTML report
    return open(suri_alert_path, "rb").read()

@route("/suritls/<task_id>")
def surialert(task_id):
    # Check if the specified task ID is valid
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    suri_alert_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id,"logs",suricfg['tlslog'])
    #print suri_alert_path
    # Check if the HTML report exists
    if not os.path.exists(suri_alert_path):
        return HTTPError(code=404, output="Report not found")
    response.set_header('Content-Type', 'text/plain; charset=UTF-8')
    # Return content of the HTML report
    return open(suri_alert_path, "rb").read()

@route("/surifiles/<task_id>")
def surifiles(task_id):
    # Check if the specified task ID is valid
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    surizip_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id,"logs","files.zip")
    print surizip_path
    # Check if the HTML report exists
    if not os.path.exists(surizip_path):
        return HTTPError(code=404, output="Report not found")

    # Return content of the HTML report
    return static_file(os.path.basename(surizip_path),root=os.path.dirname(surizip_path),download="%s.zip" % (task_id))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to bind the web server on", default="0.0.0.0", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port to bind the web server on", default=8080, action="store", required=False)
    parser.add_argument("-L", "--limit", help="Number of Jobs to limit in display", default=1000, action="store", required=False)
    parser.add_argument("-P", "--pid", help="Write pid to this file", action="store", required=False)
    args = parser.parse_args()

    if args.pid:
        write_pid(args.pid)

    run(host=args.host, port=args.port, reloader=True)

