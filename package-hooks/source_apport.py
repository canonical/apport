'''Apport package hook for apport itself.

This adds /var/log/apport.log and the file listing in /var/crash to the report.

(c) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>'''

APPORT_LOG = '/var/log/apport.log'

import os.path, subprocess

def add_info(report):
    if os.path.exists(APPORT_LOG):
        report['ApportLog'] = open(APPORT_LOG).read()
    stat = subprocess.Popen('stat -c %a:%u:%g:%s:%y:%x:%n /var/crash/*',
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    report['CrashReports'] = stat.communicate()[0]
