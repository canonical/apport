#!/usr/bin/python

# Determine the order of events in apport, based on some constraints.
# Copyright (c) 2006 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

from logilab.constraint import *

def print_solution(s):
    sol = [None] * len(s.keys())
    for k, v in s.iteritems():
	assert sol[v] == None
	sol[v] = k
    print sol

variables = [] # will be initialized from all occuring constraint variables

# constraints
before = (
    # necessary:
    ('copy_coredump','parent_exit'),
    ('report_creation','droppriv'),
    ('droppriv','temp_creation'),
    ('runtime_info','droppriv'),
    ('runtime_info','parent_exit'),
    ('droppriv','static_info'),
    ('fork','temp_creation'),
    ('fork','runtime_info'),
    ('copy_coredump','static_info'),
    ('temp_creation','copy_coredump'),
    ('report_creation','report_writing'),
    ('static_info','report_writing'),
    ('runtime_info','report_writing'),

    # nice to have:
    ('parent_exit','static_info'), # performance and reason why we fork in the first place
)

constraints = []
for v1, v2 in before:
    constraints.append(fd.make_expression((v1, v2), '%s < %s' % (v1, v2)))
    if not v1 in variables:
	variables.append(v1)
    if not v2 in variables:
	variables.append(v2)

# do not do two actions at the same time
for v1 in variables:
    for v2 in variables:
        if v2 != v1:
            constraints.append(fd.make_expression((v1, v2), '%s != %s'%(v1, v2)))

# define variable domains
domains = {}
for v in variables:
    domains[v] = fd.FiniteDomain(range(len(variables)))

# solve
r = Repository(variables, domains, constraints)
for s in Solver().solve(r):
    print_solution(s)
