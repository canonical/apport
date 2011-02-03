from apport.report import Report

from apport.packaging_impl import impl as packaging

import sys

# fix gettext to output proper unicode strings
import gettext

def unicode_gettext(str):
    trans = gettext.gettext(str)
    if isinstance(trans, unicode):
        return trans
    return trans.decode('UTF-8')

def fatal(msg, *args):
    '''Print out an error message and exit the program.'''

    error(msg, *args)
    sys.exit(1)

def error(msg, *args):
    '''Print out an error message.'''

    sys.stderr.write('ERROR: ')
    sys.stderr.write(msg % args)
    sys.stderr.write('\n')

def warning(msg, *args):
    '''Print out an warning message.'''

    sys.stderr.write('WARNING: ')
    sys.stderr.write(msg % args)
    sys.stderr.write('\n')
