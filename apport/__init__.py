from apport.report import Report

from apport.packaging_impl import impl as packaging

# fix gettext to output proper unicode strings
import gettext

def unicode_gettext(str):
    trans = gettext.gettext(str)
    if type(trans) == type(u''):
        return trans
    return trans.decode('UTF-8')
