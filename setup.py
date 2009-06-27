#!/usr/bin/python

from glob import glob

try:
    import DistUtilsExtra.auto
except ImportError:
    import sys
    print >> sys.stderr, 'To build Apport you need https://launchpad.net/python-distutils-extra'
    sys.exit(1)

assert DistUtilsExtra.auto.__version__ >= '2.2', 'needs DistUtilsExtra.auto >= 2.2'

DistUtilsExtra.auto.setup(name='apport',
      author='Martin Pitt',
      author_email='martin.pitt@ubuntu.com',
      url='https://wiki.ubuntu.com/Apport',
      license='gpl',
      description='intercept, process, and report crashes and bug reports',
      version='1.4',

      data_files=[('share/mime/packages', glob('xdg-mime/*')),
                  ('share/apport', glob('kde/*.ui')), #TODO: use pykdeuic modules
                  ('share/apport/testsuite/', glob('test/*')),
                  ('share/doc/apport/', glob('doc/*.txt')),
                  ],
      scripts=['gtk/apport-gtk', 'kde/apport-kde', 'cli/apport-cli'],
)
