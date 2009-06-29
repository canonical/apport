#!/usr/bin/python

from glob import glob
import os.path, shutil, sys

try:
    import DistUtilsExtra.auto
except ImportError:
    import sys
    print >> sys.stderr, 'To build Apport you need https://launchpad.net/python-distutils-extra'
    sys.exit(1)

assert DistUtilsExtra.auto.__version__ >= '2.2', 'needs DistUtilsExtra.auto >= 2.2'

# try to auto-setup packaging_impl
if len(sys.argv) >= 2 and sys.argv[1] != 'sdist' and not os.path.exists('apport/packaging_impl.py'):
    if os.path.exists('/etc/apt/sources.list'):
        print 'Installing apt/dpkg packaging backend.'
        shutil.copy('backends/packaging-apt-dpkg.py', 'apport/packaging_impl.py')
    elif os.path.exists('/usr/bin/rpm'):
        print 'Installing RPM packaging backend.'
        shutil.copy('backends/packaging_rpm.py', 'apport/packaging_impl.py')
    else:
        print >> sys.stderr, 'Could not determine system package manager. Copy appropriate backends/packaging* to apport/packaging_impl.py'
        sys.exit(1)

DistUtilsExtra.auto.setup(name='apport',
      author='Martin Pitt',
      author_email='martin.pitt@ubuntu.com',
      url='https://wiki.ubuntu.com/Apport',
      license='gpl',
      description='intercept, process, and report crashes and bug reports',
      version='1.5',

      data_files=[('share/mime/packages', glob('xdg-mime/*')),
                  ('share/apport', glob('kde/*.ui')), #TODO: use pykdeuic modules
                  ('share/apport/testsuite/', glob('test/*')),
                  ('share/doc/apport/', glob('doc/*.txt')),
                  ],
      scripts=['gtk/apport-gtk', 'kde/apport-kde', 'cli/apport-cli'],
)
