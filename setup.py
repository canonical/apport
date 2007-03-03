#!/usr/bin/python

from distutils.core import setup

import subprocess, glob, os.path

mo_files = []
# HACK: make sure that the mo files are generated and up-to-date
subprocess.call(['make', '-C', 'po', 'build-mo'])
for filepath in glob.glob("po/mo/*/LC_MESSAGES/*.mo"):
    lang = filepath[len("po/mo/"):]
    targetpath = os.path.dirname(os.path.join("share/locale",lang))
    mo_files.append((targetpath, [filepath]))

setup(name='apport',
      author='Martin Pitt',
      author_email='martin.pitt@ubuntu.com',
      maintainer='Martin Pitt',
      maintainer_email='martin.pitt@ubuntu.com',
      url='http://www.ubuntu.com',
      license='gpl',
      description='read, write, and modify problem reports',
      py_modules=['problem_report'],
      data_files=[('share/apport', ['gtk/apport-gtk.glade'] + glob.glob('qt4/*.ui')),
                  ('share/icons/hicolor/scalable/apps', ['apport/apport.svg']),
                  ('share/apport/testsuite/', ['test-apport', 'test-hooks', 'run-tests']),
                  ('share/doc/apport/', glob.glob('doc/*'))]+mo_files,
      scripts=['bin/apport', 'bin/apport-checkreports', 'bin/apport-retrace',
	  'bin/apport-unpack', 'bin/package_hook', 'bin/kernel_hook',
          'gtk/apport-gtk', 'qt4/apport-qt'],
      packages=['apport']
      )
