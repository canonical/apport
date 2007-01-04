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
      version='0.1',
      author='Martin Pitt',
      author_email='martin.pitt@ubuntu.com',
      maintainer='Martin Pitt',
      maintainer_email='martin.pitt@ubuntu.com',
      url='http://www.ubuntu.com',
      license='gpl',
      description='read, write, and modify problem reports',
      py_modules=['problem_report'],
      data_files=[('share/apport', ['gtk/apport-gtk.glade', 'gtk/apport-gtk.png'])]+mo_files,
      scripts=['bin/apport', 'bin/apport-checkreports', 'bin/apport-retrace', 'bin/apport-unpack', 'gtk/apport-gtk'],
      packages=['apport']
      )
