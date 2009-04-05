#!/usr/bin/python

from distutils.core import setup
import distutils.command.install_data

import subprocess, glob, os.path

class my_install_data(distutils.command.install_data.install_data):
    '''Install files from etc/ and build gettext *.mo'''

    def run(self):
        for (root, _, files) in os.walk('etc'):
            self.data_files.append((os.path.join('/', root), 
                    [os.path.join(root, f) for f in files]))

        subprocess.call(['make', '-C', 'po', 'build-mo'])
        for filepath in glob.glob('po/mo/*/LC_MESSAGES/*.mo'):
            lang = filepath[len('po/mo/'):]
            targetpath = os.path.dirname(os.path.join('share/locale',lang))
            self.data_files.append((targetpath, [filepath]))

        distutils.command.install_data.install_data.run(self)

setup(name='apport',
      author='Martin Pitt',
      author_email='martin.pitt@ubuntu.com',
      maintainer='Martin Pitt',
      maintainer_email='martin.pitt@ubuntu.com',
      url='https://wiki.ubuntu.com/Apport',
      license='gpl',
      description='read, write, and modify problem reports',
      py_modules=['problem_report', 'apport_python_hook'],
      data_files=[('share/apport', ['gtk/apport-gtk.glade'] + glob.glob('qt4/*.ui')),
                  ('share/icons/hicolor/scalable/apps', ['apport/apport.svg']),
                  ('share/mime/packages', glob.glob('xdg-mime/*')),
                  ('share/apport/testsuite/', ['test-apport', 'test-hooks', 'run-tests']),
                  ('share/doc/apport/', glob.glob('doc/*.txt') + glob.glob('doc/*.pdf')),
                  ('share/apport/package-hooks/', glob.glob('package-hooks/*')),
                  ('share/apport/general-hooks/', glob.glob('general-hooks/*')),
                  ],
      scripts=['bin/apport', 'bin/apport-checkreports', 'bin/apport-retrace',
          'bin/apport-unpack', 'bin/package_hook',
          'bin/kernel_crashdump', 'bin/gcc_ice_hook', 'gtk/apport-gtk',
          'qt4/apport-qt', 'cli/apport-cli', 'bin/dupdb-admin',
          'bin/kernel_oops', 'bin/apportcheckresume'],
      packages=['apport', 'apport.crashdb_impl'],

      cmdclass = { 'install_data': my_install_data },
)
