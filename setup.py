#!/usr/bin/python

from distutils.core import setup

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
      )
