# You do not want to know why this empty file exist! You have been warned!
#
# This empty module exist to be imported by `apport/__init__.py` before
# `apport/__init__.py` defines the `packaging` object instance. This makes
# following code work:
#
# >>> import apport.packaging
# >>> type(apport.packaging)
# apport.packaging_impl.apt_dpkg._AptDpkgPackageInfo
#
# Importing `apport.packaging` will import `apport` first. This will import
# `apport.packaging` and shadow it.
