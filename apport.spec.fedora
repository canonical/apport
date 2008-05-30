Summary: read, write, and modify problem reports
Name: apport
Version: 0.89
Release: 0.ww2%{dist}
Source0: %{name}_%{version}.tar.gz
Patch0: apport-%{version}-fedora.patch
License: GPL
Group: Applications/System
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildArch: noarch
# These two might need to be changed for inclusion in Fedora
Vendor: Martin Pitt <martin.pitt@ubuntu.com>
Packager: Will Woods <wwoods@redhat.com>
Url: https://wiki.ubuntu.com/Apport
BuildRequires: python-devel intltool gettext tetex-latex
# Need the ability to use pipes in /proc/sys/kernel/core_pattern
Requires: kernel >= 2.6.19
# FIXME there's probably scads more requires here, need to do some testing
# on a minimal system
Requires: rpm-python yum
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
Requires(postun): /sbin/service

%description
apport automatically collects data from crashed processes and compiles a
problem report in /var/crash/.

This package also provides apport's python libraries and a command line
frontend for browsing and handling the crash reports.

See https://wiki.ubuntu.com/AutomatedProblemReports for more information.

%package gtk
Summary: GTK frontend for the apport crash report system
Group: Applications/System
Requires: pygtk2 pygtk2-libglade pyxdg procps
%description gtk
apport automatically collects data from crashed processes and compiles a
problem report in /var/crash/. 

This package provides a GTK frontend for browsing and handling the
crash reports.

%package qt
Summary: Qt4 frontend for the apport crash report system
Group: Applications/System
Requires: PyQT pyxdg procps
%description qt
apport automatically collects data from crashed processes and compiles a
problem report in /var/crash/.

This package provides a Qt4 frontend for browsing and handling the
crash reports.

# Yes, this is kind of useless in Fedora right now. Alas.
%package retrace
Summary: tools for reprocessing Apport crash reports
Group: Applications/System
%description retrace
apport-retrace recombines an Apport crash report (either a file or a
Launchpad bug) and debug symbol packages (.ddebs) into fully symbolic
stack traces.

This package also ships apport-chroot. This tool can create and
manage chroots for usage with apport-retrace. If the fakeroot and
fakechroot libraries are available (either by installing the packages
or by merely putting their libraries somewhere and setting two
environment variables), the entire process of retracing crashes in
chroots can happen with normal user privileges.

%prep
%setup -n apport
%patch0 -b .fedora

%build
python setup.py build
make -C po
make -C gtk
make -C qt4
make -C doc
# set up the packaging backend
cp backends/packaging_rpm.py backends/packaging_fedora.py apport
ln -s packaging_fedora.py apport/packaging_impl.py

%install
rm -rf $RPM_BUILD_ROOT # clean up before we begin
python setup.py install --root=$RPM_BUILD_ROOT \
                        --install-scripts usr/share/apport
# We'll handle the docs in the %files section
rm -rf $RPM_BUILD_ROOT/usr/share/doc/apport
# Do the man pages
install -d -m755 $RPM_BUILD_ROOT%{_mandir}/man1
install -m644 man/apport-*.1 $RPM_BUILD_ROOT%{_mandir}/man1
# cron job
install -d -m755 $RPM_BUILD_ROOT/etc/cron.daily
install -m755 debian/apport.cron.daily $RPM_BUILD_ROOT/etc/cron.daily/apport
# create the dir for crash reports
install -d -m1777 $RPM_BUILD_ROOT/var/crash
# install initscript
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 apport.init.fedora $RPM_BUILD_ROOT/etc/rc.d/init.d/apport

%clean
rm -rf $RPM_BUILD_ROOT

%post
# Add proper symlinks in /etc/rc*.d
/sbin/chkconfig --add apport
%preun
# Really uninstalling? Stop the service and remove its links
if [ "$1" == "0" ]; then
    /sbin/service apport stop > /dev/null
    /sbin/chkconfig --del apport
fi
%postun
# Upgrading? Restart the service, if it's running
if [ "$1" -ge "1" ]; then
    /sbin/service apport condrestart > /dev/null || :
fi

%files
%defattr(-,root,root)
%dir /var/crash
%doc %{_mandir}/man1/apport-unpack.1*
%doc doc/*
/usr/share/apport/apport
# We include the cli inside the main package
/usr/share/apport/*cli*
/usr/share/apport/apport-checkreports
/usr/share/apport/package_hook
/usr/share/apport/kernel_hook
/usr/share/apport/apport-unpack
/usr/share/locale
/usr/share/icons
/usr/share/apport/testsuite/
/usr/share/apport/package-hooks/
# This is the hook for catching python crashes
/usr/lib/python*/site-packages/apport_python_hook.py*
# In Ubuntu these are in a separate 'python-apport' package
/usr/lib/python*/site-packages/apport/*
# In Ubuntu this library is in 'python-problem-report' 
/usr/lib/python*/site-packages/problem_report*
# /etc files
/etc/cron.daily/apport
/etc/rc.d/init.d/apport
# Not (noreplace) - generally users won't be modifying this file. Sorry devs,
# I guess you'll just have to deal with it clobbering your config..
%config /etc/apport/crashdb.conf

%files gtk
/usr/share/apport/apport-gtk*

%files qt
/usr/share/apport/apport-qt
/usr/share/apport/*.ui

%files retrace
%doc %{_mandir}/man1/apport-retrace.1*
/usr/share/apport/apport-retrace
/usr/share/apport/apport-chroot

%changelog
* Mon Jul 2 2007 - Will Woods <wwoods@redhat.com> - 0.87
- Update to 0.87 from upstream

* Thu Jun 28 2007 - Will Woods <wwoods@redhat.com> - 0.86
- Update to 0.86 from upstream, and add fedora changes as a single patch
- Fix packaging problems - actually install packaging implementation
- change setup.py invocation to move scripts to /usr/share/apport
- Add initscript for Fedora and derivatives, chkconfig --add/--del as needed
- condrestart on upgrade
- stub get_available_version() so reports work

* Thu Jun 28 2007 - Will Woods <wwoods@redhat.com> - 0.85
- Changelog begins. Updated to 0.85 from upstream.
