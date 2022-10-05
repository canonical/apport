Apport crash detection/reporting
================================

Apport intercepts Program crashes, collects debugging information about the
crash and the operating system environment, and sends it to bug trackers in a
standardized form. It also offers the user to report a bug about a package,
with again collecting as much information about it as possible.

It currently supports

 - Crashes from standard signals (`SIGSEGV`, `SIGILL`, etc.) through the kernel
   coredump handler (in piping mode)
 - Unhandled Python exceptions
 - GTK, KDE, and command line user interfaces
 - Packages can ship hooks for collecting specific data (such as
   `/var/log/Xorg.0.log` for X.org, or modified gconf settings for GNOME
   programs)
 - apt/dpkg and rpm backend (in production use in Ubuntu and OpenSUSE)
 - Reprocessing a core dump and debug symbols for post-mortem (and preferably
   server-side) generation of fully symbolic stack traces (`apport-retrace`)
 - Reporting bugs to Launchpad (more backends can be easily added)

Please see https://wiki.ubuntu.com/Apport for more details and further links.
The files in [doc/](./doc/) document particular details such as package hooks,
crash database configuration, or the internal data format.

Temporarily enabling apport
===========================

The automatic crash interception component of apport is disabled by default in
stable releases
[for a number of reasons](https://wiki.ubuntu.com/Apport#How%20to%20enable%20apport).
To enable it just for the current session, do

```sh
sudo service apport start force_start=1
```

Then you can simply trigger the crash again, and Apport's dialog will show up
with instructions to report a bug with traces. Apport will be automatically
disabled on next start.

If you are triaging bugs, this is the best way to get traces from bug reporters
that didn't use Apport in the first place.

To enable it permanently, do:

```sh
sudo nano /etc/default/apport
```

and change enabled from `0` to `1`.

Crash notification on servers
=============================

You can add

```sh
if [ -x /usr/bin/apport-cli ]; then
    if groups | grep -qw admin && /usr/share/apport/apport-checkreports -s; then
        cat <<-EOF
You have new problem reports waiting in /var/crash.
To take a look at them, run "sudo apport-cli".

EOF
    elif /usr/share/apport/apport-checkreports; then
        cat <<-EOF
You have new problem reports waiting in /var/crash.
To take a look at them, run "apport-cli".

EOF
    fi
fi
```

to your `~/.bashrc` to get automatic notification of problem reports.

Contributing
============

Please visit Apport's Launchpad homepage for links to the source code revision
control, the bug tracker, translations, downloads, etc.:

  https://launchpad.net/apport

The preferred mode of operation for Linux distribution packagers is to create
their own branch from `main` and add the distro specific packaging and patches
to it. Please send patches which are applicable to main as merge requests or
bug reports, so that
1. other distributions can benefit from them as well, and
2. you reduce the code delta to upstream.

Creating releases
=================

This project uses [semantic versioning](https://semver.org/). To create a
release, increase the version in [apport/ui.py](apport/ui.py) and document the
noteworthy changes in [NEWS.md](./NEWS.md). Then commit the changes and get them
reviewed:

```
version=$(python3 -c "import apport.ui; print(apport.ui.__version__)")
git commit -sm "Release apport $version" NEWS.md setup.py
```

Once merged to `main`, tag the release and generate a xz-compressed release
tarball:

```
version=$(python3 -c "import apport.ui; print(apport.ui.__version__)")
name="apport-$version"
git tag "$version" main
git archive --prefix="$name/" "$version" | xz -c9 > "../$name.tar.xz"
gpg --output "../$name.tar.xz.asc" --armor --detach-sign "../$name.tar.xz"
```

On https://launchpad.net/apport/main create a release from the milestone. Set
the date and copy the entries from [NEWS.md](./NEWS.md) to the release notes.
Click on "Add download file" and add `apport-${version}.tar.xz`. Use the
filename as description and do not forget to add the GPG signature. Finally
set the bug status for all linked bugs from "Fix Committed" to "Fix Released".

Afterwards create a new milestone on https://launchpad.net/apport/main using the
next version as name. All other fields can be left empty.
