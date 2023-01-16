This file summarizes the major and interesting changes for each release. For a
detailed list of changes, please see the git history.

2.24.0 (2022-12-07)
-------------------

### Added
* Add `apport.service` as alternative to the init.d script

### Changed
* build: Bump source/target Java version to 7
* Split bash completions by command

### Fixed
* Address complaints from pylint 2.15.5
* Catch malformed problem reports
  ([LP: #1996040](https://launchpad.net/bugs/1996040))
* Catch `ValueError`: not enough values to unpack
  ([LP: #1995100](https://launchpad.net/bugs/1995100))
* Catch `FileNotFoundError` for missing desktop files
  ([LP: #1997753](https://launchpad.net/bugs/1997753))
* Catch `binascii.Error`: Incorrect padding
  ([LP: #1997912](https://launchpad.net/bugs/1997912))
* Catch `AttributeError`: `NoneType` object has no attribute `origins`
  ([LP: #1997973](https://launchpad.net/bugs/1997973))
* Add main category System to `apport-kde-mime.desktop`
* data/apport: Fix ignoring `SIGXCPU` and `SIGXFSZ`
* tests:
  * Fix path for installed `apport-cli`
  * Determine source package dynamically in `test_run_crash_kernel`
    ([LP: #1992172](https://launchpad.net/bugs/1992172))

2.23.1 (2022-10-05)
-------------------

### Changed
* Disable debuginfod when collecting a report
  ([LP: #1989803](https://launchpad.net/bugs/1989803))

### Fixed
* apport-cli: Fix AttributeError: 'bytes' object has no attribute 'fileno'
  ([LP: #1991200](https://launchpad.net/bugs/1991200))
* apport-bug: Add `/snap/bin` to `PATH` for Firefox snap on Lubuntu
  ([LP: #1973470](https://launchpad.net/bugs/1973470))
* tests:
  * Wait for test process to be started to fix `AssertionError` in
    `test_omit_all_processes_except_one`
    ([LP: #1989365](https://launchpad.net/bugs/1989365))
  * Fix `psutil.NoSuchProcess` in `wait_for_gdb_child_process`
    ([LP: #1989371](https://launchpad.net/bugs/1989371))

2.23.0 (2022-08-22)
-------------------

### Added
* Add support for `qastaging.launchpad.net`
* apport-kde: Implement "Examine locally" for KDE as well
* tests/run-linters: Run also `pylint` and `pydocstyle` (if present)

### Changed
* tests: Use `sleep` instead of `yes` for tests
* Open files explicitly with UTF-8 encoding
* Suggest installing `python3-launchpadlib` if missing and needed
  ([LP: #1958059](https://launchpad.net/bugs/1958059))
* Query `/etc/os-release` for version codename. `lsb_release` will not be needed
  in most cases any more.
* Determine system package manager during runtime
* Address pylint errors and warning and most conventions and refactoring

### Fixed
* apport-gtk:
  * Fix importing the wrong Gdk version (regression in 2.22.0)
  * Gracefully handle import failure of gi
    ([LP: #1980561](https://launchpad.net/bugs/1980561))
  * Catch `AssertionError` when importing Gdk
    ([LP: #1980238](https://launchpad.net/bugs/1980238))
* Fix trying to find debug packages for non-existing version
* data/apport:
  * Initialize error log as first step
  * Fix `PermissionError` for setuid programs inside container
    ([LP: #1982487](https://launchpad.net/bugs/1982487))
  * Fix reading from stdin inside containers
    ([LP: #1982555](https://launchpad.net/bugs/1982555))
* unkillable_shutdown: Fix failure if report file exists
* apport-kde:
  * Fix inverse order of choices
    ([LP: #1967965](https://launchpad.net/bugs/1967965))
  * Import apport before usage
    ([LP: #1980553](https://launchpad.net/bugs/1980553))
* apport-unpack: Fix `ValueError`: `['separator']` has no binary content
  ([LP: #1889443](https://launchpad.net/bugs/1889443))
* Fix `_run_hook` getting called with `ui=None`
  ([LP: #1983481](https://launchpad.net/bugs/1983481))
* Break cyclic imports inside apport module
* apport_python_hook: Try to create report directory if missing
* tests:
  * Fix killing itself in `test_unpackaged_script`
  * Fix killing test executable too early
    ([LP: #1980390](https://launchpad.net/bugs/1980390))
  * Fix `test_add_gdb_info_script` on `armhf`
  * Fix wrong Ubuntu archive URI on ports
  * Fix `KeyError` in `test_install_packages_unversioned`
  * Fix `IndexError` in `test_crash_setuid_drop`

### Removed
* data/apport: Drop support for positional arguments
* Remove partially implemented and unused login API
* apport-kde: Drop old workaround for bug in SIP destructor
  ([LP: #1980553](https://launchpad.net/bugs/1980553))

2.22.0 (2022-06-27)
-------------------

* Fix several pycodestyle warnings
* Sort Python imports with isort
* Replace `ProblemReport.get_date` by `ProblemReport.get_timestamp`, fixes
  regression in 2.21.0 ([LP: #1978487](https://launchpad.net/bugs/1978487))
* Format Python code with black
* apport-gtk: Exclude trailing dot from URL links
  ([LP: #1978301](https://launchpad.net/bugs/1978301))
* Fix `AttributeError`: 'NoneType' object has no attribute 'write', fixes
  regression in 2.21.0 ([LP: #1979211](https://launchpad.net/bugs/1979211))
* `apport_python_hook`:
  * Properly handle missing modules
    ([LP: #1774843](https://launchpad.net/bugs/1774843))
  * Fix `FileNotFoundError` if the current directory was deleted
    ([LP: #1979637](https://launchpad.net/bugs/1979637))
  * Fix crash if `os.getcwd()` fails
    ([LP: #1977954](https://launchpad.net/bugs/1977954))
* Replace deprecated `imp` module
  ([LP: #1947425](https://launchpad.net/bugs/1947425))
* tests: Replace deprecated `load_module()`
* `whoopsie-upload-all`: Fix 'EOFError' object has no attribute 'errno', fixes
  regression in 2.21.0 ([LP: #1979681](https://launchpad.net/bugs/1979681))
* Convert documentation to Markdown

2.21.0 (2022-06-09)
-------------------
  * SECURITY UPDATE: TOCTOU issue allows local user to read arbitrary
    files ([LP: #1830858](https://launchpad.net/bugs/1830858))
    - apport/report.py: Avoid TOCTOU issue on users ignore file by
      dropping privileges and then opening the file both test for access and
      open the file in a single operation, instead of using access() before
      reading the file which could be abused by a symlink to cause Apport to
      read and embed an arbitrary file in the resulting crash dump.
    - CVE-2019-7307
  * SECURITY UPDATE: apport reads arbitrary files if ~/.config/apport/settings
    is a symlink ([LP: #1830862](https://launchpad.net/bugs/1830862))
    - apport/fileutils.py: drop permissions before reading user settings file.
    - CVE-2019-11481
  * SECURITY UPDATE: TOCTTOU race conditions and following symbolic
    links when creating a core file
    ([LP: #1839413](https://launchpad.net/bugs/1839413))
    - data/apport: use file descriptor to reference to cwd instead
      of strings.
    - CVE-2019-11482
  * SECURITY UPDATE: fully user controllable lock file due to lock file
    being located in world-writable directory
    ([LP: #1839415](https://launchpad.net/bugs/1839415))
    - data/apport: create and use lock file from /var/lock/apport.
    - CVE-2019-11485
  * SECURITY UPDATE: per-process user controllable Apport socket file
    ([LP: #1839420](https://launchpad.net/bugs/1839420))
    - data/apport: forward crashes only under a valid uid and gid,
      thanks Stéphane Graber for the patch.
    - CVE-2019-11483
  * SECURITY UPDATE: PID recycling enables an unprivileged user to
    generate and read a crash report for a privileged process
    ([LP: #1839795](https://launchpad.net/bugs/1839795))
    - data/apport: drop permissions before adding proc info (special thanks
      to Kevin Backhouse for the patch)
    - data/apport, apport/report.py, apport/ui.py: only access or open
      /proc/[pid] through a file descriptor for that directory.
    - CVE-2019-15790
  * SECURITY REGRESSION: 'module' object has no attribute 'O_PATH'
    ([LP: #1851806](https://launchpad.net/bugs/1851806))
    - apport/report.py, apport/ui.py: use file descriptors for /proc/pid
      directory access only when running under python 3; prevent reading /proc
      maps under python 2 as it does not provide a secure way to do so; use
      io.open for better compatibility between python 2 and 3.
  * SECURITY UPDATE: World writable root owned lock file created in user
    controllable location ([LP: #1862348](https://launchpad.net/bugs/1862348))
    - data/apport: Change location of lock file to be directly under
      /var/run so that regular users can not directly access it or perform
      symlink attacks.
    - CVE-2020-8831
  * SECURITY UPDATE: Race condition between report creation and ownership
    ([LP: #1862933](https://launchpad.net/bugs/1862933))
    - data/apport: When setting owner of report file use a file-descriptor
      to the report file instead of its path name to ensure that users can
      not cause Apport to change the ownership of other files via a
      symlink attack.
    - CVE-2020-8833
  * SECURITY UPDATE: information disclosure issue
    ([LP: #1885633](https://launchpad.net/bugs/1885633))
    - data/apport: also drop gid when checking if user session is closing.
    - CVE-2020-11936
  * SECURITY UPDATE: crash via malformed ignore file
    ([LP: #1877023](https://launchpad.net/bugs/1877023))
    - apport/report.py: don't crash on malformed mtime values.
    - CVE-2020-15701
  * SECURITY UPDATE: TOCTOU in core file location
    - data/apport: make sure the process hasn't been replaced after Apport
      has started.
    - CVE-2020-15702
  * SECURITY UPDATE: multiple security issues
    ([LP: #1912326](https://launchpad.net/bugs/1912326))
    - CVE-2021-25682: error parsing /proc/pid/status
    - CVE-2021-25683: error parsing /proc/pid/stat
    - CVE-2021-25684: stuck reading fifo
    - data/apport: make sure existing report is a regular file.
    - apport/fileutils.py: move some logic here to skip over manipulated
      process names and filenames.
    - test/test_fileutils.py: added some parsing tests.
  * SECURITY UPDATE: Multiple arbitrary file reads
    ([LP: #1917904](https://launchpad.net/bugs/1917904))
    - apport/hookutils.py: don't follow symlinks and make sure the file
      isn't a FIFO in read_file().
    - test/test_hookutils.py: added symlink tests.
    - CVE-2021-32547, CVE-2021-32548, CVE-2021-32549, CVE-2021-32550,
      CVE-2021-32551, CVE-2021-32552, CVE-2021-32553, CVE-2021-32554,
      CVE-2021-32555
  * SECURITY UPDATE: info disclosure via modified config files spoofing
    ([LP: #1917904](https://launchpad.net/bugs/1917904))
    - backends/packaging-apt-dpkg.py: properly terminate arguments in
      get_modified_conffiles.
    - CVE-2021-32556
  * SECURITY UPDATE: arbitrary file write
    ([LP: #1917904](https://launchpad.net/bugs/1917904))
    - data/whoopsie-upload-all: don't follow symlinks and make sure the
      file isn't a FIFO in process_report().
    - CVE-2021-32557
  * SECURITY UPDATE: Arbitrary file read
    ([LP: #1934308](https://launchpad.net/bugs/1934308))
    - data/general-hooks/ubuntu.py: don't attempt to include emacs
      byte-compilation logs, they haven't been generated by the emacs
      packages in a long time.
    - CVE-2021-3709
  * SECURITY UPDATE: Info disclosure via path traversal
    ([LP: #1933832](https://launchpad.net/bugs/1933832))
    - apport/hookutils.py, test/test_hookutils.py: detect path traversal
      attacks, and directory symlinks.
    - CVE-2021-3710
  * SECURITY UPDATE: Privilege escalation via core files
    - refactor privilege dropping and create core files in a well-known
      directory in apport/fileutils.py, apport/report.py, data/apport,
      test/test_fileutils.py, test/test_report.py,
      test/test_signal_crashes.py, test/test_ui.py.
    - use systemd-tmpfiles to create and manage the well-known core file
      directory in setup.py, data/systemd/apport.conf.
  * backends/packaging-apt-dpkg.py: Utilize a release and architecture specific
    contents mapping.
  * test/test_backend_apt_dpkg.py: Update the test as we are using a contents
    mapping.
  * test/test_report.py: remove unused import of gzip.
  * apport/ui.py: Write an UnreportableReason for snaps and provide information
    on how to contact a snap developer.
    ([LP: #1729491](https://launchpad.net/bugs/1729491))
  * problem_report.py, bin/apport-unpack: restore some python2 code because the
    Error Tracker retracers need it.
  * backends/packaging-apt-dpkg.py: add in /usr/games and /usr/libexec as paths
    for executables in the contents mapping.
  * apport/ui.py: When saving a report for later processing if the filename
    to save it to ends with .gz then gzip the report file. Thanks to Yuan-Chen
    Cheng for the patch. ([LP: #1837174](https://launchpad.net/bugs/1837174))
  * Catch zlib.error when decoding CoreDump from crash file
    ([LP: #1947800](https://launchpad.net/bugs/1947800))
  * whoopsie-upload-all: Catch FileNotFoundError during process_report
    ([LP: #1867204](https://launchpad.net/bugs/1867204))
  * Drop Python 2 support
  * Grab a slice of JournalErrors around the crash time
    ([LP: #1962454](https://launchpad.net/bugs/1962454))
  * Fix several race conditions in test cases
  * Make test cases more robust against running in specific environments
  * Split the test suite into unit, integration, and system tests

2.20.11 (2019-05-16)
--------------------
  * SECURITY UPDATE: Ensure that we propely handle crashes that originate from
    a PID namespace. Thanks to Sander Bos for discovering this issue.
    (CVE-2018-6552, [LP: #1746668](https://launchpad.net/bugs/1746668))
  * backends/packaging-apt-dpkg.py: switch to using python3-launchpadlib to
    communicate with Launchpad thereby gaining retry capabilities and using its
    cache.
  * backends/packaging-apt-dpkg.py: utilize a global mapping of files to
    packages instead of searching a Contents.gz file multiple times,
    additionally write this mapping to disk so subsequent lookups and retraces
    are quicker. ([LP: #1370230](https://launchpad.net/bugs/1370230))
  * apport/ui.py: Handle old reports generated pre-apport with "remember"
    option. If the option isn't there, consider as false.
    ([LP: #1791324](https://launchpad.net/bugs/1791324))
  * apport/report.py: End our gdb batch script with a separator, to accomodate
    new exit codes from gdb 8.2.50. Thanks Steve Langasek!
  * data/apport: Introduce support for non-positional arguments so we
    can easily extend core_pattern in the future
    ([LP: #1732962](https://launchpad.net/bugs/1732962))
  * apport/report.py: Have add_gdb_info return a FileNotFoundError if gdb or
    the crashing executable are not found and modify whoopsie-upload-all to
    upload crashes in that situation.
    ([LP: #1820132](https://launchpad.net/bugs/1820132))
  * apport/report.py, apport/ui.py: raise ValueError if the pid is not
    accessible, display an error message for that or an invalid pid.
    ([LP: #1396160](https://launchpad.net/bugs/1396160))
  * switch from pyflakes to pyflakes3, drop some python2 code
  * backends/packaging-apt-dpkg.py: strip /usr from binary names so the .list
    file will match.
  * test/*: switch from using deprecated imp to importlib, modify binary
    locations for merged-usr changes.
  * apport/report.py: reorder directories check for binaries so /usr is
    checked first.
  * data/whoopsie-upload-all: confirm the exception has an errno before using
    it in a comparison. ([LP: #1824152](https://launchpad.net/bugs/1824152))
  * test/test_report.py: update test_add_proc_info for function raising a
    ValueError.
  * apport/REThread.py, apport/ui.py: Avoid deprecation warnings by switching
    from isAlive() to is_alive().
  * apport/ui.py: if report.get_timestamp() returns None don't try and use it
    in a comparison. ([LP: #1658188](https://launchpad.net/bugs/1658188))
  * test/test_apport_valgrind.py: specify the location for true.
  * apport/ui.py: when using ubuntu-bug properly handle executables which
    start with /snap/bin. ([LP: #1760220](https://launchpad.net/bugs/1760220))
  * Fix PEP8 605 warnings and ignore 503,504 ones.
  * tests/test_ui_gtk.py: Increase the timeout so that when the autopkgtest
    infrastructure is busy the tests should not fail.
    ([LP: #1780767](https://launchpad.net/bugs/1780767))
  * problem_report.py: Decrease zlib compression level from 9 to 6.  After
    a crash, this reduces the time Apport spends compressing the core dump
    by an order of magnitude. Thanks to Anders Kaseorg for the analysis and
    initial patch. ([LP: #1537635](https://launchpad.net/bugs/1537635))

2.20.10 (2018-05-09)
--------------------
  * backends/packaging-apt-dpkg.py: when using a permanent sandbox better check
    for the package being already available thereby quantity of downloads.
  * apport/report.py: Use timeout parameter in subprocess to limit how long
    we'll wait for gdb to return information as gdb can hang with some core
    files.
  * data/apport: Fix PEP8 issues
  * apport/ui.py: Include ProblemType in reports which are updated as package
    hooks may expect the report to have a ProblemType.
    ([LP: #1766794](https://launchpad.net/bugs/1766794))
  * test/test_ui.py: modify run_crash_kernel test to account for the fact that
    linux-image-$kvers-$flavor is now built from the linux-signed source
    package on amd64 and ppc64el.
    ([LP: #1766740](https://launchpad.net/bugs/1766740))

2.20.9 (2018-02-14)
-------------------
  * Re-enable container support. Thanks to Stéphane Graber!
    ([LP: #1732518](https://launchpad.net/bugs/1732518))
  * Add code preventing a user from confusing apport by using
    a manually crafted filesystem inside a combination of a user and mount
    namespace. Thanks to Stéphane Graber!
  * Add a check in apport receiver for the number of arguments so that
    should another argument be added later, the receiver will simply ignore
    the crash until it itself gets updated. Thanks to Stéphane Graber!
  * data/apport: add a second os.path.exists check to ensure we do not
    receive a Traceback in is_container_id().
    ([LP: #1733366](https://launchpad.net/bugs/1733366))
  * apport/sandboxutils.py: when installing extra packages do not install the
    debug versions of them as this was installing gdb-dbg. If debug versions of
    a package are specifically required they can be passed as an extra-package.
  * backends/packaging-apt-dpkg.py: when reusing a sandbox do not remove
    conflicting packages when they conflict with themselves, or when they
    conflict with but also provide a virtual package.
  * bin/apport-retrace: add a --no-stracktrace-source option that does not do
    the work of creating a StacktraceSource field in the retraced report
    thereby decreasing the time to retrace.
  * apport/report.py: gdb's version 8.0.90 output changed from Warning to
    warning however to support using gdb in sandbox we need to support either
    case so check for both.
  * data/apport: add an exception handler in case either name space can not be
    found.
  * data/general-hooks/generic.py: change JournalErrors to contain errors not
    warnings. ([LP: #1738581](https://launchpad.net/bugs/1738581))
  * data/apport: wait for lock, with 30s timeout
    ([LP: #1746874](https://launchpad.net/bugs/1746874))

2.20.8 (2017-11-15)
-------------------
  * SECURITY UPDATE: Denial of service via resource exhaustion and
    privilege escalation when handling crashes of tainted processes.
    - When /proc/sys/fs/suid_dumpable is set to 2, do not assume that
      the user and group owning the /proc/<PID>/stat file is the same
      owner and group that started the process. Rather check the dump
      mode of the crashed process and do not write a core file if its
      value is 2. Thanks to Sander Bos for discovering this issue!
    (CVE-2017-14177, [LP: #1726372](https://launchpad.net/bugs/1726372))
  * SECURITY UPDATE: Denial of service via resource exhaustion,
    privilege escalation, and possible container escape when handling
    crashes of processes inside PID namespaces.
    - Change the method for determining if a crash is from a container
      so that there are no false positives from software using PID
      namespaces. Additionally, disable container crash forwarding by
      ignoring crashes that occur in a PID namespace. This functionality
      may be re-enabled in a future update. Thanks to Sander Bos for
      discovering this issue!
    (CVE-2017-14180, [LP: #1726372](https://launchpad.net/bugs/1726372))
 * apport/hookutils.py: modify package_versions to return an empty string if
   packages is empty. ([LP: #1723822](https://launchpad.net/bugs/1723822))
 * bin/apport-cli: read until <enter> instead of a single character when # of
   apport options is non-unique with a single character. Thanks to Chad Smith
   for the patch. ([LP: #1722564](https://launchpad.net/bugs/1722564))

2.20.7 (2017-08-29)
-------------------
 * Fix new pep8 failures in artful - E722 do not use bare except.
 * apport/REThread.py: A bare except needs to be used so that we can catch
   the dialog being closed.
 * test/test_report.py: Be a little patient and give some time for the core
   file to show up.
 * backends/packaging-apt-dpkg.py: Don't install the version mentioned in a
   versioned dep, rather install the latest version of that dep.
 * backends/packaging-apt-dpkg.py: search -proposed last so we prefer packages
   from other pockets.

2.20.6 (2017-07-18)
-------------------
 * SECURITY FIX: Fix path traversal vulnerability with hooks execution.
   Ensure that ExecutablePath: fields loaded from reports do not contain
   directories. Until now, an attacker could trick a user into opening a
   malicious .crash file containing
   ```
   ExecutablePath: /opt/../../../../some/dir/foo
   ```
   which would execute /some/dir/foo.py with arbitrary code.  Thanks to Felix
   Wilhelm for discovering this!
   (CVE-2017-10708, [LP: #1700573](https://launchpad.net/bugs/1700573))
 * Stop installing a MIME handler for crash files as it ends up causing more
   trouble than it is worth.
 * bin/crash-digger: Set self.lp if the crashdb is Launchpad.
 * test/test_backend_apt_dpkg.py: cache directories contain the
   architecture in the path if if is not the native arch.
 * apport/crashdb_impl/launchpad.py: Don't make a contentless change to a bug,
   it just generates more bug mail.
 * apport/crashdb_impl/launchpad.py: Handle FailedToDecompressContent httplib2
   error when downloading a broken attachment.
 * Convert regular expressions to raw strings to avoid deprecation warnings
   with Python version 3.6. Thanks to Michael Hudson-Doyle for the patch!
 * test/test_signal_crashes.py: a ulimit of 1M bytes isn't enough to produce a
   core file anymore so bump it to 10M.

2.20.5 (2017-05-12)
-------------------
 * bin/apport-retrace: Comment on bug reports when an invalid core file is
   encountered. ([LP: #1647635](https://launchpad.net/bugs/1647635))
 * Switch to using HxW directory names for app icons instead of just one
   number. Thanks to Jeremy Bicha for the patch.
 * apport/ui.py: Ensure the Date field exists in a report before using it in a
   comparison. ([LP: #1658188](https://launchpad.net/bugs/1658188))
 * bin/apport-retrace: Add in a --gdb-sandbox switch which creates or utilizes
   a sandbox with the report's distribution release and the host system's
   architecture for installing and running gdb.
   ([LP: #1517257](https://launchpad.net/bugs/1517257))
 * apport/hookutils.py: Don't crash if .xsession-errors is not readable by the
   user. ([LP: #1675928](https://launchpad.net/bugs/1675928))
 * bin/apport-retrace: Be specific about which required field is missing from a
   report and not retracing it.
 * Disable report.test_add_gdb_info_abort_glib test case for now, as the
   glib assertion message is broken under current Ubuntu
   ([LP: #1689344](https://launchpad.net/bugs/1689344))

2.20.4 (2016-12-14)
-------------------
 * SECURITY FIX: Restrict a report's CrashDB field to literals.
   Use ast.literal_eval() instead of the generic eval(), to prevent arbitrary
   code execution from malicious .crash files. A user could be tricked into
   opening a crash file whose CrashDB field contains an exec(), open(), or
   similar commands; this is fairly easy as we install a MIME handler for
   these. Thanks to Donncha O'Cearbhaill for discovering this!
   (CVE-2016-9949, [LP: #1648806](https://launchpad.net/bugs/1648806))
 * SECURITY FIX: Fix path traversal vulnerability with hooks execution.
   Ensure that Package: and SourcePackage: fields loaded from reports do not
   contain directories. Until now, an attacker could trick a user into opening a
   malicious .crash file containing
   ```
   Package: ../../../../some/dir/foo
   ```
   which would execute /some/dir/foo.py with arbitrary code.
   Thanks to Donncha O'Cearbhaill for discovering this!
   (CVE-2016-9950, [LP: #1648806](https://launchpad.net/bugs/1648806))
 * SECURITY FIX: apport-{gtk,kde}: Only offer "Relaunch" for recent /var/crash
   crashes.
   It only makes sense to offer relaunching for crashes that just happened and
   the apport UI got triggered on those. When opening a .crash file copied from
   somewhere else or after the crash happened, this is even actively dangerous
   as a malicious crash file can specify any arbitrary command to run.
   Thanks to Donncha O'Cearbhaill for discovering this!
   (CVE-2016-9951, [LP: #1648806](https://launchpad.net/bugs/1648806))
 * test_backend_apt_dpkg.py: Move tests from Ubuntu 15.10 "wily" (which is EOL
   now) to 16.04 LTS "xenial".
 * packaging-apt-dpkg.py: Explicitly set Dir::State::Status to the host
   dpkg status file for get_source_tree(), to work with apt 1.3~pre4.
 * packaging-apt-dpkg.py: Change the proxy settings to use "DIRECT" instead
   of "direct". The latter never really worked, but APT did not complain about
   it.
 * data/iwlwifi_error_dump: Fix add_package() call.
 * hookutils.py, attach_mac_events(): Only attach /proc/version_signature if
   that actually exists.
 * test/test_report.py: Slightly relax stack trace checks to also work with
   glibc 2.24.
 * apport-gtk: Specify module version with GI imports to avoid warnings. Thanks
   Anatoly Techtonik. ([LP: #1502173](https://launchpad.net/bugs/1502173))
 * test/run: Prefer pycodestyle over pep8.
 * backends/packaging-apt-dpkg.py: provide a fallback method if using zgrep to
   search for a file in Contents.gz fails due to a lack of memory.  Thanks
   Brian Murray.
 * bin/apport-retrace: When --core-file is used instead of loading the core
   file and adding it to the apport report just pass the file reference to gdb.

2.20.3 (2016-07-28)
-------------------
 * problem_report.py: Fail with proper exception when trying to assign a list
   to a report key, or when trying to assing a tuple with more than 4 entries.
   ([LP: #1596713](https://launchpad.net/bugs/1596713))
 * test_backend_apt_dpkg.py: Install GPG key for ddebs.ubuntu.com to avoid apt
   authentication errors.

2.20.2 (2016-06-19)
-------------------
 * problem_report.py: Make assertion of invalid key names more verbose.
 * hookutils.py: Fix generation of valid report key names from arbitrary paths
   in attach_file() and related functions. This will now replace all invalid
   characters with dots, not just a few known invalid ones.
   ([LP: #1566975](https://launchpad.net/bugs/1566975))
 * problem_report.py: Instead of AssertionError, raise a ValueError for invalid
   key names and TypeError for invalid kinds of values. Thanks Barry Warsaw.
 * Don't ignore OSError in Report.add_gdb_info(), as we do want to fail with an
   useful error message if gdb cannot be called in apport-retrace. Move the
   catching to the UI as not having gdb installed is still fine for reporting
   clients. ([LP: #1579949](https://launchpad.net/bugs/1579949))
 * Show gdb error messages in Report.add_gdb_info() OSError exception when gdb
   fails. ([LP: #1579897](https://launchpad.net/bugs/1579897))
 * hookutils, attach_root_command_outputs(): Return str again, like before
   2.15.2. ([LP: #1370259](https://launchpad.net/bugs/1370259))
 * Stop issuing "set architecture" gdb commands on ARM and Power; these only
   applied to 32 bit platforms and are apparently not needed any more with
   recent gdb versions. ([LP: #1585702](https://launchpad.net/bugs/1585702))
 * Disable report.test_add_gdb_info_abort_libnih test case for now, as libnih
   is broken under current Ubuntu
   ([LP: #1580601](https://launchpad.net/bugs/1580601))
 * do-release: Drop generation of ChangeLog. Interesting changes are already
   documented here, and the details can be seen in the bzr log.

2.20.1 (2016-03-31)
-------------------
 * Fix signal_crashes.test_modify_after_start test when running as root.
 * Relax report.test_add_gdb_info gdb warning check, as this changed with gdb
   7.10.90.
 * crash-digger: Untag bugs which cannot be retraced instead of stopping
   crash-digger. This led to too many pointless manual restarts on broken bug
   reports.
 * Disambiguate overly generic Python exceptions in duplicate signature
   computation: dbus-glib's DBusException wraps a "real" server-side exception,
   so add the class of that to disambiguate different crashes; for OSError
   that is not a known subclass like FileNotFoundError, add the errno.
   ([LP: #989819](https://launchpad.net/bugs/989819))

2.20 (2016-02-12)
-----------------
 * Reimplement forwarding crashes into a container, via activating the new
   apport-forward.socket in the container and handing over the core dump fd.
   This is a much safer way than the original implementation with nsexec.
   Thanks Stéphane Graber! ([LP: #1445064](https://launchpad.net/bugs/1445064))
 * Drop obsolete signal_crashes.test_ns_forward_privilege() test case. This
   code was dropped long ago.

2.19.4 (2016-01-26)
-------------------
 * Fix fileutils.test_find_package_desktopfile test for symlinks and other
   unowned files in /usr/share/applications/.
 * Fix ui.test_run_crash_anonymity test case to not fail if the base64 encoded
   core dump happens to contain the user name, as that's just by chance.
 * Fix test_hooks.py for unreleased gcc versions which have a different
   --version format.
 * hookutils.py, attach_hardware(): Stop attaching /var/log/udev. This was an
   upstart-ism, mostly redundant with the udev db and is not being written
   under systemd. ([LP: #1537211](https://launchpad.net/bugs/1537211))

2.19.3 (2015-12-08)
-------------------
 * apport: Fix comparison against SIGQUIT to work for current Python versions.
 * apt/dpkg: Fix source record lookup in install_packages. Thanks Brian Murray!
 * hookutils.py, attach_gsettings_schema(): Don't replace the schema variable;
   fixes attaching relocatable schemas. Thanks Sébastien Bacher!
 * generic hook: Limit JournalErrors to the 1.000 last lines. This avoids long
   report load times when processes cause massive log spew.
   ([LP: #1516947](https://launchpad.net/bugs/1516947))
 * Add key filtering to ProblemReport.load().
 * Don't read the entire report when determining the CrashCounter. This avoids
   long delays for existing large reports.
 * test_python_crashes.py: Be less sensitive to the precise names of
   gvfs-metadata D-Bus service files.
 * Move backend_apt_dpkg -dbgsym test cases to Ubuntu 15.10.
 * Tests: Move to unittest's builtin "mock" module.

2.19.2 (2015-10-27)
-------------------
 * SECURITY FIX: When determining the path of a Python module for a program
   like "python -m module_name", avoid actually importing and running the
   module; this could lead to local root privilege escalation. Thanks to
   Gabriel Campana for discovering this and the fix!
   (CVE-2015-1341, [LP: #1507480](https://launchpad.net/bugs/1507480))
 * apt/dpkg: Don't mark packages downloaded from Launchpad for installation by
   apt. Thanks Brian Murray.
 * Fix backend_apt_dpkg.test_install_packages_system for recent "Fall back to
   direct Launchpad ddeb download" fix. coreutils-dbgsym should now always be
   available independent of whether the local system has ddeb apt sources.
 * test_backend_apt_dpkg.py: Reset internal apt caches between tests. Avoids
   random test failures due to leaking paths from previous test cases.

2.19.1 (2015-10-07)
-------------------
 * Consistently intercept "report file already exists" errors in all writers of
   report files (package_hook, kernel_crashdump, and similar) to avoid
   unhandled exceptions on those.
   ([LP: #1500450](https://launchpad.net/bugs/1500450))
 * apt/dpkg: Fall back to direct Launchpad ddeb download if we can't find it in
   the apt cache. Thanks Brian Murray!
   ([LP: #1500557](https://launchpad.net/bugs/1500557))
 * doc/data-format.tex: Clarify that key names are being treated as case
   sensitive (unlike RFC822).

2.19 (2015-09-24)
-----------------
 * apport: Drop re-nicing. This might decrease the time a user has to wait for
   apport to finish the core dump for a crashed/hanging foreground process.
   (See [LP: #1278780](https://launchpad.net/bugs/1278780))
 * kernel_crashdump: Enforce that the log/dmesg files are not a symlink. This
   prevents normal users from pre-creating a symlink to the predictable .crash
   file, and thus triggering a "fill up disk" DoS attack when the .crash report
   tries to include itself. Thanks to halfdog for discovering this!
   (CVE-2015-1338, part of [LP: #1492570](https://launchpad.net/bugs/1492570))
 * SECURITY FIX: Fix all writers of report files (package_hook,
   kernel_crashdump, and similar) to open the report file exclusively, i. e.
   fail if they already exist. This prevents privilege escalation through
   symlink attacks. Note that this will also prevent overwriting previous
   reports with the same same. Thanks to halfdog for discovering this!
   (CVE-2015-1338, [LP: #1492570](https://launchpad.net/bugs/1492570))
 * apport: Ignore process restarts from systemd's watchdog. Their traces are
   usually useless as they don't have any information about the actual reasaon
   why processes hang (like VM suspends or kernel lockups with bad hardware)
   ([LP: #1433320](https://launchpad.net/bugs/1433320))
 * Switch all executables to use Python 3 by default.

2.18.1 (2015-09-10)
-------------------
 * test_hooks.py: Adjust for gcc executable names that don't include the minor
   version number.
 * When determinining the logind session and $XDG_SESSION_ID is not set, fall
   back to reading it from /proc/pid/cgroup.
 * whoopsie-upload-all: Intercept OSError too (e. g. "No space left on
   device"). ([LP: #1476258](https://launchpad.net/bugs/1476258))
 * apport-retrace: Only consider the file name of a source file, not its path;
   the latter often contains parts like "../" or directories which are specific
   to a build machine. This fixes most broken StacktraceSource results.
   ([LP: #1462491](https://launchpad.net/bugs/1462491))
 * packaging.py: Only consider first word in /etc/os-release's NAME value. This
   works around Debian's inconsistent value.
   ([LP: #1408245](https://launchpad.net/bugs/1408245))
 * Unify and simplify Package: field generation in kernel_crashdump,
   kernel_oops, and package_hook by using the new Report.add_package() method.
   ([LP: #1485787](https://launchpad.net/bugs/1485787))
 * sandboxutils.py, make_sandbox(): Make "Cannot find package which ships
   Executable/InterpreterPath" fatal, to save some unnecessary package unpack
   cycles. ([LP: #1487174](https://launchpad.net/bugs/1487174))

2.18 (2015-07-17)
-----------------
 * Fix backend_apt_dpkg.test_install_packages_permanent_sandbox test to more
   carefully restore the environment and apt config.
 * Enable suid_dumpable in the init.d script to also get Apport reports about
   suid, unreadable, and otherwise protected binaries. These will be "system
   reports" owned and readable by root only.
 * init.d script: Fix tab usage inconsistencies.
 * apport-gtk: Use GtkWidget::valign property instead of GtkMisc::yalign which
   is deprecated in GTK 3.16. Thanks Iain Lane.
 * sandboxutils, make_sandbox(): Don't exit with 0 (success) if the
   ExecutablePath does not exist.
   ([LP: #1462469](https://launchpad.net/bugs/1462469))
 * sandboxutils, make_sandbox(): Fix second round of package installs to go
   into permanent root dir as well.
 * apt/dpkg install_packages(): If a requested package version is not available
   from apt in the given archive, try to download it from Launchpad. Thanks to
   Brian Murray!
 * kerneloops: Fix crash when determining the version of a custom kernel.
   Thanks Brian Murray. ([LP: #1468154](https://launchpad.net/bugs/1468154))
 * apt/dpkg install_packages(): Ignore -dbg packages whose descriptions contain
   "transitional". ([LP: #1469635](https://launchpad.net/bugs/1469635))
 * Keep "[origin: ...]" information in Package: and Dependencies: fields for
   native-origins.d/ origins, so that it's possible to retrace them. Thanks
   Brian Murray! ([LP: #1470572](https://launchpad.net/bugs/1470572))
 * Add support for retracing with discovering and enabling foreign Launchpad
   PPA origins, as specified in reports' Package:/Dependencies: fields. Thanks
   Brian Murray!
 * hookutils.attach_wifi(): Shorten value of CRDA if iw isn't available on the
   system. Thanks Brian Murray.
 * Fix wrong assertion in crashdb.test_check_duplicate() which surfaces under
   Python 3.5. ([LP: #1474539](https://launchpad.net/bugs/1474539))

2.17.3 (2015-05-20)
-------------------
 * SECURITY UPDATE: When /proc/sys/fs/suid_dumpable is enabled, crashing a
   program that is suid root or not readable for the user would create
   root-owned core files in the current directory of that program. Creating
   specially crafted core files in /etc/logrotate.d or similar could then lead
   to arbitrary code execution with root privileges.
   Now core files do not get written for these kinds of programs, in accordance
   with the intention of core(5).
   Thanks to Sander Bos for discovering this issue!
   (CVE-2015-1324, [LP: #1452239](https://launchpad.net/bugs/1452239))
 * SECURITY UPDATE: When writing a core dump file for a crashed packaged
   program, don't close and reopen the .crash report file but just rewind and
   re-read it. This prevents the user from modifying the .crash report file
   while "apport" is running to inject data and creating crafted core
   dump files. In conjunction with the above vulnerability of writing core
   dump files to arbitrary directories this could be exploited to gain root
   privileges.
   Thanks to Philip Pettersson for discovering this issue!
   (CVE-2015-1325, [LP: #1453900](https://launchpad.net/bugs/1453900))
 * apportcheckresume: Fix "occured" typo, thanks Matthew Paul Thomas.
   ([LP: #1448636](https://launchpad.net/bugs/1448636))
 * signal_crashes test: Fix test_crash_setuid_* to look at whether
   suid_dumpable was enabled.
 * test/run: Run UI tests under dbus-launch, newer GTK versions require this
   now.

2.17.2 (2015-04-16)
-------------------
 * SECURITY UPDATE: Disable crash forwarding to containers. The previous fix in
   2.17.1 was not sufficient against all attack scenarios. By binding to
   specially crafted sockes, a normal user program could forge arbitrary
   entries in /proc/net/unix. We cannot currently rely on a kernel-side
   solution for this; this feature will be re-enabled once it gets re-done to
   be secure. ([LP: #1444518](https://launchpad.net/bugs/1444518))
 * do-release: Force UTC timezone for upstream changelog generation.
 * apport-kde: Fix crash when showing byte array values. Thanks Jonathan
   Riddell. ([LP: #1443659](https://launchpad.net/bugs/1443659))
 * Really create a better duplicate signature for recoverable problems, using
   ExecutablePath. Thanks Brian Murray.
   ([LP: #1316763](https://launchpad.net/bugs/1316763))

2.17.1 (2015-04-14)
-------------------
 * SECURITY UPDATE: Fix root privilege escalation through crash forwarding to
   containers.
   Version 2.13 introduced forwarding a crash to a container's apport. By
   crafting a specific file system structure, entering it as a namespace
   ("container"), and crashing something in it, a local user could access
   arbitrary files on the host system with root privileges.
   Thanks to Stéphane Graber for discovering and fixing this!
   (CVE-2015-1318, [LP: #1438758](https://launchpad.net/bugs/1438758))
 * apport-kde tests: Fix imports to make tests work again.
 * Fix UnicodeDecodeError on parsing non-ASCII environment variables.
 * apport: use the proper pid when calling apport in another PID namespace.
   Thanks Brian Murray. ([LP: #1300235](https://launchpad.net/bugs/1300235))

2.17 (2015-03-31)
-------------------
 * apport-kde: Port to Qt5. Thanks Harald Sitter!
 * Adjust signal_crashes.test_crash_setuid_{keep,drop} for systemd.
 * general-hooks/generic.py: Add systemd journal warnings and errors to the new
   "JournalErrors" field.

2.16.2 (2015-03-02)
-------------------
 * hookutils.in_session_of_problem(): Check $XDG_SESSION_ID and
   /run/systemd/sessions instead of the cgroup, as the latter does not work
   under cgmanager.
 * ProblemReport: Set a timestamp of 0 in gzip compressed fields; they are
   meaningless and cause unnecessary jitter in the output.
 * launchpad backend: Fix unclosed file in upload().
 * launchpad backend: Fix wrong use of filter() with Python 3.
 * launchpad backend download(): Try to convert textual values from byte arrays
   into into strings.
 * ui.py, collect_info(): Fix crash on bug pattern checking with broken gzipped
   values. ([LP: #1345653](https://launchpad.net/bugs/1345653))
 * hookutils, attach_drm_info(): Avoid UnicodeDecodeErrors in Python 3 when
   reading binary files. Thanks Chad Miller.
   ([LP: #1425254](https://launchpad.net/bugs/1425254))
 * apport-gtk: Update legacy icon names to modern GTK ones, to fix icons under
   GNOME. Thanks Scott Sanbar.
   ([LP: #1422176](https://launchpad.net/bugs/1422176))
 * Move backend_apt_dpkg testsuite to use Ubuntu 14.04 LTS.
 * hookutils, attach_dmesg(): Only attach dmesg as CurrentDmesg, drop BootDmesg
   as /var/log/dmesg is upstart specific and thus not reliably correct any
   more.
 * hookutils, recent_syslog(): Read system logs from the journal when running
   under systemd, and fall back to /var/log/syslog if not.
 * hookutils, attach_mac_events(): Read kernel violation messages from dmesg
   instead of /var/log/kern.log, as that's specific to rsyslog and its
   configuration.

2.16.1 (2015-02-10)
-------------------
 * Set gettext translation domain in setup.cfg, so that tools like
   dh_translations pick it up and show correct polkit translations.
   Thanks to Aron Xu! ([LP: #1306857](https://launchpad.net/bugs/1306857))
 * Report.get_logind_session(): Check $XDG_SESSION_ID and /run/systemd/sessions
   instead of the cgroup, as the latter does not work under cgmanager.

2.16 (2015-02-06)
-----------------
Improvements/behaviour changes:
 * Add a new method ProblemReport.extract_keys() which writes binary keys
   (which can be very large) directly to files without loading them all into
   memory first. Use that in apport-unpack. Thanks Louis Bouchard!
   ([LP: #1307413](https://launchpad.net/bugs/1307413))
 * launchpad backend: Work with Python 3, now that launchpadlib exists for
   Python 3. ([LP: #1153671](https://launchpad.net/bugs/1153671))
 * apport-bug, apport-gtk: Also check for $WAYLAND_DISPLAY, to use apport-gtk
   instead of apport-cli under Wayland. Thanks Tim Lunn.
   ([LP: #1418766](https://launchpad.net/bugs/1418766))
 * apport-gtk: When running under Wayland, avoid Gdk/Wnck operation for setting
   crash window modal to the PID of the crashed window; these only work under
   X11.
 * Don't install the test suite any more, to save 1 MB of installed space. It
   can be run out of trunk easily enough, and distributions can install it from
   tests/ if they desire.

Bug fixes:
 * hookutils, attach_root_command_outputs(): Fix UnicodeDecodeError crash for
   non-textual values. ([LP: #1370259](https://launchpad.net/bugs/1370259))
 * ui.py: Only provide a UI to hooks if the crash db will accept the report.
   This avoids asking questions if the report is merely sent to whoopsie for
   Ubuntu stable releases. Thanks Brian Murrary.
   ([LP: #1084979](https://launchpad.net/bugs/1084979))
 * whoopsie-upload-all: Add package information to the report before calling
   package hooks. Thanks Brian Murray.
 * Fix check for available terminal when checking whether to display the
   "Examine locally" button.

2.15.1 (2014-12-19)
-------------------
 * Robustify report.test_get_timestamp test.
 * Robustify signal_crashes.test_limit_size test.
 * Adjust launchpad crashdb testsuite to work against current Launchpad.
 * apt/dpkg _search_contents(): Check HTTP last-modified header to avoid
   re-downloading Contents.gz every day unless it actually changed. Thanks
   Brian Murray!
 * apport-gtk: Drop properties which are deprecated in GTK 3.14.

2.15 (2014-12-02)
-----------------
 * ui.py: Robustify check if apport-retrace is installed. This brings back the
   "Examine locally" UI option.
   ([LP: #1358734](https://launchpad.net/bugs/1358734))
 * recoverable_problem: Handle the parent process going away while we're
   attempting to read from proc.
 * apport-retrace: Stop considering a package download error as transient; it
   can too easily lead to unnoticed eternal retry loops.
 * whoopsie-upload-all: Refactor to behave more reliably in case of overlapping
   crash processing. Thanks Steve Langasek and Brian Murray.
   ([LP: #1354318](https://launchpad.net/bugs/1354318))
 * whoopsie-upload-all: Remove crash reports that have a core dump which is
   broken and cannot be processed by gdb. Thanks Brian Murray.
   ([LP: #1376374](https://launchpad.net/bugs/1376374))
 * Stop setting $PATH in the init.d script. It breaks assumptions from
   /lib/lsb/init-functions.d/ which might call other tools which are not in
   /bin; also, we generally shouldn't meddle with $PATH in individual scripts.
   ([LP: #1372665](https://launchpad.net/bugs/1372665))
 * When core size exceeds the limit (3/4 of available memory) and thus the core
   dump is skipped, log this to /var/log/apport.log.
   ([LP: #1387835](https://launchpad.net/bugs/1387835))
 * apport-gtk: Fix jump-to-top on first click of the details treeview. Thanks
   Marius Gedminas. ([LP: #1387328](https://launchpad.net/bugs/1387328))
 * apport-retrace: Fix location of cached Contents.gz when using --sandbox-dir.
   ([LP: #1394798](https://launchpad.net/bugs/1394798))
 * Fix backend_apt_dpkg.test_install_packages_permanent_sandbox test case with
   proxy env variables with latest apt.
 * data/whoopsie-upload-all: confirm that the crash file exists before trying
   to remove it. ([LP: #1384358](https://launchpad.net/bugs/1384358))

2.14.7 (2014-08-29)
-------------------
 * Adjust backend_apt_dpkg.test_get_file_package() test: newer util-linux
   versions do not provide /etc/blkid.tab any more.
 * Fix interpretation of core dump ulimits: they are in bytes, not kB.
   ([LP: #1346497](https://launchpad.net/bugs/1346497))
 * apport-retrace: Don't require specifying an operation; default to updating
   the given .crash file. ([LP: #1361242](https://launchpad.net/bugs/1361242))
 * Write report even on UnreportableReasons, so that whoopsie can still upload
   them. ([LP: #1360417](https://launchpad.net/bugs/1360417))
 * apt/dpkg install_packages(): Write a "packages.txt" into sandbox root
   directory to keep track of installed packages and their versions.
   Prerequisite for [LP: #1352591](https://launchpad.net/bugs/1352591).
 * apt/dpkg install_packages(): Avoid re-downloading/installing packages which
   are already installed into a permanent sandbox. Prerequisite for
   [LP: #1352591](https://launchpad.net/bugs/1352591).
 * sandboxutils.py, make_sandbox(): Drop check for already existing files when
   dynamically resolving libraries and ExecutablePaths; with that, these
   packages would never get updated in a permanent sandbox. The new version
   tracking from above now takes care of that.
   ([LP: #1352591](https://launchpad.net/bugs/1352591))
 * Fix report.test_add_proc_info test to stop assuming that pid 1 is named
   "init", as one can specify a different one on the kernel command line.
 * report.py, add_gdb_info(): Check for truncated core dumps, and set
   UnreportableReason and raise an IOError on them. Handle this in
   apport-retrace and whoopsie-upload-all to fail properly instead of silently
   producing broken Stacktraces.
   ([LP: #1354571](https://launchpad.net/bugs/1354571))

2.14.6 (2014-08-18)
-------------------
 * general-hooks/generic.py: Fix hook crash if there are non-distro libraries
   and no user interface.
 * collect_info(): Don't assume that reports have a ProblemType. Fixes crashes
   with apport-collect. ([LP: #1325729](https://launchpad.net/bugs/1325729))
 * apport-retrace: Declare -s/-g/-o as mutually exclusive, to get proper error
   messages instead of silent misbehaviour.
   ([LP: #1352450](https://launchpad.net/bugs/1352450))
 * apport-gtk: Drop usage of deprecated GTK stock items.
   ([LP: #1348116](https://launchpad.net/bugs/1348116))

2.14.5 (2014-07-29)
-------------------
 * apport-bug: Stop checking the autoreport flag and calling
   whoopsie-upload-all; these two are different tasks, and that breaks bug
   reporting. ([LP: #1339663](https://launchpad.net/bugs/1339663))
 * apt/dpkg get_file_package(): If checking for uninstalled packages, don't
   use package information from the host system, but always look it up in the
   correct indexes. Otherwise this returns wrong results when files move to a
   different package between releases. Thanks Brian Murray!
   ([LP: #1336062](https://launchpad.net/bugs/1336062))
 * apt/dpkg install_packages(): Disable fetching apt translation indexes, to
   save some bandwidth.
 * whoopsie-upload-all: Ignore crash reports with incomplete core dumps instead
   of crashing on them. Thanks Brian Murray.
   ([LP: #1329520](https://launchpad.net/bugs/1329520))
 * etc/default/apport: Fix comment to use "service" instead of calling the
   init.d script directly.
 * whoopsie-upload-all: Collect hooks information to gather ApportVersion,
   NonfreeKernelModules, and SystemImageInfo. Do this before collecting package
   data to minimize hook run time.
   ([LP: #1349579](https://launchpad.net/bugs/1349579))
 * Adjust report.test_get_logind_session test to work with systemd >= 205.
 * Fix report.test_check_interpreted_twistd test to skip instead of fail if
   twisted is not installed.

2.14.4 (2014-07-03)
-------------------
 * Adjust code to match latest pep8 checker.
 * Report.crash_signature_addresses(): Drop kernel architecture from
   StacktraceAddressSignature field. It isn't useful there (at most the ELF
   architecture, but we don't really need that either). This makes it easier to
   regenerate broken signatures from existing reports on different
   architectures. ([LP: #1336565](https://launchpad.net/bugs/1336565))

2.14.3 (2014-05-30)
-------------------
 * Add kernel package version to the various kernel-related hooks. Thanks Brian
   Murray. ([LP: #1316845](https://launchpad.net/bugs/1316845))
 * Use package name in duplicate signature for recoverable problems. Thanks
   Brian Murray. ([LP: #1316763](https://launchpad.net/bugs/1316763))
 * Have whoopsie-upload-all upload recoverable problems. Thanks Brian Murray.
   ([LP: #1319099](https://launchpad.net/bugs/1319099))

2.14.2 (2014-04-30)
-------------------
 * Delay the import of the glob and re modules in the python apport hook,
   and only import them when needed. Speeds up interpreter startup time
   by 50%. Thanks Matthias Klose!
   ([LP: #1307684](https://launchpad.net/bugs/1307684))
 * Move error handling for invalid .crash files into collect_info(), so that it
   also applies when using the "Show Details..." button in the UI. Otherwise
   the UI just hangs eternally at this point when encountering broken core
   dumps. ([LP: #1282349](https://launchpad.net/bugs/1282349))
 * apt/dpkg install_packages(): Try to install the requested package version
   instead of always picking the most recent one. This should improve retracing
   results for older crash reports. Thanks to Brian Murray for inspiring this.
 * sandboxutils.py, make_sandbox(): When determining packages to install from
   ProcMaps, look up and use the package versions from the reporter, to improve
   retracing results. Thanks Brian Murray for the initial patch!
 * iwlwifi_error_dump: Make reports private, and subscribe canonical-kernel-team.
   Thanks Seth Forshee. ([LP: #1313818](https://launchpad.net/bugs/1313818))
 * signal_crashes test: Time out after 5 seconds if the test process does not
   terminate on the specified signal, to avoid eternal hangs.
 * signal_crashes test: Ensure that we don't inherit an ignored SIGQUIT from
   the caller.

2.14.1 (2014-04-04)
-------------------
 * Fix FileNotFoundError from temporary launchpadlib cache dir cleanup.
   ([LP: #1300474](https://launchpad.net/bugs/1300474))
 * ui.py, open_url(): Skip any Python cleanup/atexit handlers in the forked
   xdg-open child, to avoid calling them twice. (Side issue of
   [LP: #1300474](https://launchpad.net/bugs/1300474) and
   [LP: #1282713](https://launchpad.net/bugs/1282713))
 * apport-kde: Work around crash in sip by skipping the destructors of SIP
   objects. Thanks Rohan Garg!
   ([LP: #1282713](https://launchpad.net/bugs/1282713))

2.14 (2014-03-31)
-----------------
 * Add KernelCrash reports when iwlwifi encounters a firmware error (via the
   "error_dump" uevent and the new iwlwifi_error_dump helper). Thanks Seth
   Forshee!
 * launchpad: Really use a temporary launchpadlib cache dir by default. This
   avoids piling up gigabytes of useless cached data over time, which also
   tends to break every now and then.
 * Fix crash in logind session detection. Thanks Dimitri Ledkov!
   ([LP: #1296026](https://launchpad.net/bugs/1296026))

2.13.3 (2014-03-07)
-------------------
 * Fix backend_apt_dpkg.test_get_file_package_uninstalled test that got broken
   in the previous release.
 * etc/cron.daily/apport: Cleanup .drkonqi files after 7 days. Thanks Harald
   Sitter.
 * ui.py: Try to grab session D-BUS address from user's session when being
   called through pkexec. ([LP: #1287460](https://launchpad.net/bugs/1287460))

2.13.2 (2014-01-27)
-------------------
 * Fix crash if systemd cgroup is unreadable in /sys, such as in containers.
   ([LP: #1270783](https://launchpad.net/bugs/1270783))
 * apt/dpkg: Also consider Contents.gz from updates/security/proposed pockets,
   so that e. g. apport-retrace works for crash reports with files that are new
   in those. Thanks to Brian Murray for the initial patch.
   ([LP: #1271258](https://launchpad.net/bugs/1271258))
 * Only drop internal/private keys (starting with '_') from uploading to the
   crash DB and from the UI report views, but not already when updating the
   report. ([LP: #1272505](https://launchpad.net/bugs/1272505))
 * data/apport: Fix stdout/stderr initialization of the error log, don't close
   the original fd after dup2'ing as it is usually already fd 1. This makes
   Apport work with Python 3.4.
   ([LP: #1272355](https://launchpad.net/bugs/1272355))
 * Adjust report tests to work with Python 3.4
   ([LP: #1272355](https://launchpad.net/bugs/1272355))

2.13.1 (2014-01-10)
-------------------
 * Fix report.test_get_timestamp test for running in other time zones.
 * Fix erroneous "gdb-multiarch not installed" warnings in ui tests.
 * Fix ui.test_run_crash_older_session test for running as root.
 * Fix ui.test_run_crash_older_session for different file system file orders.

2.13 (2014-01-10)
-----------------
Improvements:
 * whoopsie-upload-all: Add a -t/--timeout option. In CI environments it is
   undesirable to block on upload for 30 mins, but it's still a reasonable
   timeout on less well connected devices.
 * Do not report keys starting with '_' to the crash database. This can be used
   for keeping private keys in .crash files between crash and report time, or
   to store data between hooks etc., without cluttering reports.
 * UI: In "run all pending crashes" mode, skip reports that happened during
   logout in a desktop (specifically, logind) session; they are uninteresting
   and confusing to see at the next login.
   ([LP: #1033932](https://launchpad.net/bugs/1033932)) They can still be
   reported manually with running the .crash file directly, but this
   sufficiently reduces the need to explicitly flag whether the report concerns
   a logout crash. ([LP: #1067646](https://launchpad.net/bugs/1067646))
 * Add support for PID namespaces (Linux containers): Crashes originating from
   a container on a system running a >= 3.12 kernel will be automatically
   redirected to apport inside the container, or ignored if apport is not
   installed in the container. Thanks to Stéphane Graber!

Bug fixes:
 * test_signal_crashes: Clean up unexpected reports after every test, to avoid
   breaking all subsequent tests.
 * test_signal_crashes: Stop checking that gdb prints nothing on stderr, as
   latest gdb 7.6.50 now almost always prints some about missing source files.
 * setup.py: Make updating of hashbangs work when building without Java, and
   also apply it on bin/.
 * Print a warning when trying to retrace a report from a foreign architecture
   and gdb-multiarch is not installed.
   ([LP: #1239395](https://launchpad.net/bugs/1239395))
 * etc/init.d/apport: Don't change core_pattern when running in a container, as
   this influences the host and other containers, too.
   ([LP: #1267728](https://launchpad.net/bugs/1267728))

2.12.7 (2013-11-19)
-------------------
 * Properly fall back to lsb_release if /etc/os-release is invalid.
 * report.py, add_proc_info(): Add "CurrentDesktop" field with the value of
   $XDG_CURRENT_DESKTOP, if present.
   ([LP: #1247904](https://launchpad.net/bugs/1247904))
 * fileutils.py, get_all_system_reports(): Filter out "guest..." users, they
   might have a system UID.
   ([LP: #1250679](https://launchpad.net/bugs/1250679))
 * apt/dpkg: Don't call dpkg-divert with full path, it moved in Ubuntu 14.04.

2.12.6 (2013-10-25)
-------------------
 * SECURITY FIX: For setuid programs which drop their privileges after
   startup, make the report and core dumps owned by root, to avoid possible
   data disclosure. Also, change core dump files to permissions "0600".
   Thanks to Martin Carpenter for discovering this!
   (CVE-2013-1067, [LP: #1242435](https://launchpad.net/bugs/1242435))
 * sandboxutils.needed_runtime_packages(): Create cache directory for
   Contents.gz if missing. ([LP: #933199](https://launchpad.net/bugs/933199))
 * apt/dpkg: Recognize options in apt sources.list.
   ([LP: #1238620](https://launchpad.net/bugs/1238620))

2.12.5 (2013-09-27)
-------------------
 * Report.add_os_info(): Do not overwrite already existing data.
   ([LP: #1226776](https://launchpad.net/bugs/1226776))
 * kernel_oops hook: Collect uname at the time of invoking the hook, instead of
   at data collection time. ([LP: #1226776](https://launchpad.net/bugs/1226776))
 * Replace fixed size icons with PNGs, which are more efficient and avoid
   rendering artifacts. ([LP: #1231763](https://launchpad.net/bugs/1231763))

2.12.4 (2013-09-19)
-------------------
 * Update icons to new design from Vishnoo Charan Reddy, many thanks!
   ([LP: #1079639](https://launchpad.net/bugs/1079639))

2.12.3 (2013-09-19)
-------------------
 * ProblemReport.write_mime(): Adjust MIMEText handling to latest Python 3.3
   upstream changes which now don't tolerate passing bytes any more.
   ([LP: #1227381](https://launchpad.net/bugs/1227381))
 * apport-gtk: Don't use obsolete add_with_viewport() method any more.
 * Fix ui_present_report_details() "modal_for" keyword for all UI
   implementations, so that --hanging works for -cli and -kde, too.
   ([LP: #1213790](https://launchpad.net/bugs/1213790))

2.12.2 (2013-09-17)
-------------------
 * fileutils.py, get_{new,all}_reports(): Don't consider reports which are
   readable, but not writable.
   ([LP: #1098844](https://launchpad.net/bugs/1098844))
 * test_ui_kde.py: Cleanly skip the test if PyQt/PyKDE are not installed,
   instead of failing.
 * crash-digger: Write pid into lock file. Thanks Steve Langasek.
 * apport-gtk: When loading a Bug report from a file, properly set up for bug
   reporting mode. ([LP: #1226140](https://launchpad.net/bugs/1226140))
 * Move "program is not installed any more" check from report loading into data
   collection, so that crash reports can be moved and reported on machines
   without that program installed.
   ([LP: #1226030](https://launchpad.net/bugs/1226030))

2.12.1 (2013-08-19)
-------------------
 * sandboxutils.py, make_sandbox(): Install packages from Package: and
   Dependencies: fields also if we have a ProcMaps: field and there are any
   third-party packages. This fixes retracing crashes that use PPAs (as they
   don't have Contents.gz).
 * Robustify "progress bar visible" GTK and KDE UI checks for the faster
   collection due to dropping lsb_release.
 * Drop apport-noui in favour of whoopsie-upload-all. We don't want to process
   hooks when run noninteractively, since they may ask questions or determine a
   report is not due to a bug in Ubuntu. whoopsie-upload-all skips these hooks.
 * apport/report.py: Gracefully handle being unable to get the source package
   for a binary package, as when the latter does not exist in the cache.
   ([LP: #1097773](https://launchpad.net/bugs/1097773))

2.12 (2013-08-02)
-----------------
Improvements:
 * recoverable_problem: Can take the PID as an argument.
 * Add data/whoopsie-upload-all: Process all pending crashes and mark them for
   whoopsie upload, but do not upload them to any other crash database. Wait
   until whoopsie is done uploading.
 * Eliminate multiple calls to lsb_release by caching the result. On systems
   which provide /etc/os-release, use that instead of lsb_release.
   ([LP: #1164742](https://launchpad.net/bugs/1164742))

Bug fixes:
 * launchpad.py: Show the Python major version in the error message about
   missing launchpadlib.
 * ui.py: Check if options for updating and reporting a new bug get used
   together, and give a proper error message in this case.
   ([LP: #1071905](https://launchpad.net/bugs/1071905))
 * apport: Fix "Exectuable" typo, leading to reports not being synced on
   upstart crashes. Thanks James Hunt.
   ([LP: #1203744](https://launchpad.net/bugs/1203744))
 * Rename apport-gtk-mime.desktop to apport-gtk.desktop and drop the
   old apport-gtk.desktop that wasn't even being installed. With that, the
   window will be shown as "Report a problem..." instead of "Apport-gtk" in
   GNOME shell and other DEs. Thanks Jeremy Bicha.
   ([LP: #1207496](https://launchpad.net/bugs/1207496))
 * report.py, add_gdb_info(): Fix crash if gdb cannot load the symbol map.
   ([LP: #1171484](https://launchpad.net/bugs/1171484))
 * apport-retrace: Fix crash when using --sandbox without --cache.
   ([LP: #1197034](https://launchpad.net/bugs/1197034))
 * Fix error message when PID is inaccessible.
   ([LP: #1204718](https://launchpad.net/bugs/1204718))
 * doc/data-format.tex: Drop unused "OS" and "OSRelease" fields, replace with
   "DistroRelease" which is actually being used.
   ([LP: #1018387](https://launchpad.net/bugs/1018387))

2.11 (2013-07-17)
-----------------
Improvements:
 * data/apport-noui: A noninteractive frontend for automatic error
   reporting. apport-bug will use this if the /etc/apport/autoreport flag
   file exists.
 * hookutils.py, attach_upstart_logs(): Also attach
   ~/.cache/upstart/application-<desktopname>.log for any *.desktop file
   shipped by a package.

Bug fixes:
 * hookutils.py, attach_conffiles(): Fix check for inaccessible or modified
   conffiles. ([LP: #1192899](https://launchpad.net/bugs/1192899))

2.10.2 (2013-05-22)
-------------------
Bug fixes:
 * Resolve symlinks in file references in Python crash signatures.
   ([LP: #1179979](https://launchpad.net/bugs/1179979))
 * Fix endless loop of EOFErrors with broken core dumps.
   ([LP: #1168849](https://launchpad.net/bugs/1168849))
 * report.py, add_gdb_info(): Fix crash if gdb did not determine an assertion
   message. ([LP: #1171484](https://launchpad.net/bugs/1171484))
 * apt/dpkg: Fix get_file_package()'s "release" field to actually mean
   DistroRelease:, not a distro code name. This now requires a previous call to
   install_packages() with a configdir, which needs to have a file
   <configdir>/<release>/codename with the release's code name in it.
 * sandboxutils.py: Call get_file_package() with the report's release, so that
   we actually get files from the target release, not the host release.
 * test_hookutils.py: Don't assume that /etc/motd exists.

2.10.1 (2013-05-14)
-------------------
Bug fixes:
 * Fix ui.test_run_crash_anonymity_escaping test when running as root.
 * launchpad.py: Fix crash when trying to adjust a distro-only bug task if the
   bug also already has a distropackage task.
 * apt/dpkg: When there is no -dbg package, install all -dbg packages of the
   corresponding source package, and only then fall back to -dbgsym.
   ([LP: #1003234](https://launchpad.net/bugs/1003234))

2.10 (2013-04-30):
------------------
Improvements:
 * Support retracing foreign powerpc reports, thanks Steve Langasek.
 * apport/report.py: Generate a crash signature for suspend/resume failures.
 * hookutils.py: Add attach_upstart_logs(), thanks Steve Langasek.
 * hookutils.py, in_session_of_problem(): Port from ConsoleKit to logind.

Bug fixes:
 * hookutils.attach_conffiles(): Fix IOError crash on inaccessible conffiles;
   mark them as '[inaccessible: <reason>]' instead.
   ([LP: #1154536](https://launchpad.net/bugs/1154536))
 * hookutils.in_session_of_problem(): Fix crash when the current locale is
   invalid. ([LP: #1154896](https://launchpad.net/bugs/1154896))
 * data/gcc_ice_hook: Fix crash with source files that have non-UTF8 data.
   ([LP: #1045283](https://launchpad.net/bugs/1045283))
 * apport/report.py: Handle the case where the user has been removed from the
   system, but one of its still-running binaries crashes
   ([LP: #1163453](https://launchpad.net/bugs/1163453)).
 * Fix anonymization of user/GECOS fields with regexp control characters like
   '+'. ([LP: #985049](https://launchpad.net/bugs/985049))
 * Run tests under LC_CTYPE=C and unset LANG as well, to discover assumptions
   about UTF-8 locales. Fix the two failing tests.
 * Fix UnicodeDecodeError when apport encounters non-ASCII environment
   variables. ([LP: #1172638](https://launchpad.net/bugs/1172638))

2.9.2 (2013-03-19):
-------------------
Improvements:
 * report.py, add_package_info(): Add "[origin: unknown]" tag to
   Package/Dependencies fields for non-distro package whose origin cannot be
   determined. ([LP: #1148116](https://launchpad.net/bugs/1148116))
 * Adjust kernel_crashdump to the format kdump-tools produces. Thanks Louis
   Bouchard.

Bug fixes:
 * Write core dumps on SIGQUIT if ulimit allows. Thanks Graeme Hewson.
   ([LP: #1153662](https://launchpad.net/bugs/1153662))

2.9.1 (2013-03-07):
-------------------
Improvements:
 * launchpad.py: Add support for filing bugs as private. Document this in
   doc/crashdb-conf.txt. ([LP: #1144647](https://launchpad.net/bugs/1144647))

Bug fixes:
 * test_signal_crashes.py: Fix test_crash_apport() when being run under
   LD_PRELOAD.
 * Fix crash in error() and warning() if there is no sys.stderr.
   ([LP: #1012445](https://launchpad.net/bugs/1012445))
 * Fix Turkish translation to add missing keyboard accelerator.
   ([LP: #648750](https://launchpad.net/bugs/648750))
 * fileutils.py, find_package_desktopfile(): Restrict to autostart and
   application .desktop files.
   ([LP: #1147528](https://launchpad.net/bugs/1147528))
 * apt/dpkg get_modified_files(): Fix crash when encountering non-ASCII file
   names in an ASCII locale.
   ([LP: #1044014](https://launchpad.net/bugs/1044014))

2.9 (2013-03-01):
-----------------
Improvements:
 * fileutils.py, shared_libraries(): Return a "name → path" dict instead of
   just a set of names. Thanks Kyle Nitzsche.
 * sandboxutils.py: Support unpackaged executables, i. e. reports which do not
   have "Package" and "Dependencies" fields. For those, get required libraries
   from "ProcMaps". Thanks Kyle Nitzsche.

Bug fixes:
 * Add "com.ubuntu.apport.apport-gtk-root" polkit action for running apport-gtk
   through pkexec to access system crash reports. Thanks Brian Murray.
 * ui.py: Check $PKEXEC_UID in addition to $SUDO_UID for opening a browser.
 * apport/report.py: report if LD_PRELOAD and LD_LIBRARY_PATH are set. Thanks
   James Hunt.
 * apport-valgrind: Cleanly exit on keyboard interrupts. Thanks Kyle Nitzsche.
 * debian.py: Fix "string payload expected" crash when building the report.
   Thanks Dmitry Shachnev. (Debian #698010)
 * Move shared_libraries() and links_with_shared_library() from hookutils into
   fileutils, so that we can use it from apport-valgrind. Thanks to Kyle
   Nitzsche for the initial patch.
 * fileutils.shared_libraries(): Filter out virtual "linux-vdso" from result.
   Thanks Kyle Nitzsche.
 * apport-valgrind: Fix path to debug symbols in the sandbox.
 * ui.py, get_desktop_entry(): Fix for Python 2.

2.8 (2013-01-08):
-----------------
Improvements:
 * Factor out sandbox management functions from apport-retrace into
   apport/sandboxutils.py, so that other programs can re-use the API easily.
   Thanks to Kyle Nitzsche for the initial work on this.
 * Generate a crash signature for kernel OOPSes.
 * Add "apport-valgrind" tool to produce valgrind reports in a temporary
   sandbox with debug symbols (similar to apport-retrace). Thanks Alex Chiang
   and Kyle Nitzsche!

Bug fixes:
 * Fix StacktraceAddressSignature generation on ARM.
   ([LP: #1089778](https://launchpad.net/bugs/1089778))
 * debian.py: Fix TypeError crash in payload generation. Thanks Ritesh Raj
   Sarraf.
 * apport_python_hook.py: Update "ExecutableTimestamp" field when mangling
   "ExecutablePath". ([LP: #1077253](https://launchpad.net/bugs/1077253))

2.7 (2012-12-10):
-----------------
Improvements:
 * packaging.py, get_file_package(): Add optional "release" and "arch"
   arguments for getting a file's package for a foreign release or
   architecture. Implement this for apt/dpkg backend.
 * packaging.py, install_packages(): Add optional "architecture" argument for
   creating a sandbox for a foreign architecture. Implement this for apt/dpkg
   backend.
 * When a report's architecture does not match the system architecture, try to
   use gdb-multiarch (if available, as packaged on Debian/Ubuntu), and set
   architecture and gnutarget accordingly in gdb. This supports x86, x86_64,
   and ARM for now, so that reports from all these architectures can be
   retraced on an x86_84 machine.
   ([LP: #1044437](https://launchpad.net/bugs/1044437))
 * launchpad.py: Add "architecture" option to process reports for a foreign
   architecture.
 * Add exceptions from package hooks to new HookError_<filename> report field,
   to make them more visible. Until now they were only written to stderr.
   ([LP: #1086309](https://launchpad.net/bugs/1086309))

Bug fixes:
 * Fix test_find_package_desktopfile test to not consider packages with only
   one "NoDisplay=true" .desktop file for the "has one desktop file" test.
 * report.py, mark_ignore(): Use home directory of actual effective user, not
   of $HOME. Fixes ignore file when using through sudo.
 * apport-cli: Fix showing of prompt. Thanks Dmitry Shachnev!
 * fileutils.py, mark_report_upload(): Do not try to remove the .uploaded file,
   as this is not owned by the user.
 * backends/packaging-apt-dpkg.py, install_packages(): Set mirror to the one in
   the sandbox config.
 * apportcheckresume: Fix crash if state file does not exist.

2.6.3 (2012-11-30):
-------------------
 * test_signal_crashes.py: Fix incompatibility with Python 3.3.
 * test_signal_crashes.py: Allow XDG_RUNTIME_DIR environment variable, as it
   only shows whether or not it is set. (Test regression from 2.6)
 * debian.py: Only reject reports with useless stack traces if the report
   actually has a stack trace at all.
 * debian.py: Fix UTF-8 string handling. Thanks Ritesh Raj Sarraf.
 * debian.py: Fix crash on broken "Package" fields, as generated by current
   Debian/Ubuntu dkms package.
 * data/apport: Call fsync when writing upstart crash reports.
 * report.py, add_gdb_info(): Handle libnih's assertion messages.
   ([LP: #997359](https://launchpad.net/bugs/997359))
 * apport-gtk, apport-kde: Don't provide an option to restart a crashed
   application when the crash occurred in a thread
   ([LP: #1033902](https://launchpad.net/bugs/1033902)).
 * apport-retrace: Disallow option -C without option -S. Thanks Kyle Nitzsche.
 * fileutils.py, mark_report_upload(): Refresh the .upload stamps if a previous
   version of the report was already uploaded, but another instance of the
   problem happened since then. Thanks Brian Murray.
   ([LP: #1084296](https://launchpad.net/bugs/1084296))
 * Ignore implausibly low addresses when computing StacktraceAddressSignature.
   These are usually artifacts from gdb when not having debug symbols, and
   having too many of them prevents proper client-side duplicate detection and
   proper bucketing in daisy.
   ([LP: #1084996](https://launchpad.net/bugs/1084996))
 * fileutils.py: Ignore .desktop files with NoDisplay=true.
   ([LP: #1048524](https://launchpad.net/bugs/1048524))

2.6.2 (2012-11-06):
-------------------
 * problem_report.py: Fix UnicodeDecodeError crash under Python 2 when the
   report has an unicode field with an unprintable ASCII character < 20.
 * debian.py: Fix calling of parent accepts() method and return value. Thanks
   Ritesh Raj Sarraf.
 * bin/apport-retrace: Fix crash when not using --sandbox mode.
 * report.py, add_proc_info(): Throw correct exception if the executable path
   does not exist, to provide a more appropriate error message.
   ([LP: #1065129](https://launchpad.net/bugs/1065129))
 * report.py, add_gdb_info(): Check __glib_assert_msg for assertion messages,
   too.
 * REThread.py: Fix for Python 3.3.

2.6.1 (2012-10-01):
-------------------
 * setup.py: Specify "-source 1.5" javac option as well, to avoid build failure
   with OpenJDK 7.

2.6 (2012-10-01):
-----------------
 * setup.py: Build java module with "-target 1.5" option, so that you can run
   it with OpenJDK 6 even if you build with OpenJDK 7.
 * report.py, add_proc_info(): Show if $XDG_RUNTIME_DIR is set.
 * Add apport/crashdb_impl/debian.py: Initial crash database implementation for
   the Debian BTS. Add configuration for it to etc/apport/crashdb.conf. Thanks
   Ritesh Raj Sarraf!
 * test_python_crashes.py: Robustify "$PYTHONPATH in ProcEnviron" check.

2.5.3 (2012-09-28):
-------------------
 * data/apportcheckresume: Open report file in binary mode.
   ([LP: #1040353](https://launchpad.net/bugs/1040353))
 * packaging-apt-dpkg.py: When throwing ValueErrors, show the non-existing
   package name. This makes it easier to debug such crashes.
 * launchpad.py: Replace characters from tags which are not allowed by
   Launchpad with '.' ([LP: #1029479](https://launchpad.net/bugs/1029479))
 * launchpad.py: Temporarily disable filing private bugs in the test suite, to
   work around the SSLHandshakeError error when downloading private attachments
   from staging.
 * hookutils.py, attach_root_command_outputs(): Ignore IOError crash about
   nonexisting files, which can happen if the user dismisses authorization.
   ([LP: #1051222](https://launchpad.net/bugs/1051222))
 * report.py, search_bug_patterns(): Fix bug patterns containing non-ASCII
   characters. Thanks Brian Murray.
 * apport_python_hook.py: Capture $PYTHONPATH and $PYTHONHOME environment
   variables for Python crashes. Thanks Brian Murray.

2.5.2 (2012-09-17):
-------------------
 * test/run: Ignore root_info_wrapper with pyflakes.
 * packaging-apt-dpkg.py: Add recommended packages to "Dependencies:" field.
   ([LP: #1014428](https://launchpad.net/bugs/1014428))
 * test_hookutils.py, test_in_session_of_problem(): Use year 2038 for a future
   date instead of 2211, as current Python 3.2 now crashes with an
   OverflowError on 32 bit machines with later years.
 * Fix crash on broken .desktop files.
   ([LP: #1039889](https://launchpad.net/bugs/1039889))
 * apport-gtk: For console program crashes, say "stopped" instead of "closed".
   Add a subtitle label with a hint about hanging programs. Thanks Matt Price
   and Matthew Paul Thomas!
 * report.py: Fix crash on determination of Python module path when examining a
   crash of "python -m ...".
 * apport-kde: Fix crash with undefined QString under Python 3. Thanks Jonathan
   Riddell! ([LP: #1028984](https://launchpad.net/bugs/1028984))
 * launchpad.py: Add missing "Pre-release Freeze" status. Thanks Brian Murray!
 * report.py, _check_bug_pattern(): Fix bug pattern matching against binary
   values. Thanks Brian Murray for the original patch.
   ([LP: #1016380](https://launchpad.net/bugs/1016380))

2.5.1 (2012-08-22):
-------------------
 * data/root_info_wrapper: Turn into a real file, a symlink can cause some
   packaging problems.

2.5 (2012-08-22):
-------------------
Bug fixes:
 * test_recoverable_problem.py: Fix test for calling test runner with absolute
   path.
 * packaging-apt-dpkg.py: Fix crash on writing virtual_mapping.db when running
   with --sandbox-dir and -S system or giving no --cache.
 * REThread.py: Fix re-raising of exceptions in Python 3. Thanks Martin
   Packman! ([LP: #1024836](https://launchpad.net/bugs/1024836))
 * apport-retrace: Keep compressed CoreDump from .crash files instead of
   uncompressing them into memory. This dramatically reduces memory usage.
   ([LP: #981155](https://launchpad.net/bugs/981155))

Improvements:
 * Add an apport.memdbg() function which prints out current memory usage if
   APPORT_MEMDEBUG is set. Annotate apport-retrace with it.
 * hookutils.py: Allow specifying a list of profile names when using
   attach_mac_events(). Thanks Marc Deslauriers.
 * hookutils.py, attach_root_command_outputs() and root_command_output(): Drop
   usage of sudo, kdesudo, and gksu, and replace with pkexec. For
   attach_root_command_outputs(), use a wrapper and proper .policy file which
   explains the action and works under every environment; thus
   attach_root_command_outputs() is preferred over root_command_output() now,
   as it provides a better user experience.
 * Package hooks which want to send the report to a different crash database
   than "default" can now also give the database specification itself in the
   "CrashDB" field, not just the DB name. With this, packages do not need to
   ship a separate /etc/apport/crashdb.conf.d/ file. Please see
   doc/package-hooks.txt for details.
   ([LP: #551330](https://launchpad.net/bugs/551330))
 * report.py, add_hooks_info(): If reporting against a package/program in /opt,
   also search for package hooks in the corresponding /opt directory. This
   allows such hooks to define a custom crash database and thus report bugs
   against their own project instead of against the distribution.
   ([LP: #1020503](https://launchpad.net/bugs/1020503))

2.4 (2012-07-18):
-----------------
Improvements:
 * apport_python_hook.py: For org.freedesktop.DBus.Error.ServiceUnknown
   exceptions, add a 'DbusErrorAnalysis' field to the report which points out
   whether any .service file provides the service it tried to talk to, and
   whether the processes for those are running. This helps to determine the
   root cause for such errors (missing dependencies, broken .service files,
   talking to the wrong bus, etc.)
   ([LP: #1020572](https://launchpad.net/bugs/1020572))
 * hookutils.py, attach_alsa(): Use alsa-info.sh when available. Thanks David
   Henningson.
 * Add new "RecoverableProblem" report type for problems which the application
   can handle, but still wishes to notify the user and send a problem report
   about. As an example, the application may wish to notify the user because
   handling the error resulted in degraded functionality. The user interface
   may fail to load items, or the action just performed may not return any
   data. Applications call /usr/share/apport/recoverable_problem with a
   string of arbitrary NUL-separated key/value pairs that are added to the
   report. Thanks Evan Dandrea!

Bug fixes:
 * ui tests, test_wait_for_pid(): Fix eternal hang when running as root.
 * testsuite: Fix ResourceWarnings when running with Python 3.
 * test_python_crashes.py: Fix race condition in timeout test.
 * launchpad.py: Fix setting of 'Medium' importance on duplicate checking.
 * apport-retrace: Fix StacktraceSource generation for relative --cache paths.
 * crashdb.py, check_duplicate(): Do not try to mark a bug as duplicate of
   itself. This can happen when re-processing a previously retraced bug.
 * apport-retrace: Fix UnicodeDecodeError when encountering a non-ASCII source
   code file and running under a non-UTF-8 locale.

2.3 (2012-07-09):
-----------------
Improvements:
 * launchpad.py: Rework test suite to not use Launchpad's +storeblob facility
   at all any more. It almost never works on staging and is horribly slow. Fake
   the bug creation from a blob by manually creating the comment and
   attachments ourselves, and just assume that storeblob works on production.
   Also change the structure to allow running every test individually.
 * crash-digger: Add --crash-db option to specify a non-default crash databae
   name. ([LP: #1003506](https://launchpad.net/bugs/1003506))
 * apport-gtk: Add --hanging option to specify the process ID of a hanging
   application. If the user chooses to report this error, apport will terminate
   the pid with SIGABRT, otherwise it will send SIGKILL. The normal core pipe
   handler will be used to process the resulting report file, with a .hanging
   file in /var/crash to separate these from regular crashes.

Bug fixes:
 * apport: Also treat a binary as modified if the /proc/pid/exe symlink does
   not point to an existing file any more.
   ([LP: #984944](https://launchpad.net/bugs/984944))
 * Fix PEP-8 violations picked up by latest pep8 checker.
 * ui.py: Do not ignore certain exceptions during upload which are not likely
   to be a network error.
 * launchpad.py: Recongize Launchpad projects for bug query and marking
   operations. ([LP: #1003506](https://launchpad.net/bugs/1003506))
 * packaging-apt-dpkg.py: Fix get_source_tree() to work with apt sandboxes.
 * apport-retrace: Turn StacktraceSource generation back on, now that it works
   with the current sandboxing.
 * launchpad.py: Ensure that upload chunk size does not underrun.
   ([LP: #1013334](https://launchpad.net/bugs/1013334))
 * apport_python_hook: Fix UnicodeEncodeError crash with Python 2 for
   exceptions with non-ASCII characters.
   ([LP: #972436](https://launchpad.net/bugs/972436))
 * test_ui_kde.py: Fix occasional test failure in test_1_crash_details if the
   application ends before the "is progress bar visible" check is done.

2.2.5 (2012-06-21):
-------------------
 * launchpad.py: Fix str vs. bytes crash for already known bugs, take 2.
   ([LP: #1015788](https://launchpad.net/bugs/1015788))
 * apport/ui.py, get_desktop_entry(): Disable interpolation, to correctly read
   desktop files with % signs.
   ([LP: #1014341](https://launchpad.net/bugs/1014341))
 * apport/ui.py: Fix rare crash if a report is already being updated in the
   background when the UI tries to update a previous version.
   ([LP: #949196](https://launchpad.net/bugs/949196))
 * GTK and KDE UI tests: Avoid eternal hangs due to "this is not a distro
   package" error messages.

2.2.4 (2012-06-21):
--------------------
Bug fixes:
 * test_apport_unpack.py: Fix test_unpack_python() test when running the
   system-installed tests.
 * data/java_uncaught_exception: Fix for Python 3.
 * test_signal_crashes.py: Show crash reports in /var/crash/.
 * test_crash_digger.py: Do not write crash reports of crash-digger into system
   /var/crash, use a temporary directory.
 * test/run: Wait for a previous xvfb server to finish before trying to start
   one. This fixes a race condition in the KDE UI tests which often failed to
   start up xvfb.
 * apport-cli: Unbreak "keep" option.
   ([LP: #1007826](https://launchpad.net/bugs/1007826))
 * launchpad.py: Fix str vs. bytes crash for already known bugs.
   ([LP: #1015788](https://launchpad.net/bugs/1015788))

2.2.3 (2012-06-15):
-------------------
Bug fixes:
 * test/run: Do not run pep8 and pyflakes when running against the sytem
   installed Apport.
 * test_backend_apt_dpkg.py: For the "are we online" check, verify that we can
   download from http://ddebs.ubuntu.com/, not just whether we have a default
   route. The latter is not sufficient for e. g. buildd environments which are
   online, but are restricted by proxies or firewalls.
 * test_report.py: Call "sync" after test script write core dumps, to ensure
   that subsequent operations have a complete one.
 * test_signal_crashes.py: Drop the broken and obsolete test_local_python()
   test. Instead, add two tests which check proper logging.
 * launchpad.py: Fix urlopen() for Python3. Thanks Steve Langasek.
 * test/run: Run the tests under LC_MESSAGES=C, to avoid failing tests on
   translated strings.

2.2.2 (2012-06-13):
-------------------
Improvements:
 * testsuite: Run with Python 3 by default. To test with Python 2, run
   "PYTHON=python2 test/run".

Bug fixes:
 * apport: Redefine sys.std{out,err} when redirecting output, as they are None
   in Python 3 when being called from the kernel.
 * test/test_signal_crashes.py: Clean up unexpected core dumps on failed test
   cases.
 * apport-gtk: Fix crash when closing the crash dialog while the information is
   being collected.
 * hookutils.py, xsession_errors(): Fix crash when running under a non-UTF8 locale.
 * data/apport: Do not use sys.stdin.fileno(), it is invalid when being called
   from the kernel with Python 3.
 * data/apport: When core dumps are enabled, read them from the written report
   instead of directly from stdin (and then reading the written core file into
   the .crash report). If the core file size is limited, we otherwise stop
   reading the core dump from the kernel in the middle and have no (or a
   broken) core dump to be put into the report.
 * data/apport: Properly close the written crash report before changing its
   permissions to be readable. This prevents having crash reporting UI from
   looking at incomplete .crash files.

2.2.1 (2012-06-11)
------------------
Bug fixes:
 * apport-cli: Port to work with Python 3.
 * setup.py: When fixing hashbang lines of installed scripts, only include the
   major Python version.
 * hookutils.py, read_file, attach_file(), attach_file_if_exists(): Convert
   file contents to unicode if the contents is UTF-8, or the newly added
   force_unicode argument is True.
 * hooktuils, command_output(): Convert output to unicode by default, and add
   a "decode_utf8" parameter to disable this.
 * hookutils.py, recent_logfile(): Fix fd leak.
 * data/apport: Do not assume that sys.stdout and sys.stderr always have a
   name; they can be None in Python 3.
 * data/dump_acpi_tables.py: Fix for Python 3.

2.2 (2012-06-11)
----------------
Improvements:
 * Clean up module imports.
 * test/run: Run pyflakes, if available.
 * package_hook: Add --tags option. Thanks to Brian Murray.
 * launchpad.py: Drop the external multipartpost_handler.py (which is not
   portable to Python 3) and replace it with using the standard email module.
 * launchpad.py: Also work with Python 3. Deal gracefully with a missing
   "launchpadlib" module; this is not yet available for Python 3, but not
   required for client-side reporting.
 * apport-kde: Port to work with Python 3.

Bug fixes:
 * apport-retrace: Fix crash when using the --procmaps option.
 * setup.py: Update hashbang lines of installed scripts in data directory to
   the python executable setup.py was run with, similar to what already happens
   to scripts installed to ../bin/.

2.1.1 (2012-05-30)
------------------
Improvements:
 * launchpad.py: When closing a bug as a duplicate, copy some well-known tags
   to the master bug. Thanks Brian Murray.
 * launchpad.py: Set importance of Python crash reports to "Medium" by default,
   similar to signal crashes. Thanks Brian Murray.
 * hookutils.py: Add attach_default_grub() convenience function from the grub2
   package hook so it can be used by other packages. Thanks Brian Murray.
 * launchpad.py: Make Launchpad bug subscription user/team configurable: The
   initial subscriber after filing a bug can be set with the
   "initial_subscriber" crashdb option, and the team which gets subscribed
   after retracing with "triaging_team".
   ([LP: #980726](https://launchpad.net/bugs/980726))

Bug fixes:
 * report.py: Do not change the SourcePackage: field if the binary package is
   not installed and does not exist. This fixes source package hooks to
   actually work in some cases where source and binary package names overlap.
   (part of [LP: #993810](https://launchpad.net/bugs/993810))
 * apport-gtk, apport-kde: Avoid collecting information twice in "bug update"
   mode. This caused a crash in cases where the source package in a bug report
   does not correspond to an installed binary package.
   ([LP: #993810](https://launchpad.net/bugs/993810))

2.1 (2012-05-18)
----------------
Improvements:
 * packaging.py, install_packages(): Add permanent_rootdir flag and if set,
   only unpack newly downloaded packages. Implement it for the apt/dpkg
   backend. Thanks Evan Dandrea.
 * apport-retrace: Add --sandbox-dir option for keeping a permanent sandbox
   (unpacked packages). This provides a considerable speedup. Thanks Evan
   Dandrea.
 * crash-digger: Add --sandbox-dir option and pass it to apport-retrace.
 * Fix the whole code to be PEP-8 compatible, and enforce this in test/run by
   running the "pep8" tool.
 * GTK UI tests: Ensure that there are no GLib/GTK warnings or criticals.
 * Support Python 3. Everything except the launchpad crashdb backend now works
   with both Python 2 and 3. An important change is that the load(),
   write(), and write_mime() methods of a ProblemReport and apport.Report
   object now require the file stream to be opened in binary mode.
 * data/apport: Ignore a crash if the executable was modified after the process
   started. This often happens if the package is upgraded and a long-running
   process is not stopped before.
   ([LP: #984944](https://launchpad.net/bugs/984944))
 * Add test cases for apport-unpack.
 * apport-retrace: Add information about outdated packages to the
   "RetraceOutdatedPackages" field.
 * ui.py: Drop python-xdg dependency, use ConfigParser to read the .desktop
   files.

Bug fixes:
 * apport-gtk: Work around GTK crash when trying to set pixmap on an already
   destroyed parent window. ([LP: #938090](https://launchpad.net/bugs/938090))
 * data/dump_acpi_tables.py: Fix crash on undefined variable with non-standard
   tables. ([LP: #982267](https://launchpad.net/bugs/982267))
 * backends/packaging-apt-dpkg.py: Fix crash if a package is installed, but has
   no candidates in apt. ([LP: #980094](https://launchpad.net/bugs/980094))
 * data/general-hooks/generic.py: Bump minimum free space requirement from 10
   to 50 MB. 10 is not nearly enough particularly for /tmp.
   ([LP: #979928](https://launchpad.net/bugs/979928))
 * hookutils.py, recent_logfile(): Use a default limit of 10000 lines and call
   "tail" instead of reading the whole file. This protects against using up all
   memory when there are massive repeated log messages.
   ([LP: #984256](https://launchpad.net/bugs/984256))
 * apport-gtk: Do not assume that an icon requested for size 42 actually
   delivers size 42; some themes do not have this available and deliver a
   smaller one instead, causing overflows. Also, copy the image as
   gtk_icon_theme_load_icon() returns a readonly result which we must not
   modify. ([LP: #937249](https://launchpad.net/bugs/937249))
 * ui.py: Don't show the duplicate warning when the crash database does not
   accept the problem type, and they are just being sent to whoopsie. Thanks
   Evan Dandrea. ([LP: #989779](https://launchpad.net/bugs/989779))
 * report.py: Correctly escape the file path passed to gdb.
 * apport-gtk, apport-kde: Do not show the information collection progress
   dialog if the crash database does not accept this kind of report. In that
   case whoopsie will upload it in the background and the dialog is not
   necessary.  ([LP: #989698](https://launchpad.net/bugs/989698))

2.0.1 (2012-04-10)
------------------
Bug fixes:
 * test_ui_gtk.py: Disable package hooks for the tests, as they might ask for
   sudo passwords and other interactive bits, and thus make the tests hang.
 * test_backend_apt_dpkg.py: Fix checks for the installation of -dbgsym
   packages. This should always happen, as the sandboxes have a ddeb apt
   source. Only make it conditional on the system apt sources in the "use
   system config" test.
 * test_report.py: Sleep a bit after calling our test crash script, to ensure
   the kernel has time to finish writing the core file.
 * generic package hook: Also check /tmp for enough space. Thanks Brian Murray.
   ([LP: #972933](https://launchpad.net/bugs/972933))
 * problem_report.py, write_mime(): Fix regression from version 1.95: Add a
   value as attachment if it is bigger than 1000 bytes, not if it is bigger
   than 100. ([LP: #977882](https://launchpad.net/bugs/977882))

Improvements:
 * packaging-apt-dpkg.py: Avoid constructing and updating the apt.Cache()
   objects multiple times, to speed up retracing. Thanks Evan Dandrea.
   ([LP: #973494](https://launchpad.net/bugs/973494))

2.0 (2012-03-30)
----------------
This is the final 2.0 release, featuring the overhauled and simplified GUI,
support for whoopsie-daemon, and client-side duplicate checking.

Bug fixes:
 - report.py, anonymize(): Only replace whole words, not substrings.
   ([LP: #966562](https://launchpad.net/bugs/966562))
 - apport_python_hook.py: Fix filtering of org.freedesktop.DBus.Error.NoReply
   exceptions. ([LP: #958575](https://launchpad.net/bugs/958575))
 - crashdb.py: When publishing the crash database, cut hash file names after
   quoting, to avoid that the quoting causes them to become too long.
   ([LP: #968070](https://launchpad.net/bugs/968070)) This also uncovered that
   known() did not actually find any signature which contained an URL-quoted
   character, therefore breaking client-side duplicate checking in a lot of
   cases. Double-quote the file name now, as urlopen() unquotes it.
 - Add a new crash database option "problem_types" and a CrashDatabase method
   "accepts(report)". This can be used to stop uploading particular problem
   report types to that database. E. g. a distribution might decide to not get
   "Crash" reports any more after release.  Document the new option in
   doc/crashdb-conf.txt.
 - ui.py: Do not upload a report if the crash database does not accept the
   report's type. This behaviour is not really correct, but necessary as long
   as we only support a single crashdb and have whoopsie hardcoded.  Once we
   have multiple crash dbs, we need to not even present the data if none of the
   DBs wants the report. See [LP: #957177](https://launchpad.net/bugs/957177)
   for details. ([LP: #968121](https://launchpad.net/bugs/968121))
 - ui.py: Do not short-circuit information collection if report already has a
   "DistroRelease" field, as the GUIs add that in some cases. Check for
   "Dependencies" instead. This fixes information collection for kernel
   problems (which now has a full GTK GUI test case).
   ([LP: #968488](https://launchpad.net/bugs/968488))

1.95 (2012-03-22)
-----------------
Bug fixes:
 - ui.py: Ensure that the report file is readable by the crash reporting daemon
   after running through collect_info(). Thanks Evan Dandrea.
 - apport-gtk, apport-kde: Set the window title to the distribution name, as
   per http://wiki.ubuntu.com/ErrorTracker#error . Thanks Evan Dandrea.
   ([LP: #948015](https://launchpad.net/bugs/948015))
 - test/run: Ignore obsolete packages on the system, to avoid breaking the GUI
   tests due to them.
 - apport-gtk, apport-kde: When reporting a "system crash", don't say "... of
   this program version", but "...of this type", as we don't show a program
   version in the initial dialog (https://wiki.ubuntu.com/ErrorTracker#error)
   ([LP: #961065](https://launchpad.net/bugs/961065))
 - problem_report.py, write_mime(): Do not put a key inline if it is bigger
   than 1 kB, to guard against very long lines.
   ([LP: #957326](https://launchpad.net/bugs/957326))
 - etc/cron.daily/apport: Do not remove whoopsie's *.upload* stamps every day,
   only if they are older than a week. whoopsie comes with its own cron job
   which deals with them. Thanks Steve Langasek.
   ([LP: #957102](https://launchpad.net/bugs/957102))
 - report.py, mark_ignore(): Fix crash if executable went away underneath us.
   ([LP: #961410](https://launchpad.net/bugs/961410))
 - apport-gtk: Do not compare current continue button label against a
   translated string.  Instead just remember whether or not we can restart the
   application. ([LP: #960439](https://launchpad.net/bugs/960439))
 - hookutils.py, command_output(): Add option to keep the locale instead of
   disabling it.
 - hookutils.py, command_output(): Actually make the "input" parameter work,
   instead of causing an eternal hang. Add tests for all possible modes of
   operation.
 - hooktuils.py: Change root_command_output() and attach_root_command_outputs()
   to disable translated messages (LC_MESSAGES=C) only as part of the command
   to be run, not already for the root prefix command. This will keep the
   latter (gksu, kdesudo, etc.) translated.
   ([LP: #961659](https://launchpad.net/bugs/961659))
 - apport-gtk: Cut off text values after 4000 characters, as Gtk's TreeView
   does not get along well with huge values. KDE's copes fine, so continue to
   display the complete value there.
   ([LP: #957062](https://launchpad.net/bugs/957062))
 - apport-gtk: Make details window resizable in bug reporting mode.
 - crashdb.py, known(): Check the address signature duplicate database if the
   symbolic signature exists, but did not find any result.
   ([LP: #103083](https://launchpad.net/bugs/103083))
 - ui.py: Run anonymization after checking for duplicates, to prevent host or
   user names which look like hex numbers to corrupt the stack trace.
   ([LP: #953104](https://launchpad.net/bugs/953104))
 - apport-gtk: Require an application to both have TERM and SHELL in its
   environment to consider it a command line application that was started by
   the user. ([LP: #962130](https://launchpad.net/bugs/962130))
 - backends/packaging-apt-dpkg.py, _check_files_md5(): Fix double encoding,
   which caused UnicodeDecodeErrors on non-ASCII characters in an md5sum file.
   ([LP: #953682](https://launchpad.net/bugs/953682))
 - apport-kde, apport-gtk: Only show "Relaunch" if the report has a
   ProcCmdline, otherwise we cannot restart it.
   ([LP: #956173](https://launchpad.net/bugs/956173))

Improvements:
 - hookutils.py, attach_alsa(): Add the full "pacmd list" output instead of
   just sinks and sources. Thanks David Henningsson.
 - apport-gtk, apport-kde: Show the ExecutablePath while we're collecting data
   for the crash report. Thanks Evan Dandrea.
   ([LP: #938707](https://launchpad.net/bugs/938707)).

1.94.1 (2012-03-07)
-------------------
Bug fixes:
 - test_ui_kde.py: Re-enable inadvertently disabled "bug report for uninstalled
   package" test.
 - ui.py, collect_info(): Do not assume that reports have a "ProblemType"
   field. This is not the case when updating a bug.
   ([LP: #947519](https://launchpad.net/bugs/947519))
 - apport-cli: Consistently handle unicode vs. byte arrays.
   ([LP: #946207](https://launchpad.net/bugs/946207))
 - report.py, anonymize(): Fix crash when the hostname or user name contain
   non-ASCII characters. ([LP: #945230](https://launchpad.net/bugs/945230))
 - packaging-apt-dpkg.py: Fix UnicodeDecodeError on unexpected md5sum output.
   ([LP: #921037](https://launchpad.net/bugs/921037))
 - apport-gtk: Fix handling of non-ASCII strings in message dialogs.
   ([LP: #865394](https://launchpad.net/bugs/865394))

1.94 (2012-03-02)
-----------------
Bug fixes:
 - apport: Set the group of written reports to "whoopsie" if that group exists.
 - Fix tests to run properly against the system-installed modules and binaries.
 - test/run: Run under LC_MESSAGES=C to avoid test failures due to translated
   strings.
 - general-hooks/generic.py: Also attach xsession-errors for programs that link
   to libgtk-3.
 - launchpad.py: Properly handle "Expired" status, to avoid marking new bugs as
   duplicates of expired ones.
   ([LP: #941854](https://launchpad.net/bugs/941854))
 - apport: Fix crash if the "whoopsie" group does not exist.
   ([LP: #942326](https://launchpad.net/bugs/942326))
 - report.py, crash_signature(): Do not put "<module>" frames into Python crash
   signatures that happen outside of function/method calls. Fall back to the
   file/line number as a frame description instead. This will do a much better
   job at disambiguating e. g. different ImportError crashes.
   ([LP: #920403](https://launchpad.net/bugs/920403))
 - Make "binary changed since the time of the crash" error message more
   comprehensible, thanks Paolo Rotolo.
   ([LP: #942830](https://launchpad.net/bugs/942830))
 - crashdb.py, check_duplicate(): It can happen that a bug gets identified as
   being a duplicate of bug S by symbolic signatures and a duplicate of bug A
   by address signatures. Empirical evidence shows that this is due to the
   unavoidable jitter in stack traces (A and S not being identified as
   duplicates as their signatures differ slightly) and not a logic error. So
   instead of erroring out, duplicate all three bugs and keep the lowest number
   as the master ID. ([LP: #943117](https://launchpad.net/bugs/943117))
 - Revert the usage of multiple nested threads during data collection, and
   switch back to only using one UI thread. The UI implementations can, and now
   do, decide between showing a spinner and showing a progress dialog in the
   ui_*_info_collection_progress() methods. This fixes libX11 crashes when
   multiple UI threads do changes concurrently
   ([LP: #901675](https://launchpad.net/bugs/901675)), and also avoids
   multi-thread induced crashes in Pango
   ([LP: #943661](https://launchpad.net/bugs/943661)). The removal of the
   collect() method also fixes the new crashes in it.
   ([LP: #942098](https://launchpad.net/bugs/942098),
   [#939803](https://launchpad.net/bugs/939803))
 - ui.py, get_desktop_entry(): Fix crash on uninstalled package.
   ([LP: #940984](https://launchpad.net/bugs/940984))
 - data/unkillable_shutdown: Fix crash on race condition when PID goes away
   while the report is created.
   ([LP: #546369](https://launchpad.net/bugs/546369))
 - apport/hookutils.py, pci_devices(): Fix crash on unexpected lines from
   lspci. ([LP: #904489](https://launchpad.net/bugs/904489))
 - Drop hardcoded "Ubuntu" words again which crept in with the whoopsie support
   merge. Use the DistroRelease: field.
 - apport-kde: Fix Home page URL in KApplication metadata.
 - apport-gtk: Fix resizability and size after hiding details.
   ([LP: #405418](https://launchpad.net/bugs/405418))

Improvements:
 - test/run: Drop "local" argument. This now tests against the source tree when
   run in the source tree root, and against the system libraries/programs when
   run from anywhere else.
 - test/run: Consider command line arguments as test names and only run those
   when given. Also support just running a single test.
 - testsuite: Force the skipping of online tests when $SKIP_ONLINE_TESTS is
   set.
 - hookutils.py, xsession_errors(): Add a reasonable default pattern which
   matches glib-style warnings, errors, criticals etc. and X window errors.
   In data/general-hooks/generic.py, call it with that default instead of the
   rather incomplete custom pattern.
   ([LP: #932660](https://launchpad.net/bugs/932660))
 - packaging.py: Add get_package_origin() method, and implement it for
   apt-dpkg.
 - report.py, add_package_info(): Add "[origin: ...]" tag to "Package" and
   "Dependencies" fields for any package which is not native to the
   distribution. If any such package is present, tag the report with
   "third-party-packages" in data/general-hooks/generic.py.
   ([LP: #927912](https://launchpad.net/bugs/927912))
 - apport/packaging.py: Add get_uninstalled_package() method as a helper method
   for the test suite. Use it instead of a hardcoded Debian/Ubuntu specific
   name in test/test_hooks.py.
 - test/test_ui_{gtk,kde}.py: Add test cases for complete UI workflow runs for
   reporting a bug against an installed/uninstalled package, and reporting a
   crash with and without showing details. This reproduces the recent crashes
   like [LP: #901675](https://launchpad.net/bugs/901675) or
   [LP: #943661](https://launchpad.net/bugs/943661).
 - test_ui.py: Add a test case for reporting a complete report on uninstalled
   package. This happens when reporting a problem from a different machine
   through copying a .crash file.
 - test/run: Add a test that there are no hardcoded "Ubuntu" words in the
   source. The code should use the DistroRelease: field or lsb_release.

1.93 (2012-02-23):
------------------
Bug fixes:
 - apport-gtk: Fix crash on nonexisting icon. Thanks Evan Dandrea.
   ([LP: #937354](https://launchpad.net/bugs/937354))
 - ui.py, open_url(): Revert back to calling sudo instead of dropping
   privileges ourselves; with the latter, calling firefox as the sudo'ing user
   fails. ([LP: #916810](https://launchpad.net/bugs/916810), #938128)
 - ui.py: Fix aborting with "AssertionError" if the report is already known,
   but without an URL. ([LP: #938778](https://launchpad.net/bugs/938778))
 - launchpad.py: If a bug is already known, but the report is private, do not
   send the report. There is little sense piling up lots of duplicates.
   ([LP: #938700](https://launchpad.net/bugs/938700))
 - test/crash: Fix regression of test_crash_apport(), consider $TERM a
   non-sensitive variable.
 - ui.py: Fix test failures for data collection progress, they are not expected
   to happen for "ProblemType: Crash" any more (happens in the background
   during sending, or if user clicks on "Show Details").
 - test/hooks: Use a package from Debian/Ubuntu main, so that this works better
   during package builds on build servers.
 - test/python: Do not assume that /var/crash/ exists. Use /var/tmp/ for the
   fake binaries instead.
 - data/general-hooks/parse_segv.py: Fix test case name.
 - ui.py: Fix crash on invalid core dumps.
   ([LP: #937215](https://launchpad.net/bugs/937215))
 - launchpad.py: Fix crash on unicode report titles.
   ([LP: #896626](https://launchpad.net/bugs/896626))

Improvements:
 - apport-gtk: Show the most interesting fields first in the details view.
 - do-release: Call pyflakes and abort on errors other than unused imports.
 - Move all test suites out of the code modules into test/test_<module>.py.
   This avoids having to load it every time the program runs, and also allows
   running the tests against the installed version of Apport.
 - Clean up the other executable test script in test/* and change them to the
   same structure as the module tests.

1.92 (2012-02-20):
------------------
Bug fixes:
 - ui.py: Fix wrong creation of "~" folder instead of expanding it to home
   directory when using "Examine locally". Thanks Jason Conti!
   ([LP: #909149](https://launchpad.net/bugs/909149))
 - Replace file() calls with open() for Python 3 compatibility. Thanks Colin
   Watson!
 - launchpad.py: Avoid sending tag names with upper case.
   ([LP: #924181](https://launchpad.net/bugs/924181))
 - report.py, crash_signature_addresses(): Fix crash if report does not have
   "Signal".
 - apport-gtk: Fix resize handling of expander in details window. Thanks Thomas
   Bechtold! ([LP: #930562](https://launchpad.net/bugs/930562))
 - Clean up unnecessary imports. Thanks Evan Dandrea!

Improvements:
 - man/apport-bug.1: Mention where crash files are stored. Thanks David
   Kastrup.
 - hookutils.py, attach_hardware(): Sort ProcModules, thanks Brian Murray.
 - launchpad.py: Keep "Dependencies" attachment in duplicates. Thanks Brian
   Murray.
 - Reorganize the GNOME and KDE user interface to do the crash notifications
   and detail browser in a single dialog. Add test/gtk and test/kde tests to
   check expected dialog layout for different cases. Thanks Evan Dandrea!
 - Add support for the whoopsie-daisy crash reporting daemon by creating
   zero-byte .upload file stamps for crash reports. Thanks Evan Dandrea!

1.91 (2012-01-18):
------------------
Bug fixes:
 - crashdb.py, check_duplicate(): If a crash has a signature but no existing
   duplicate in the DB, also check for an existing address signature duplicate
   in the DB.
 - apport-retrace: Use DistroRelease specific subdirectory of the cache dir for
   mapping a file to a package, as these maps are release specific.
 - packaging-apt-dpkg.py: Refresh Contents.gz cache if it is older than one
   day.
 - crashdb.py: Ensure that address_signature duplicate db table does not have
   multiple identical signatures by making it a primary key. Bump the db format
   to "3". Existing databases need to be migrated manually as SQLite does not
   allow adding a "PRIMARY KEY" constraint to existing tables.
 - crashdb.py: Do not add a new address signature entry if one already exists.
 - apport-cli: Fix UnicodeDecodeError on unicode report values.
   ([LP: #275972](https://launchpad.net/bugs/275972))
 - launchpad.py: Only set bug task importance if it is undecided.
 - apport-retrace: Fix "an useful" typo.
   ([LP: #911437](https://launchpad.net/bugs/911437))
 - report.py: Filter out frames which are internal kernel/glibc implementation
   details and not stable across duplicates. In particular, filter out
   __kernel-syscall() and the SSE stubs.
 - crashdb.py: Remove debugging leftover which completely disabled bug pattern
   checking.
 - report.py: Update reading AssertionMessage. Current (e)glibc turned
   __abort_msg from a simple static string into a struct.

Improvements:
 - Change permissions of .crash files from 0600 to 0640, so that /var/crash can
   be made g+s and crash handling daemons can access those.
 - Python exceptions: Blacklist DBus.Error.NoReply. It does not help to get
   these traces from the client-side application, you need the actual exception
   in the D-Bus server backend instead.
   ([LP: #914220](https://launchpad.net/bugs/914220))
 - Support /etc/apport/whitelist.d/ similarly to /etc/apport/blacklist.d/, for
   cases like installer environments where only crashes of a few selected
   programs should be reported.

1.90 (2011-11-24):
------------------
First beta release of 2.0 which introduces client-side duplicate checking.

Bug fixes:
 - backends/packaging-apt-dpkg.py: Fix another test case failure when ddeb
   repository is not enabled.
 - backends/packaging-apt-dpkg.py: Fix handling of explicit cache directory
   name when it is a relative path.
 - launchpad.py: Only query for bugs after 2011-08-01, to avoid timeouts.
 - ui.py: Also anonymize standard bug title.
   ([LP: #893863](https://launchpad.net/bugs/893863))
 - launchpad.py: Current Launchpad cannot have private bugs which affect
   multiple projects. Fix test suite accordingly.

Improvements:
 - report.py: Break out new method stacktrace_top_function() from
   standard_title(), so that other parts of the code can use this as well.
 - launchpad.net: When sending retraced results back to the bug report, update
   the topmost function in the bug title.
   ([LP: #869970](https://launchpad.net/bugs/869970))
 - report.py, add_gdb_info(): Add a new field "StacktraceAddressSignature"
   which is a heuristic signature for signal crashes. This should be used if
   crash_signature() fails, i. e. the Stacktrace field does not have enough
   symbols. This can be used to check for duplicates on the client side,
   provided that the crash database server supports querying for these.
   Do not expose this field when uploading to crash databases though, as it can
   be recomputed from the already existing information (ProcMaps and
   Stacktrace) and thus would just clutter the reports.
 - crashdb.py: Add a table "version" with the database format version. Add
   automatic upgrading to the most current format.
 - crashdb.py: Put address signatures from reports checked with
   check_duplicate() into the duplicate database, so that implementations of
   known() can check for these.
 - dupdb-admin: Add "publish" dupdb-admin command which exports the
   duplicate database into a set of text files suitable for WWW publishing.
 - crashdb.py: Add new method "known(report)" which can be implemented to check
   if the crash db already knows about the crash signature. If so, the report
   will not be uploaded, and instead the user will be directed to the existing
   report URL (if available), similar to bug patterns. The default
   implementation checks this format, if the crash database is initialized with
   a "dupdb_url" option pointing to the exported database.
 - launchpad.py: Override known() to check if the master bug is actually
   accessible by the reporter, and is not tagged with "apport-failed-retrace"
   or "apport-request-retrace"; otherwise file it anyway.
 - crash-digger: Add --publish-db option to conveniently integrate duplicate DB
   publication (similar to dupdb-admin publish) into retracer setups.
 - launchpad.py: Attach updated stack traces from a duplicate to the master bug
   if it failed retracing previously or has an "apport-request-retrace" tag.
   ([LP: #869982](https://launchpad.net/bugs/869982))
 - apport-kde, apport-gtk: Support the "Annotation" field for custom dialog
   titles for "Crash" and "Package" problem types as well, not just for
   "Kernel". ([LP: #664378](https://launchpad.net/bugs/664378))

1.26 (2011-11-11):
------------------
Bug fixes:
 - backends/packaging-apt-dpkg.py: Port to current python-apt API.
 - hookutils.py: Fix path_to_key() to also work with unicode arguments.
 - test/crash: Exit successfully if apport is not enabled in the system. This
   allows packages to run the test suite during build.
 - report.py, add_proc_info(): Correctly handle "python -m <modulename>"
   programs as being interpreted and determine the appropriate module path.
 - Fix some import statements to also work for the system-installed test suite.
 - test/run: Fix testing data/general-hooks/parse_segv.py when called in
   system-installed mode.
 - apport/ui.py: Clean up test .crash file after test cases.
 - Fix tests when running as root.
 - setup.py: Fix crash when "javac -version" fails.
 - README: Update command for one-time enablement.
 - backends/packaging-apt-dpkg.py: Fix interleaving usage of install_packages()
   with other operations such as get_version(), by resetting the apt status
   after building and using the sandbox.
 - report.py test suite: Remove requirement that $USER is set, which makes it
   easier to run this from package build environments.
 - apport/ui.py, test/crash: Use "yes" as test process instead of "cat". The
   former is less likely to run already, and does not depend on having a stdin,
   so it runs better in test environments like autopkgtest.
 - backends/packaging-apt-dpkg.py: Fix tests if system does not have a dbgsym
   apt source.

Improvements:
 - Ignore a crash if gnome-session is running and says that the session is
   being shut down. These often die because X.org or other services are going
   away, are usually harmless, and just cause a lot of clutter in bug trackers.
   ([LP: #460932](https://launchpad.net/bugs/460932))
 - test/crash: Rewrite using Python's unittest, to be in line with other tests,
   and be easier to maintain and extend.

1.25 (2011-11-02):
------------------
Improvements:
 - Add new response "Examine locally" to presenting the report details, which
   runs apport-retrace in the chosen mode in a terminal. This should be made
   available for crash reports if apport-retrace and a Terminal application are
   installed; add an abstrace UI method for this.
   ([LP: #75901](https://launchpad.net/bugs/75901))
 - apport-gtk: Add "Examine locally..." button, and implement
   ui_run_terminal().
 - apport-cli: Add "Examine locally..." responses, and implement
   ui_run_terminal().
 - apport-cli: Greatly speed up displaying large reports. This also changes the
   format to avoid indenting each line with a space, and visually set apart the
   keys in a better way.
 - apport_python_hook.py: Move tests out of this file into test/python, to
   avoid having to parse the unit tests at each Python startup.
 - test/python: Also make tests work if Python hook is not installed in
   system's sitecustomize.py.
 - packaging.py: Add get_modified_conffiles() API, and implement it in
   packaging-apt-dpkg.py.
 - hookutils.py: Add attach_conffiles().
 - hookutils.py: Add attach_upstart_overrides().

Bug fixes: 
 - launchpad.py: Remove "Ubuntu" in bug response, replace with "this software".
   ([LP: #883234](https://launchpad.net/bugs/883234))
 - apport-kde: Rearrange order of imports to get intended error message if
   PyKDE is not installed.
 - packaging-apt-dpkg.py: Ignore hardening-wrapper diversions, to make
   gcc_ice_hook work if hardening-wrapper is installed.
 - apport_python_hook: Respect $APPORT_REPORT_DIR.
 - apport_python_hook: Limit successive crashes per program and user to 3 per
   day, just like signal crashes.
   ([LP: #603503](https://launchpad.net/bugs/603503))
 - packaging-apt-dpkg.py: Skip online tests when there is no default route.
 - ui.py: Fix test suite to not fail if system has some obsolete or non-distro
   packages.

1.24 (2011-10-19):
------------------
Bug fixes:
 - backends/packaging-apt-dpkg.py, install_packages(): Also copy
   apt/sources.list.d/ into sandbox.
 - backends/packaging-apt-dpkg.py, install_packages(): Install apt keyrings
   from config dir or from system into sandbox.
   ([LP: #856216](https://launchpad.net/bugs/856216))
 - packaging.py, backends/packaging-apt-dpkg.py: Define that install_packages()
   should return a SystemError for broken configs/unreachable servers etc., and
   fix the apt/dpkg implementation accordingly.
 - apport-retrace: Don't crash, just give a proper error message if servers are
   unreachable, or configuration files are broken.
   ([LP: #859248](https://launchpad.net/bugs/859248))
 - backends/packaging-apt-dpkg.py: Fix crash when /etc/apport/native-origins.d
   contains any files. ([LP: #865199](https://launchpad.net/bugs/865199))
 - hookutils, recent_logfile(): Fix invalid return value if log file is not
   readable. ([LP: #819357](https://launchpad.net/bugs/819357))
 - test/crash: Fix race condition in the "second instance terminates
   immediately" check.
 - hookutils.py: Replace attach_gconf() with a no-op stub. It used static
   python modules like "gconf" which broke the PyGI GTK user interface, and
   gconf is rather obsolete these days.
 - ui.py, open_url(): Greatly simply and robustify by just using xdg-open. This
   already does the right thing wrt. reading the default browser from GNOME,
   KDE, XCE, and other desktops.
   ([LP: #198449](https://launchpad.net/bugs/198449))
 - data/general-hooks/generic.py: Only attach ~/.xsession_errors if the bug is
   reported in the same XDG session as the crash happened.
   ([LP: #869974](https://launchpad.net/bugs/869974))
 - Ignore crashes for programs which got updated in between the crash and
   reporting. ([LP: #132904](https://launchpad.net/bugs/132904))
 - Special-case crashes of 'twistd': Try to determine the client program and
   assign the report to that, or fail with an UnreportableReason.
   ([LP: #755025](https://launchpad.net/bugs/755025))
 - apport-gtk: In bug update mode, make details dialog resizable and fix
   default size. ([LP: #865754](https://launchpad.net/bugs/865754))
 - apport-gtk: Fix crash if report does not have ProcCmdline.
   ([LP: #854452](https://launchpad.net/bugs/854452))
 - hookutils.py, attach_wifi(): Anonymize ESSID and AP MAC from "iwconfig"
   output. ([LP: #746900](https://launchpad.net/bugs/746900))
 - test/crash: Fix test failure if user is not in any system groups.
 - test/crash: Change to /tmp/ for test crash process, to fix failure if the
   user that runs the test suite cannot write into the current directory.
   ([LP: #868695](https://launchpad.net/bugs/868695))
 - ui.py: Improve error message if package is not a genuine distro package.
   Thanks to Ronan Jouchet. ([LP: #559345](https://launchpad.net/bugs/559345))

Improvements:
 - apport-retrace: Add --timestamp option to prepend a timestamp to log
   messages. This is useful for batch operations.
 - crash-digger: Call apport-retrace with --timestamps, to get consistent
   timestamps in log output.
 - hookutils.py: Add two new functions attach_gsettings_package() and
   attach_gsettings_schema() for adding user-modified gsettings keys to a
   report. ([LP: #836489](https://launchpad.net/bugs/836489))
 - hookutils.py: Add new function in_session_of_problem() which returns whether
   the given report happened in the currently running XDG session. This can be
   used to determine if e. g. ~/.xsession-errors is relevant and should be
   attached.

1.23.1 (2011-09-29)
-------------------
Bug fixes:
 - apport/crashdb.py: Ensure that duplicate table only has one entry per report
   ID.
 - apport-retrace: Pass correct executable path to gdb in --gdb with --sandbox
   mode.
 - apport-retrace: Do not leave behind temporary directories on errors.
 - apport-retrace: Drop assertion failure for existance of "Stacktrace". This
   isn't present in the case of gdb crashing, and there is not much we can do
   about it. This should not break the retracer.
 - apport/report.py: Unwind XError() from stack traces for the "StacktraceTop"
   field, as they take a significant part of the trace. This causes bugs to be
   duplicated which really have different causes.

1.23 (2011-09-14)
-----------------
Improvements:
 - crashdb.py, crash-digger, dupdb-admin: Drop the concept of "duplicate DB
   consolidation". Such massive queries cause timeouts with e. g. Launchpad.
   Instead, update the status of potential master bugs in the crash DB whenever
   check_duplicate() is called.

Bug fixes:
 - launchpad.py: Fix crash in close_duplicate() if master bug was already
   marked as a duplicate of the examined bug.
 - problem_report.py, load(): Fix missing last character if the last line in a
   multi-line field is not terminated with a newline.
 - launchpad.py: Fix test_marking_python_task_mangle() check to work with
   current Launchpad.
 - apport-retrace: If the user did not specify a --cache directory, create a
   shared one instead of letting the two install_packages() calls create their
   own. This ensures that the apt and dpkg status is up to date, and avoids
   downloading the package indexes multiple times.
   ([LP: #847951](https://launchpad.net/bugs/847951))
 - apport-retrace: Give proper error mesage instead of AssertionError crash if
   a report does not contain standard Apport format data.
   ([LP: #843221](https://launchpad.net/bugs/843221))
 - fileutils.py, get_new_reports(): Fix crash if report file disappears in the
   middle of the operation. ([LP: #640216](https://launchpad.net/bugs/640216))
 - apport/ui.py, load_report(): Intercept another case of broken report files.
   ([LP: #445142](https://launchpad.net/bugs/445142))
 - apport/report.py, standard_title(): Escape regular expression control
   characters in custom exception names.
   ([LP: #762998](https://launchpad.net/bugs/762998))

1.22.1 (2011-09-06)
-------------------
Improvements:
 - dupdb-admin: Add "removeid" command.

Bug fixes:
 - dupdb-admin: Use the in-memory CrashDB implementation for simple operations
   like dump or changeid, which do not require an actual backend. This makes
   the command work in checkouts without a /etc/apport/crashdb.conf.
 - dupdb-admin: Fix UnicodeEncodeError crash.
 - launchpad.py: Fix crash if a crash report does not have a DistroRelease.
 - Set the default "Apport" title for choice dialogs instead of the default
   apport-gtk title. Thanks Robert Roth.
   ([LP: #608222](https://launchpad.net/bugs/608222))
 - apport-gtk: Update markup_escape_text() call to current glib.
   ([LP: #829635](https://launchpad.net/bugs/829635))

1.22 (2011-08-25)
-----------------
Improvements:
 - Completely rework apport-retrace to use gdb's "debug-file-directory" and
   "solib-absolute-prefix" settings and only unpack the necessary packages in a
   temporary directory. This makes it possible to use it in a running system
   without actually touching installed packages, does not need any root
   privileges, and stops the requirement of using chroots with fakechroot and
   fakeroot. This is a lot easier to maintain and use, and a lot faster, too.
   As a consequence, drop the chroot module, and update crash-digger
   accordingly. See "man apport-retrace" for the new usage.
   It is now also easier to port to other packaging backends, as a lot of the
   common logic moved out of the packaging API;
   packaging.install_retracing_packages() got dropped in favor of the simpler
   packaging.install_packages().
 - crash-digger: Show how many bugs are left in the pool with each new retrace.

Bug fixes:
 - apport-gtk: Fix crash in GLib.markup_escape_text() call, regression from
   1.21.3. ([LP: #828010](https://launchpad.net/bugs/828010))
 - launchpad.py: When searchTasks() times out, exit with 99 as this is a
   transient error.
 - crash-digger: Intercept OverflowError from downloaded compressed
   attachments.

1.21.3 (2011-08-17)
-------------------
Bug fixes:
 - gtk/apport-gtk.desktop.in: Also show in Unity.
   ([LP: #803519](https://launchpad.net/bugs/803519))
 - apport-unpack: Fix crash on file errors.
 - Add apport.packaging.get_library_paths() interface and implement it for
   backends/packaging-apt-dpkg.py using dpkg multiarch directories. Use it in
   chroot.py.
 - hookutils.py: Don't attach empty values. Thanks Bryce Harrington.
   ([LP: #813798](https://launchpad.net/bugs/813798))
 - apport-gtk: Correctly pass message dialog type.
 - apport-gtk: Fix GLib and GObject imports to be compatible with the future
   pygobject 3.0.

Improvements:
 - hookutils.py: Add attach_mac_events() for reporting logs of MAC systems.
   Looks for AppArmor messages for now. Thanks Marc Deslauriers!
 - hookutils.py, attach_alsa(): Get a list of outputs/inputs that PulseAudio
   knows about, which also shows the currently selected output/input, as well
   as volumes. This should help with "no sound" bug troubleshooting. Thanks
   Luke Yelavich.

1.21.2 (2011-07-01)
-------------------
Improvements:
 - test/run: Check $PYTHON for using a different Python interpreter (such as
   "python3") for the tests.
 - generic hook: Don't report package installation failures due to segfaulting
   maintainer scripts. We want the actual crash report only. Thanks Brian
   Murray.
 - hookutils.py, attach_wifi(): Also include wpasupplicant logs. Thanks Mathieu
   Trudel-Lapierre!

Bug fixes:
 - backends/packaging-apt-dpkg.py: Fix crash introduced in 1.21.1's multiarch
   fixes.
 - report.py: Fix bug patterns to correctly match against compressed report
   fields.

1.21.1 (2011-06-20)
-------------------
Improvements:
 - data/general-hooks/generic.py: Also check for low space on /var. Thanks
   Brian Murray.
 - hookutils.py, attach_file() and attach_file_if_exists(): Add a new
   "overwrite" flag option. If not given, now default to overwriting an
   existing key, as this is usually what you need when attaching files
   (instead of attaching it several times with '_' appended to the keys). You
   can get the old behaviour by setting overwrite=False.

Bug fixes:
 - When showing the size of the full report, take the compressed size of binary
   values instead of their uncompressed size, as the crash db upload will use
   the compressed values.
 - backends/packaging-apt-dpkg.py: Fix for current dpkg with multiarch support.
 - test/run: Fix the test suite to run against the system installed libraries
   with current Python versions (2.6, 2.7) where __file__ does not work any
   more with imports.

1.21 (2011-06-08)
-----------------
Improvements:
 - Supply --desktop option to kdesudo to improve the description which program
   is requesting administrative privileges.
 - apport-checkreports: Exit with status 2 if there are new reports, but apport
   is disabled. This helps crash notification GUIs to not display new crash
   reports in that case. Thanks to Michael Vogt for the original patch.
 - Add data/is-enabled: Shell script to check if apport is enabled. Non-Python
   programs (which can't use apport.packaging.enabled() ) can call this instead
   of having to parse /etc/default/apport themselves, and just check the exit
   code. Inspired by original patch from Michael Vogt, thanks!

Bug fixes:
 - apport-gtk: HTML-escape text for dialogs with URLs.
   ([LP: #750870](https://launchpad.net/bugs/750870))
 - dump_acpi_tables.py: Check to see if acpi/tables dir is mounted first.
   Thanks Brian Murray. ([LP: #729622](https://launchpad.net/bugs/729622))
 - man/apport-cli.1: Document recently added -w/--window option. Thanks Abhinav
   Upadhyay! ([LP: #765600](https://launchpad.net/bugs/765600))
 - Use kde-open instead of kfmclient to open URLs under KDE. Thanks Philip
   Muškovac. ([LP: #765808](https://launchpad.net/bugs/765808))

1.20.1 (2011-03-31)
-------------------
Bug fixes:
 - Add bash completion support for new -w/--window option that was introduced
   in 1.20. Thanks Philip Muškovac.
 - apport-unpack: Fix crash if target directory already exists.
 - Fix crash if UnreportableReason is a non-ASCII string.
   ([LP: #738632](https://launchpad.net/bugs/738632))
 - Fix crash if application from desktop name is a non-ASCII string.
   ([LP: #737799](https://launchpad.net/bugs/737799))
 - unkillable_shutdown: Fix rare crash if ExecutablePath does not exist (any
   more). ([LP: #537904](https://launchpad.net/bugs/537904))
 - kernel_crashdump: Fix crash if the vmcore file disappeared underneath us.
   ([LP: #450295](https://launchpad.net/bugs/450295))
 - unkillable_shutdown: Fix crash if the checked process terminated underneath
   us. ([LP: #540436](https://launchpad.net/bugs/540436))
 - ui.py: Properly raise exceptions from the upload thread that happen at its
   very end. ([LP: #469943](https://launchpad.net/bugs/469943))

1.20 (2011-03-17)
-----------------
Improvements:
 - Add support for -w/--window option which will enable user to select a
   window as a target for filing a problem report. Thanks Abhinav Upadhyay for
   the patch! ([LP: #357847](https://launchpad.net/bugs/357847))
 - Disable the filtering on SIGABRT without assertion messages. Turns out that
   developers want these crash reports after all.
   ([LP: #729223](https://launchpad.net/bugs/729223))
 - Add support for a "DuplicateSignature" report fields. This allows package
   hooks to implement custom duplicate problem handling which doesn't need to
   be hardcoded in Apport itself. Update the launchpad backend to tag such bugs
   as "need-duplicate-check".

Bug fixes:
 - report.py, add_hooks_info(): Properly report TypeErrors from hooks.
 - apport-retrace: Intercept SystemErrors from ill-formed gzip attachments as
   well.
 - Fix crash if crash database configuration does not specify a
   bug_pattern_url. Just assume None.
   ([LP: #731526](https://launchpad.net/bugs/731526))
 - If a custom crash database does not specify a bug_pattern_url, fall back to
   using the default database's.
   ([LP: #731526](https://launchpad.net/bugs/731526))
 - hookutils.py Update WifiSyslog regex to correctly catch application log
   messages in syslog. Thanks Mathieu Trudel-Lapierre.
   ([LP: #732917](https://launchpad.net/bugs/732917))
 - hookutils.py, attach_hardware(): Avoid error message if machine does not
   have a PCI bus. Thanks Marcin Juszkiewicz!
   ([LP: #608449](https://launchpad.net/bugs/608449))
 - backends/packaging-apt-dpkg.py: Replace deprecated getChanges() call with
   get_changes().
 - apport-gtk: Fix broken dialog heading if the name of the crashed program
   contains an & or other markup specific characters.
 - apport-gtk: Don't crash if GTK cannot be initialized. This usually happens
   without a $DISPLAY or when the session is being shut down. Just print an
   error message. If there are pending crashes, they will be shown again the
   next time a session starts.
   ([LP: #730569](https://launchpad.net/bugs/730569))

1.19 (2011-02-28)
-----------------
Bug fixes:
 - Update stack unwind patterns for current glib (slightly changed function
   names), and also ignore a preceding '*'.
   ([LP: #716251](https://launchpad.net/bugs/716251))
 - Fix crash_signature() to fail if there is an empty or too short
   StacktraceTop.
 - apt backend: Do not generate a warning if the opportunistically added -dbg
   package does not exist.
 - apt backend: Only add -dbg in --no-pkg mode, as there will be conflicts in
   normal package mode.
 - apt backend: Call tar with target cwd instead of using -C; the latter causes
   an extra openat() call which breaks with current fakechroot.
 - launchpad.py: Fix retracer crash if DistroRelease field does not exist.
 - Convert deprecated failIf()/assert_() TestCase method calls to
   assertFalse()/assertTrue().

Improvements:
 - In apport-bug, if the user specifies a PID referring to a kernel thread,
   do the right thing and file the bug against the kernel
 - In hookutils.attach_dmesg, skip over an initial truncated message if one
   is present (this happens when the ring buffer overflows)
 - Change bug patterns to just use one central file instead of per-package
   files. This allows bug patterns to be written which are not package
   specific, and is easier to maintain as well. IMPORTANT: This changed the
   format of crashdb.conf: bug_pattern_base is now obsolete, and the new
   attribute bug_pattern_url now points to the full URL/path of the patterns
   file. Thanks to Matt Zimmerman!

1.18 (2011-02-16)
-----------------
Bug fixes:
 - Ensure that symptom scripts define a run() function, and don't show them if
   not.
 - Do not show symptom scripts which start with an underscore. These can be
   used for private libraries for the actual symptom scripts.
 - Update bash completion. Thanks Philip Muškovac.
 - etc/default/apport: Remove obsolete "maxsize" setting.
   ([LP: #719564](https://launchpad.net/bugs/719564))

Improvements:
 - Remove explicit handling of KDE *.ui files in setup.py, as
   python-distutils-extra 2.24 fixes this. Bump version check.
 - hookutils.py: Add attach_root_command_outputs() to run several commands
   at once. This avoids asking for the password several times.
   ([LP: #716595](https://launchpad.net/bugs/716595))

1.17.2 (2011-02-04)
-------------------
Improvements:
 - Be more Python 3 compatible (not fully working with Python 3 yet, though).
 - apt/dpkg backend: Drop support for pre-0.7.9 python-apt API.
 - Add --tag option to add extra tags to reports.
   ([LP: #572504](https://launchpad.net/bugs/572504))

Bug fixes:
 - hookutils.py, attach_dmesg(): Do not overwrite already existing dmesg.
 - hookutils.py: Be more robust against file permission errors.
   ([LP: #444678](https://launchpad.net/bugs/444678))
 - ui.py: Do not show all the options in --help when invoked as *-bug.
   ([LP: #665953](https://launchpad.net/bugs/665953))
 - launchpad.py: Adapt test cases to current standard_title() behaviour.

1.17.1 (2011-01-10)
-------------------
Bug fixes:
 - Make the GTK frontend work with GTK 2.0 as well, and drop "3.0" requirement.

1.17 (2010-12-31)
-----------------
Improvements:
 - Better standard bug titles for Python crashes. Thanks Matt Zimmerman!
   ([LP: #681574](https://launchpad.net/bugs/681574))
 - Add handler for uncaught Java exceptions. There is no integration for
   automatically intercepting all Java crashes yet, see java/README.
   Thanks Matt Zimmerman! ([LP: #548877](https://launchpad.net/bugs/548877))

Bug fixes:
 - GTK frontend: Require GTK 3.0.
 - launchpad.py: Default to "production" instance, not "edge", since edge is
   obsolete now.
 - hookutils.py, attach_alsa(): Fix crash if /proc/asound/cards does not exist.
   ([LP: #626215](https://launchpad.net/bugs/626215))
 - ui.py, format_filesize(): Fix to work with stricter locale.format() in
   Python 2.7. ([LP: #688535](https://launchpad.net/bugs/688535)). While we are at it, also change it to use base-10
   units.
 - hookutils.py, package_versions(): Always include all requested package names
   even if they're unknown to us. Thanks Matt Zimmerman!
   ([LP: #695188](https://launchpad.net/bugs/695188))
 - launchpad.py: When updating a bug, also add new tags. Thanks Brian Murray!

1.16 (2010-11-19)
-----------------
New features:
 - Port GTK frontend from pygtk2 to GTK+3.0 and gobject-introspection.

Bug fixes:
 - Fix symptoms again. Version 1.15 broke the default symptom directory.
 - Fix memory test case to work with current Python versions, where the SQLite
   integrity check throws a different exception.

1.15 (2010-11-11)
-----------------
New features:
 - Add dump_acpi_tables.py script. This can be called by package hooks which
   need ACPI table information (in particular, kernel bug reports). Thanks to
   Brad Figg for the script!
 - Order symptom descriptions alphabetically. Thanks to Javier Collado.
 - Check $APPORT_SYMPTOMS_DIR environment variable for overriding the system
   default path. Thanks to Javier Collado.

Bug fixes:
 - testsuite: Check that crashdb.conf can have dynamic code to determine DB
   names and options.
 - ui.py test suite: Rewrite _gen_test_crash() to have the test process core
   dump itself, instead of using gdb to do it. The latter fails in ptrace
   restricted environments, such as Ubuntu 10.10.
 - packaging-apt-dpkg.py: Fix handling of /etc/apport/native-origins.d to
   actually work. Thanks Steve Langasek.
   ([LP: #627777](https://launchpad.net/bugs/627777))
 - apport-kde: Load correct translation catalogue. Thanks Jonathan Riddell.
   ([LP: #633483](https://launchpad.net/bugs/633483))
 - launchpad.py: Use launchpadlib to file a bug instead of screen scraping.
   The latter was completely broken with current Launchpad, so this makes the
   test suite actually work again. Thanks to Diogo Matsubara!
 - launchpad.py: Change $APPORT_STAGING to $APPORT_LAUNCHPAD_INSTANCE, so that
   you can now specify "staging", "edge", or "dev" (for a local
   http://launchpad.dev installation). Thanks to Diogo Matsubara!
 - backends/packaging-apt-dpkg.py: Fix crash on empty lines in ProcMaps
   attachment.
 - doc/symptoms.txt: Fix typo, thanks Philip Muskovac.
   ([LP: #590521](https://launchpad.net/bugs/590521))
 - apport/hookutils.py: rename ProcCmdLine to ProcKernelCmdLine to not wipe
   wipe out /proc/$pid/cmdline information.
   ([LP: #657091](https://launchpad.net/bugs/657091))
 - apport/hookutils.py: attach_file() will not overwrite existing report
   keys, instead appending "_" until the key is unique.
 - Fix --save option to recognise ~, thanks Philip Muškovac.
   ([LP: #657278](https://launchpad.net/bugs/657278))
 - Remove escalation_subscription from Ubuntu bug DB definition, turned out to
   not be useful; thanks Brian Murray.
 - launchpad.py: Fix APPORT_LAUNCHPAD_INSTANCE values with a https:// prefix.
 - apt backend: Opportunistically try to install a -dbg package in addition to
   -dbgsym, to increase the chance that at least one of it exists. Thanks
   Daniel J Blueman!

1.14.1 (2010-06-24)
-------------------
Bug fixes:
 - hookutils.py, attach_drm_info(): Sanitize connector names. Thanks Chris
   Halse Rogers! ([LP: #597558](https://launchpad.net/bugs/597558))
 - bash completion: Complete all path names, apport-bug can be invoked with a
   path to a program. Thanks Philip Muskovac.

1.14 (2010-06-16)
-----------------
New features:
 - hookutils.py: Add new method attach_drm_info() to read and format
   /sys/class/drm/*.

Bug fixes:
 - packaging-apt-dpkg.py: Fix deprecated python-apt variables, thanks David
   Stansby. ([LP: #591695](https://launchpad.net/bugs/591695))
 - launchpad.py: Fix crash on attachments which are named *.gz, but
   uncompressed. ([LP: #574360](https://launchpad.net/bugs/574360))
 - hookutils.py, attach_gconf(): Fix defaults parsing for boolean keys.
   ([LP: #583109](https://launchpad.net/bugs/583109))

1.13.4 (2010-05-04)
-------------------
 - bash completion: Fix error message if /usr/share/apport/symptoms does not
   exist. Thanks Philip Muškovac!
   ([LP: #562118](https://launchpad.net/bugs/562118))
 - general-hooks/parse_segv.py: Report stack exhaustion more clearly and
   correctly handle register dereferencing calls.
 - Save/restore environment when calling hooks, in case they change the locale,
   etc. ([LP: #564422](https://launchpad.net/bugs/564422))
 - hookutils.py, command_output(): Do not set $LC_MESSAGES for the calling
   process/hook, just for the command to be called.
 - ui.py: When displaying strings from system exceptions, decode them into an
   unicode string, to avoid crashing the KDE UI.
   ([LP: #567253](https://launchpad.net/bugs/567253))
 - apport-retrace: Fix crash for retracing kernel vmcores, which do not have an
   ExecutablePath.
 - apport-bug manpage: Clarify when apport-collect may be used. Thanks Brian
   Murray! ([LP: #537273](https://launchpad.net/bugs/537273))
 - generic hook: Check ProcMaps for unpackaged libraries, and ask the user if
   he really wants to continue. If he does, tag the report as "local-libs" and
   add a "LocalLibraries" field to the report with a list of them.
   ([LP: #545227](https://launchpad.net/bugs/545227))

1.13.3 (2010-04-14)
-------------------
 - data/general-hooks/parse_segv.py: suggest segv-in-kernel possibility.
 - ui.py: When running as root, only show system crash reports, to avoid
   restarting user programs as root.
   ([LP: #445017](https://launchpad.net/bugs/445017))

1.13.2 (2010-03-31)
-------------------
 - problem_report.py, write_mime(): Add new optional argument "priority_fields"
   for ordering report keys. Patch by Brian Murray, thanks!
 - launchpad.py: Put some interesting fields first in the report, with the new
   priority_fields argument. Patch by Brian Murray, thanks!
 - packaging-apt-dpkg.py, _install_debug_kernel(): Do not crash on an outdated
   kernel, just return that it is outdated.
   ([LP: #532923](https://launchpad.net/bugs/532923))
 - launchpad.py test suite: Add "Referer" HTTP header, now required by
   launchpad.
 - launchpad.py: Fix crash if configuration does not have an "escalated_tag"
   option.
 - launchpad.py: Port to launchpadlib 1.0 API, thanks Michael Bienia for the
   initial patch! ([LP: #545009](https://launchpad.net/bugs/545009))
 - gtk/apport-gtk-mime.desktop.in, kde/apport-kde-mime.desktop.in: Change
   categories so that these do not ever appear in menu editors.
   ([LP: #449215](https://launchpad.net/bugs/449215))
 - launchpad.py: Some LP bugs have broken attachments (this is a bug in
   Launchpad itself). Ignore those instead of crashing.
 - apport-gtk: Turn http:// and https:// links into clickable hyperlinks in
   information and error dialogs.
   ([LP: #516323](https://launchpad.net/bugs/516323))
 - apport-retrace: Fix crash when trying to rebuild package info for reports
   without an ExecutablePath. ([LP: #436157](https://launchpad.net/bugs/436157))
 - ui.py: Fix crash when package information cannot be determined due to broken
   apt status. ([LP: #362743](https://launchpad.net/bugs/362743))
 - ui.py: Fix crash when /etc/apport/crashdb.conf is damaged; print an
   appropriate error message instead.
   ([LP: #528327](https://launchpad.net/bugs/528327))
 - data/kernel_crashdump: Fix crash if log file disappeared underneath us.
   ([LP: #510327](https://launchpad.net/bugs/510327))
 - data/apport: Fix IOError when apport is called with invalid number of
   arguments, and stderr is not a valid fd.
   ([LP: #467363](https://launchpad.net/bugs/467363))
 - hookutils.py: Factor out the DMI collection code from attach_hardware()
   into attach_dmi(), and call that in attach_alsa() as well. Thanks to Brad
   Figg for the patch! ([LP: #552091](https://launchpad.net/bugs/552091))
 - apport/ui.py: Fix the help output if Apport is invoked under an alternative
   name (like apport-collect).
   ([LP: #539427](https://launchpad.net/bugs/539427))

1.13.1 (2010-03-20)
-------------------
Bug fixes:
 - Update parse-segv to handle gdb 7.1 output.
 - Enhance test suite to work with gdb 7.1 as well, and catch future outputs.
 - UI: Add exception string to the "network error" dialog, to better tell what
   the problem is.
 - UI: Add back -p option to apport-collect/apport-update-bug (regression from
   1.13). ([LP: #538944](https://launchpad.net/bugs/538944))
 - launchpad.py: Add yet another workaround for LP#336866.
   ([LP: #516381](https://launchpad.net/bugs/516381))
 - launchpad.py, download(): Ignore attachments with invalid key names.
 - Fix regression from 1.10 which made it impossible for a package hook to set
   a third-party crash database for non-native packages.
   ([LP: #517272](https://launchpad.net/bugs/517272))
 - apport-cli: Create the 'details' string only if user wants to view details,
   and do not show files larger than 1MB. Thanks Scott Moser!
   ([LP: #486122](https://launchpad.net/bugs/486122))
 - packaging-apt-dpkg.py: Silence apt.Cache() spewage to stdout with newer
   python-apt versions. ([LP: #531518](https://launchpad.net/bugs/531518))

Improvements:
 - unkillable_shutdown: Add list of running processes and omit PIDs to
   report. ([LP: #537262](https://launchpad.net/bugs/537262))
 - Sort the report by key in the details view.
   ([LP: #519416](https://launchpad.net/bugs/519416))

1.13 (2010-03-10)
-----------------
New features:
 - Add "unkillable_shutdown" script to collect information about processes
   which are still running after sending SIGTERM to them. This can be hooked
   into e. g. /etc/init.d/sendsigs on Debian/Ubuntu systems.

Improvements:
 - apport_python_hook.py: Directly check /etc/default/apport instead of
   querying packaging.enabled(), to avoid importing lots of modules for
   non-packaged scripts. Thanks Stuart Colville!
   ([LP: #528355](https://launchpad.net/bugs/528355))

Bug fixes:
 - Fix SegV parser to notice walking off the stack during "call" or "ret"
   ([LP: #531672](https://launchpad.net/bugs/531672)).
 - Fix --help output for bug updating mode (invocation as apport-collect or
   apport-update-bug). ([LP: #504116](https://launchpad.net/bugs/504116))
 - Fix bug escalation tagging, thanks to Brian Murray.
 - Fix option processing when being invoked as apport-bug. Thanks to Daniel
   Hahler for the patch! ([LP: #532944](https://launchpad.net/bugs/532944))

1.12.1 (2010-02-22)
-------------------
Bug fixes:
 - launchpad.py: Do not keep escalating bugs, just escalate at the 10th
   duplicate.
 - Improve error message if a symptom script did not determine a package name.
   ([LP: #503834](https://launchpad.net/bugs/503834))
 - general-hooks/generic.py: Fix crash on libGL check with empty StacktraceTop.
 - Review and clean up usage of chmod(). This fixes a small race condition in the
   Python exception hook where a local attacker could read the information from
   another user's crash report. ([LP: #516029](https://launchpad.net/bugs/516029))
 - hookutils, package_versions(): Ignore "None" packages, for more robust
   package hooks. ([LP: #518295](https://launchpad.net/bugs/518295))

1.12 (2010-01-20)
-----------------
Improvements:
 - launchpad.py: Add options 'escalation_subscription' and 'escalation_tag' for
   handling bugs with more than 10 duplicates.
 - crashdb.conf: For Ubuntu, escalate bugs with >= 10 duplicates to
   "ubuntu-bugcontrol" and tag them with "bugpattern-needed".
   ([LP: #487900](https://launchpad.net/bugs/487900))
 - general-hooks/generic.py: Filter out crashes on missing GLX
   ([LP: #327673](https://launchpad.net/bugs/327673))
 - Add bash completion script. Thanks to Philip Muškovac.
   ([LP: #218933](https://launchpad.net/bugs/218933))

Bug fixes:
 - launchpad.py: Drop APPORT_FILES whitelist for download() and instead just
   filter out file extensions that we know about (*.txt and *.gz).
   ([LP: #444975](https://launchpad.net/bugs/444975))
 - launchpad.py: Do not put the Tags: field into the bug description, since
   they are already proper tags. In download(), convert the real tags back to
   the Tags: field. ([LP: #505671](https://launchpad.net/bugs/505671))
 - test/crash: Update expected core dump flags for changed rlimit behaviour in
   Linux 2.6.32.
 - launchpad.py: Fix marking of 'checked for duplicate' for bugs with upstream
   tasks.
 - launchpad.py, get_fixed_version(): Do not consider a bug as invalid just
   because it has any invalid distro package task.

1.11 (2009-12-23)
-----------------
Improvements:
 - Add "--save" UI option to store the collected information into an .apport
   file instead of sending it right away. The file can then later be sent
   through apport-bug. Update manpages accordingly.
 - Update all copyright and description headers and consistently format them.
 - Rename all TestCase classes to "_T", which makes it much easier to run
   individual tests from the command line.
 - Testsuite: Verify that report details are/are not shown. This uncovered that
   details about package installation failures were not shown before sending
   them, which is fixed now.

Bug fixes:
 - test/hooks: Do not try to add hook information to kernel_crashdump test
   case, since we do not have an UI here. This test case broke when the system
   had an interactive package hook for the kernel.
 - When reporting a bug from a saved .apport file, let the user review/confirm
   the content before sending.

1.10.1 (2009-12-23)
-------------------
Improvements:
 - Install apport-collect symlink.
 - Update translations from Launchpad.

Bug fixes:
 - Move all remaining option/argument parsing from apport-bug into ui.py. This
   allows the user to add options to apport-bug/apport-collect, and also avoids
   unwieldy dissection of options/arguments in shell.

1.10 (2009-12-19)
-----------------
New features:
 - Add a mode for updating an existing problem report to ui.py (-u/--update).
   This is similar to the Ubuntu specific "apport-collect" tool, but
   implemented the right way now: In particular, this has access to the UI and
   thus can use interactive hooks
   ([LP: #385811](https://launchpad.net/bugs/385811)) and show you what is being
   sent for confirmation/cancelling
   ([LP: #371827](https://launchpad.net/bugs/371827))
 - apport-bug: If invoked as "apport-collect" or "apport-update-bug" (i. e.
   through a symlink), run apport in update mode (-u <number>). This provides a
   convenient no-options command line program. Please note that setup.py does
   not currently install such a symlink. Update the apport-bug manpage
   accordingly.

Improvements:
 - launchpad.py: Use new login_with() to clean up code, and specify allowed
   access levels (WRITE_PRIVATE is the only sensible one anyway).
   ([LP: #410205](https://launchpad.net/bugs/410205))
 - New hookutils functions:
   xsession_errors (match lines from ~/.xsession-errors)
   shared_libraries (determine which libraries a binary links with)
   links_with_shared_library (test if a binary links with a particular library)
 - New CrashDatabase API: get_affected_packages(), can_update(), is_reporter()
 - Rename CrashDatabase.update() to update_traces().
 - Add CrashDatabase.update() for adding all new fields of a report. This is
   primarily useful for collecting local standard and package hook data for an
   already existing bug report which was not filed through Apport. This checks
   can_update()/is_reporter() if the user is eligible for updating that
   particular bug. ([LP: #485880](https://launchpad.net/bugs/485880))

Bug fixes:
 - Ignore SIGXCPU and SIGXFSZ; thanks to Kees Cook.
   ([LP: #498074](https://launchpad.net/bugs/498074))
 - launchpad.py: Do not mark non-Ubuntu bugs as needs-retrace, since there is
   no retracer right now. ([LP: #489794](https://launchpad.net/bugs/489794))
 - packaging-apt-dpkg.py, install_retracing_packages(): Do not crash on
   malformed Dependencies.txt lines.
   ([LP: #441709](https://launchpad.net/bugs/441709))
 - use-local: Fix for new source tree location of "apport" binary.

1.9.6 (2009-12-01)
------------------
Improvements:
 - Add pm-utils hook to record current operation, so that apportcheckresume can
   check it. Before this was kept in Ubuntu's pm-utils package.
 - general-hooks/generic.py: Check if using ecryptfs, and which directory.
   ([LP: #444656](https://launchpad.net/bugs/444656))

Bug fixes:
 - launchpad.py: Ensure that text attachments on initial bug filing are valid
   UTF-8. ([LP: #453203](https://launchpad.net/bugs/453203))
 - man/apport-retrace.1: Document -R option.

1.9.5 (2009-11-20)
------------------
Bug fixes:
 - apport-retrace: Fix crash if InterpreterPath/ExecutablePath do not exist.
 - hookutils.py, attach_alsa(): Attach /proc/cpuinfo too, for CPU flags.
 - Fix crash if InterpreterPath does not exist any more at the time of
   reporting. ([LP: #428289](https://launchpad.net/bugs/428289))
 - apport-gtk: Connect signals properly, to repair cancel/window close buttons.
   ([LP: #427814](https://launchpad.net/bugs/427814))
 - Update German translations and fix "konnre" typo.
   ([LP: #484119](https://launchpad.net/bugs/484119))

1.9.4 (2009-11-06)
------------------
Bug fixes:
 - Fix crash when ExecutablePath isn't part of a package.
   ([LP: #424965](https://launchpad.net/bugs/424965))
 - hookutils.py, attach_hardware(): Anonymize disk labels. Thanks to Marco
   Rodrigues. ([LP: #394411](https://launchpad.net/bugs/394411))
 - hookutils.py, attach_wifi(): Anonymize encryption key (which appeared in hex
   when being called as root). Thanks to Marco Rodrigues.
   ([LP: #446299](https://launchpad.net/bugs/446299))
 - launchpad.py: If unset, set bug task source package also for interpreter
   crashes.
 - apport-gtk: Give details window a minimize/maximize button, which were
   missing in some window managers. Thanks to Marien Zwart.
   ([LP: #447749](https://launchpad.net/bugs/447749))
 - apport-kde: Properly terminate program after closing the last dialog.
   ([LP: #458662](https://launchpad.net/bugs/458662))
 - hookutils.py, attach_alsa(): Attach /proc/asound/version.
   ([LP: #467233](https://launchpad.net/bugs/467233))
 - general-hooks/generic.py: Only collect ~/.xsession-errors bits when we have
   an ExecutablePath linked to libgtk.

1.9.3 (2009-10-14)
------------------
Changes:
 - Drop handling of the APPORT_REPORT_THIRDPARTY environment variable and
   "thirdparty" configuration file option. This has never been documented, and
   conceptually does not work. There is a proper mechanism for this in place
   now, e. g. launchpad.py's "project" option.

Bug fixes:
 - hookutils.py: Fix error codes from "comm", thanks to Brian Murray.
 - general-hooks/generic.py: Catch xkbcomp error messages.
   ([LP: #431807](https://launchpad.net/bugs/431807))
 - launchpad.py: Assert that we have exactly one of "distro" or "project"
   option.
 - doc/crashdb-conf.txt: Improve documentation of crash database options.
 - apport-gtk: Make Cancel/Send buttons focusable. Thanks to Marco Rodrigues.
   ([LP: #447780](https://launchpad.net/bugs/447780))

1.9.2 (2009-10-02)
------------------
Improvements:
 - apport-cli: Print the URL and ask whether to open a browser. In many
   situations (such as usage on a server through ssh), it's preferable to not
   open the browser on the reporting computer. Thanks to Matt Zimmerman for the
   initial patch! ([LP: #286415](https://launchpad.net/bugs/286415))
 - general-hooks/generic.py: Collect important glib errors/assertions (which
   should not have private data) from ~/.xsession-errors
   ([LP: #431807](https://launchpad.net/bugs/431807))
 - launchpad.py: Link hardware data submission key if it exists.
   ([LP: #424382](https://launchpad.net/bugs/424382))

Bug fixes:
 - apport-cli: Fix crash with non-ASCII characters in prompts.
 - Fix "apport-bug symptomname" to actually work.
 - launchpad.py: Fix crash on invalid credentials file. Thanks to Marco
   Rodrigues for the initial patch!
   ([LP: #414055](https://launchpad.net/bugs/414055))

1.9.1 (2009-09-22)
------------------
Bug fixes:
 - hookutils.py, attach_hardware(): Do not attach empty Pccardctl*.
 - apport/report.py, add_gdb_info(): Do not throw away stderr from gdb.
 - data/general-hooks/parse_segv.py:
   + Handle arithmetic wrapping correctly.
   + Handle empty base, scale, or index registers in disassembly.
   + Handle in/out ioport faults.
 - Various improvements to user-visible strings, thanks to Marco Rodrigues!
   ([LP: #178507](https://launchpad.net/bugs/178507))
 - Various apport-retrace robustifications.
 - setup.py: Fix DistUtilsExtra version check.
   ([LP: #428337](https://launchpad.net/bugs/428337))
 - hookutils.py, attach_gconf(): Do not overwrite previous values from other
   packages, thanks Loïc Minier!
 - hookutils.py, attach_gconf(): Fix crash with nonexisting <applyto> tags.

1.9 (2009-09-08)
----------------
New features:
 - Add "do what I mean" mode to command line argument parsing (applies to all
   interfaces: -cli, -gtk, -kde). When giving a single argument and no options,
   determine the most likely mode, like reporting a bug against a symptom,
   package, executable name, or PID.
 - Add program "apport-bug" which determines the most appropriate user
   interface (GTK, KDE, CLI) and files a bug through it, using the single
   argument "do what I mean" mode. This is an improved version of Ubuntu's
   "ubuntu-bug" script.

Bug fixes:
 - Update apport-cli manpage to current set of options and behaviour. Also
   point out that apport-gtk and apport-kde share the same CLI.
 - setup.py now installs apport-{gtk,kde} into $prefix/share/apport/, they are
   not supposed to be called directly. This also reflects the path which the
   .desktop files expect.
 - setup.py now installs the internal helper scripts like "kernel_crashdump",
   "apport", or "apportcheckresume" into $prefix/share/apport instead of
   $prefix/bin.
 - Update usage of gettext to work around Python bug of gettext() not returning
   unicodes, but str. Fixes UnicodeDecodeErrors on translated --help output.

1.8.2 (2009-09-05)
------------------
Bug fixes.

1.8.1 (2009-09-03)
------------------
Lots of bug fixes.

1.8 (2009-08-26)
----------------
New features:
 - Do not generally ignore SIGABRT any more. Try to extract the assertion
   message from the core dump, and add it as "AssertionMessage" field. Mark
   reports as unreportable if they do not have an assertion message and crashed
   with SIGABRT. This requires your glibc to have this patch:
   http://sourceware.org/git/?p=glibc.git;a=commitdiff;h=48dcd0ba
 - report.py, add_hooks_info(): Add optional package/srcpackage argument. Hooks
   can use that to change the affected package or call hooks from different
   packages.
 - KDE frontend implementation of ui_question_userpass(), for crash databases
   which need to ask for credentials.
 - hookutils.py: New funtion attach_wifi() to add wireless network related
   information to reports.

Important bug fixes:
 - Fix the test suite on current kernels; test/crash previously often failed
   with python segfaults, since it killed the test processes too early.

1.7 (2009-08-05):
-----------------
New features:
 - Support for "symptom" scripts, which figure out the package for a bug report
   based on interactive questions.

1.6 (2009-07-15)
----------------
New features:
 - Integrate analysis and retracing of kernel vmcore crashes with the "crash"
   tool. Courtesy of Michael Vogt.

Various little bug fixes.

1.5 (2009-06-29)
----------------
New features:
 - Drop all Makefiles, po/POTFILES.in, and most code from setup.py, and use
   DistUtilsExtras.auto which "just does the right thing" for most build system
   tasks. This requires python-distutils-extra >= 2.2, see
   https://launchpad.net/python-distutils-extra

Cleanup:
 - Move all test scripts into test/, to unclutter source tree.
 - setup.py now auto-detects the required packaging backend if
   apport/packaging_impl.py is not manually installed.

1.4 (2009-06-26)
----------------
New features:
 - Replaced Qt4 frontend with a KDE frontend for better KDE integration.

Major bug fixes:
 - packaging-apt-dpkg.py: Add backwards compatibility code for python-apt <
   0.7.9 to not break backportability.

1.3 (2009-06-10)
----------------
New features:
- Interactive package hooks:
  * Add apport.ui.HookUI class which provides GUI functionality such as yes/no
    questions or file dialogs to hooks.
  * add_info() in package hooks now can (optionally) take a second argument which
    is the HookUI instance.
  * See doc/package-hooks.txt for details.
- New function apport.hookutils.root_command_output() to run a command as root,
  through gksu/kdesudo/sudo, depending on the desktop environment.
- Add general hook for analyzing reason of a segfault.

Bug fixes:
- Drop "UnsupportableReason" field, it is too similar to UnreportableReason and
  just confusing.
- Report key names can now contain dashes ('-') and underscores ('_').
  ([LP: #380811](https://launchpad.net/bugs/380811))

1.2.1 (2009-05-15)
------------------
Bug fixes:
- Fix setup.py and PO file merging for recent .glade -> .ui renaming.

Translations:
- Update German translations.

1.2.0 (2009-05-15)
------------------
Moving away from deprecated APIs:
- packaging-apt-dpkg.py: Use python-apt >= 0.7.9 official API and drop usage of
  internal symbols.
- hookutils.py: Drop hal related functions and queries, replace with udev
  database, udev log file, and DMI information from sysfs.
- gtk UI: Convert from libglade to gtk.Builder.

Bug fixes:
- hookutils.py: Drop /proc/version_signature collection, it is Ubuntu specific.
- apportcheckresume: Fix log collection from pm-utils.
- Fix various crashes and report properties for reporting against uninstalled
  packages.

1.1.1 (2009-04-30)
------------------
Security fix:
- etc/cron.daily/apport: Only attempt to remove files and symlinks, do not
  descend into subdirectories of /var/crash/. Doing so might be exploited by a
  race condition between find traversing a huge directory tree, changing an
  existing subdir into a symlink to e. g. /etc/, and finally getting that piped
  to rm. This also changes the find command to not use GNU extensions.  Thanks
  to Stephane Chazelas for discovering this!
  ([LP: #357024](https://launchpad.net/bugs/357024), CVE-2009-1295)

Bug fixes:
- launchpad.py: Send and read Date: field again, reverting r1128; it is useful
  after all. ([LP: #349139](https://launchpad.net/bugs/349139))
- Only add ProcAttrCurrent to reports if it is not "unconfined", to remove some
  noise from reports.
- Detect invalid PIDs in the UI (such as for kernel processes) and give a
  friendly error message instead of silently doing nothing.
  ([LP: #360608](https://launchpad.net/bugs/360608))
- Always run common hooks, and run source package hooks if we do not have a
  binary package name. ([LP: #350131](https://launchpad.net/bugs/350131))
- launchpad.py: Consider socket errors when connecting as transient, so
  that crash-digger doesn't stop completely on them.

1.1 (2009-04-20)
----------------
New features:
- Add hookutils methods for attaching relevant packages, greatly improve
  attach_alsa() for sound problem debugging.
- Move launchpad crash database implementation from ever-breaking
  python-launchpad-bugs (screenscraping) to launchpadlib (official and stable
  Launchpad API).

Bug fixes:
- Drop some remaining distro specific pieces of code.
- Add new field Report.pid which gets set on add_proc_info() and can be used by
  hooks.
- setup.py: Properly clean up all generated files, install missing
  mimetypes/text-x-apport.svg icon symlink.
- Add README file.
- Add translations from Launchpad.
- Remove preloadlib/*; it's undermaintained, and not really useful any more
  these days.
- Various bug fixes; most visible being the misnamed etc/default/apport.default
  file (which should just be etc/default/apport).

1.0 (2009-04-06)
----------------
First upstream release, based on Ubuntu packaging branch; that had been the
de-facto trunk for many years, but this becomes unpractical with several
distributions using it now.
