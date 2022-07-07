Principal CrashDB conf file
===========================

The file is located in `/etc/apport/crashdb.conf`.

This file contains information about the Crash Databases to use when sending a
crash report.  Here is an excerpt of the file:

```python
default = "ubuntu"

databases = {
    "ubuntu": {
        "impl": "launchpad",
        "distro": "ubuntu",
        "bug_pattern_url": "http://people.canonical.com/~ubuntu-archive/bugpatterns/bugpatterns.xml",
        "dupdb_url": "http://people.canonical.com/~ubuntu-archive/apport-duplicates",
    },
}
```

The `default` parameter is used to specify the default database to use when
getting a crash report.  It's one of the names used as a label in the
`databases` dictionary. Please note that package hooks can change the database
to report to by setting the `CrashDB` field; please see
[package-hooks.md](./package-hooks.md) for details of this.

Standard options
================

All crash database implementations support the following options:

 - `bug_pattern_url`: URL to an XML file describing the bug patterns for this
   distribution. This can match existing bugs to arbitrary keys of a report
   with regular expressions, to prevent common problems from being reported
   over and over again. Please see `apport.Report.search_bug_patterns()` for the
   format.

 - `dupdb_url`: URL for the duplicate DB export, to prevent already known
   crashes from being reported again. This can be generated from an existing
   duplicate database SQLite file with `dupdb admin publish` (see manpage) or
   with the `--publish-db` option of `crash-digger`.

 - `problem_types`: List of `ProblemType:` values that this database accepts for
   reporting. E. g. you might set

   ```python
   "problem_types": ["Bug", "Package"]
   ```

   to only get bug and package failure reports reported to this database,
   but not crash reports. If not present, all types of problems will be
   reported.

Third Parties crashdb databases
===============================

Third party packages can also ship a set of databases to use with Apport. Their
configuration files should be located in `/etc/apport/crashdb.conf.d/` and end
with `.conf`.

Here is an example `/etc/apport/crashdb.conf.d/test.conf` file:

```python
mydatabase = {
    "impl": "mycrashdb_impl",
    "option1": "myoption1",
    "option2": "myoption2",
}
mydatabase1 = {
    "impl": "mycrashdb_impl",
    "option1": "myoption3",
    "option2": "myoption4",
}
```

The databases specified in this file will be merged into the `databases`
dictionary. The result is the equivalent of having the principal file:

```python
default = "ubuntu"

databases = {
    "ubuntu": {
        "impl": "launchpad",
        "bug_pattern_url": "http://people.canonical.com/~ubuntu-archive/bugpatterns/bugpatterns.xml",
        "distro": "ubuntu",
    },
    "mydatabase": {
        "impl": "mycrashdb_impl",
        "option1": "myoption1",
        "option2": "myoption2",
    },
    "mydatabase1": {
        "impl": "mycrashdb_impl",
        "option1": "myoption3",
        "option2": "myoption4",
    },
}
```

Crash database implementations
==============================

 * `launchpad` uses bug reports against https://launchpad.net, either projects
   or distribution packages.

   **Options**:
   - `distro`: Name of the distribution in Launchpad
   - `project`: Name of the project in Launchpad
     (Note that exactly one of `distro` or `project` must be given.)
   - `staging`: If set, this uses staging instead of production (optional).
     This can be overriden or set by `APPORT_STAGING` environment.
   - `cache_dir`: Path to a permanent cache directory; by default it uses a
     temporary one. (optional). This can be overridden or set by
     `APPORT_LAUNCHPAD_CACHE` environment.
   - `escalation_subscription`: This subscribes the given person or team to
     a bug once it gets the 10th duplicate.
   - `escalation_tag`: This adds the given tag to a bug once it gets more
     than 10 duplicates.
   - `initial_subscriber`: The Launchpad user which gets subscribed to newly
     filed bugs (default: `apport`). It should be a bot user which the
     `crash-digger` instance runs as, as this will get to see all bug
     details immediately.
   - `triaging_team`: The Launchpad user/team which gets subscribed after
     updating a crash report bug by the retracer (default:
     `ubuntu-crashes-universe`)
   - `architecture`: If set, this sets and watches out for `needs-*-retrace`
     tags of this architecture. This is useful when being used with
     `apport-retrace` and `crash-digger` to process crash reports of foreign
     architectures. Defaults to system architecture.

   Crash reports are always filed as private Launchpad bug. Bug reports are
   public by default, but a package hook can change this by adding a
   `LaunchpadPrivate` report field (**not** a crashdb option!) with any value,
   and adding a `LaunchpadSubscribe` report field with a list of initial
   subscribers. For example, your package hook might do this:

   ```python
   def add_info(report):
       report["LaunchpadPrivate"] = "1"
       report["LaunchpadSubscribe"] = "joe-hacker foobar-dev"
   ```

 * `memory` is a simple implementation of crash database interface which keeps
   everything in RAM. This is mainly useful for testing and debugging.

   The only supported option is `dummy_data`; if set to a non-`False` value, it
   will populate the database with some example reports.
