Apport per-package hooks
========================

In addition to the generic information apport collects, arbitrary
package-specific data can be included in the report by adding package hooks.
For example:

 - Relevant log files
 - Configuration files
 - Current system state 

Hooks can also ask interactive questions, cause a crash to be ignored, or the
problem can be marked as "not reportable" with an explanation. 

This happens by placing a Python code snippet into

```
/usr/share/apport/package-hooks/<packagename>.py
```

or

```
/usr/share/apport/package-hooks/source_<sourcepackagename>.py
```

Apport will import this and call a function

```python
add_info(report, ui)
```

and pass two arguments:

 - The currently processed problem report. This is an instance of
   `apport.Report`, and should mainly be used as a dictionary (keys have to be
   alphanumeric and may contain dots, dashes, or underscores). Please see the
   Python help of this class for details:

   ```sh
   python -c 'import apport; help(apport.Report)'
   ```

 - An instance of `apport.ui.HookUI` which can be used to interactively get more
   information from the user, such as asking for doing a particular action,
   yes/no question, multiple choices, or a file selector. Please see the Python
   help for available functions:

   ```sh
   python -c 'import apport.ui; help(apport.ui.HookUI)'
   ```

Hook behaviour
==============

If you just add information in hooks, Apport will always proceed with filing
a report. You can influence this in various ways:

 * The hook detects a situation which should not be reported as a problem,
   because they happen on known-bad hardware, from a third-party repository, or
   other situations. This can be achieved by adding a field

   ```python
   report["UnreportableReason"] = _("explanation")
   ```

   Such reports are displayed by the apport frontends as unreportable with the
   given explanation. Please ensure proper i18n for the texts.

 * The user cancelled an interactive question for which the hook requires an
   answer. Then you should call

   ```python
   raise StopIteration
   ```

   to cancel the problem report submission.

For special classes of problems where Apport does not have a builtin crash
duplicate detection (such as for signal and Python crashes), hooks can also set
`report["DuplicateSignature"]`. This should both uniquely identify the problem
class (e. g. `XorgGPUFreeze`) as well as the particular problem (i. e.
variables which tell this instance apart from different problems).

Package independent hooks
=========================

Similarly to per-package hooks, you can also have additional
information collected for any crash or bug. For example, you might
want to include violation logs from SELinux or AppArmor for every
crash. The interface and file format is identical to the per-package
hooks, except that they need to be put into

```
/usr/share/apport/general-hooks/<hookname>.py
```

The `<hookname>` can be arbitrary and should describe the functionality.

Tags
====

Some bug tracking systems support tags to further categorize bug reports and
make searching/duplication easier. Hooks can set tags with

```python
report.add_tags(["tag1", "tag2"])
```

The `Tags` field contains a space separated list of tag names.

Customize the crash DB to use
=============================

To use another crash database than the default one, you should create
an hook that adds a `CrashDB` field with the name of the database to
use. See `/etc/apport/crashdb.conf` and
`/etc/apport/crashdb.conf.d/*.conf` for available databases.

If there is no existing database, or you do not want to ship a configuration,
the `CrashDB` field can also contain the DB specification itself, i. e. what
would otherwise be in `/etc/apport/crashdb.conf.d/*.conf`. Example:

```python
report["CrashDB"] = '{"impl": "launchpad", "project": "foo", "my_option": "1"}'
```

Please see [crashdb-conf.md](./crashdb-conf.md) for a description of available
implementations and options.

Standard hook functions
=======================

If you write hooks, please have a look at the `apport.hookutils`
module first: 

```sh
python -c 'import apport.hookutils; help(apport.hookutils)'
```

It provides readymade and safe functions many standard situations, 
such as getting a command's output, attaching a file's contents, 
attaching hardware related information, etc.

Examples
========

Trivial example: To attach a log file `/var/log/foo.log` for crashes in
binary package `foo`, put this into `/usr/share/apport/package-hooks/foo.py`:

```python
import os.path


def add_info(report, ui):
    if os.path.exists("/var/log/foo.log"):
        with open("/var/log/foo.log") as f:
            report["FooLog"] = f.read()
```


Example with an interactive question and attaching sound hardware information:

```python
import apport.hookutils


def add_info(report, ui):
    apport.hookutils.attach_alsa(report)

    ui.information("Now playing test sound...")

    report["AplayOut"] = apport.hookutils.command_output(
        ["aplay", "/usr/share/sounds/question.wav"]
    )

    response = ui.yesno("Did you hear the sound?")
    if response is None:  # user cancelled
        raise StopIteration
    report["SoundAudible"] = str(response)
```

Apport itself ships a source package hook, see
`/usr/share/apport/package-hooks/source_apport.py`.
