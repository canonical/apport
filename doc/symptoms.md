Apport symptom scripts
======================

In some cases it is quite hard for a bug reporter to figure out which package to
file a bug against, especially for functionality which spans multiple packages.
For example, sound problems are divided between the kernel, alsa, pulseaudio,
and gstreamer.

Apport supports an extension of the notion of package hooks to do an
interactive "symptom based" bug reporting. Calling the UI with just `-f` and
not specifying any package name shows the available symptoms, the user selects
the matching category, and the symptom scripts can do some question & answer
game to finally figure out which package to file it against and which
information to collect. Alternatively, the UIs can be invoked with 
`-s symptom-name`.

Structure
=========

Symptom scripts go into `/usr/share/apport/symptoms/symptomname.py`, and have
the following structure:

```python
description = "One-line description"


def run(report, ui):
    problem = ui.choice(
        "What particular problem do you observe?",
        ["Thing 1", "Thing 2", ...],
    )

    # collect debugging information here, ask further questions, and figure out
    # package name
    return "packagename"
```

They need to define a `run()` method which can use the passed `HookUI` object
for interactive questions (see [package-hooks.md](./package-hooks.md) for
details about this).

`run()` can optionally add information to the passed report object, such as
tags. Before `run()` is called, Apport already added the OS and user information
to the report object.

After the symptom `run()` method, Apport adds package related information and
calls the package hooks as usual. 

`run()` has to return the (binary) package name to file the bug against.

Just as package hooks, if the user canceled an interactive question for which
the script requires an answer, `run()` should raise `StopIteration`, which will
stop the bug reporting process. 

Example
=======

```python
import apport

description = "External or internal storage devices (e. g. USB sticks)"


def run(report, ui):
    problem = ui.choice(
        "What particular problem do you observe?",
        [
            "Removable storage device is not mounted automatically",
            "Internal hard disk partition cannot be mounted manually",
            # ...
        ],
    )

    # collect debugging information here, ask further questions

    if not kernel_detected:
        return apport.packaging.get_kernel_package()
    if not udev_detected:
        return "udev"
    return "devicekit-disks"
```
