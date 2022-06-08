Test suite for Apport
=====================

The test suite for Apport is grouped into different groups described below. If
the tests are run in place, they test the code in place. If the `tests`
directory is copied outside, the tests will run against the installation.

Linter tests
------------

The script [run-linters](./run-linters) runs following linters on the source
code:

 * pycodestyle
 * pyflakes

Unit tests
----------

The [unit directory](./unit) contains unit tests. These test cases test
individual functions or methods. They execute fast (a few milliseconds per test
at most) and do not interact with the outside system. All outside access is
mocked. The unit tests can be run from the top directory by calling:

```
python3 -m unittest tests/unit/test_*.py
```

or with pytest:

```
python3 -m pytest tests/unit/
```

Integration tests
-----------------

The [integration directory](./integration) contains integration tests. These
test cases test full scripts but also individual functions or methods. They
execute relatively quickly (a few seconds per test at most) and interact with
the outside system in a non invasive manner. Temporary directories are created
in case the test needs to write to them. The integration tests can be run from
the top directory by calling:

```
python3 -m unittest tests/integration/test_*.py
```

or with pytest:

```
python3 -m pytest tests/integration/
```

System tests
------------

The [system directory](./system) contains system tests. It also contains
integration tests that need special environment setup or have a long execution
time. The GTK and KDE UI integration tests need a window system, which can be
provided by `xvfb-run`. Some integration tests query https://launchpad.net/.
These tests can be skipped by setting the environment variable
`SKIP_ONLINE_TESTS` to something non empty. The test in
[test_python_crashes.py](./system/test_python_crashes.py) need a running D-Bus
daemon. Whit a D-Bus daemon running, the system tests can be run from the top
directory by calling:

```
GDK_BACKEND=x11 xvfb-run python3 -m unittest tests/system/test_*.py
```

or with pytest:

```
GDK_BACKEND=x11 xvfb-run python3 -m pytest tests/system/
```
