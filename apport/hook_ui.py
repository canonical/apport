# Copyright (C) 2007 - 2011 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Interactive functions which can be used in package hooks"""

import threading
import time


class HookUI:
    """Interactive functions which can be used in package hooks.

    This provides an interface for package hooks which need to ask interactive
    questions. Directly passing the UserInterface instance to the hooks needs
    to be avoided, since we need to call the UI methods in a different thread,
    and also don't want hooks to be able to poke in the UI.
    """

    def __init__(self, ui):
        """Create a HookUI object.

        ui is the UserInterface instance to wrap.
        """
        self.ui = ui

        # variables for communicating with the UI thread
        self._request_event = threading.Event()
        self._response_event = threading.Event()
        self._request_fn = None
        self._request_args = None
        self._response = None

    #
    # API for hooks
    #

    def information(self, text):
        """Show an information with OK/Cancel buttons.

        This can be used for asking the user to perform a particular action,
        such as plugging in a device which does not work.
        """
        return self._trigger_ui_request("ui_info_message", "", text)

    def yesno(self, text):
        """Show a yes/no question.

        Return True if the user selected "Yes", False if selected "No" or
        "None" on cancel/dialog closing.
        """
        return self._trigger_ui_request("ui_question_yesno", text)

    def choice(self, text, options, multiple=False):
        """Show an question with predefined choices.

        options is a list of strings to present. If multiple is True, they
        should be check boxes, if multiple is False they should be radio
        buttons.

        Return list of selected option indexes, or None if the user cancelled.
        If multiple == False, the list will always have one element.
        """
        return self._trigger_ui_request("ui_question_choice", text, options, multiple)

    def file(self, text):
        """Show a file selector dialog.

        Return path if the user selected a file, or None if cancelled.
        """
        return self._trigger_ui_request("ui_question_file", text)

    #
    # internal API for inter-thread communication
    #

    def _trigger_ui_request(self, fn, *args):
        """Called by HookUi functions in info collection thread."""
        # only one at a time
        assert not self._request_event.is_set()
        assert not self._response_event.is_set()
        assert self._request_fn is None

        self._response = None
        self._request_fn = fn
        self._request_args = args
        self._request_event.set()
        self._response_event.wait()

        self._request_fn = None
        self._response_event.clear()

        return self._response

    def process_event(self):
        """Called by GUI thread to check and process hook UI requests."""
        # sleep for 0.1 seconds to wait for events
        self._request_event.wait(0.1)
        if not self._request_event.is_set():
            return

        assert not self._response_event.is_set()
        self._request_event.clear()
        self._response = getattr(self.ui, self._request_fn)(*self._request_args)
        self._response_event.set()


class NoninteractiveHookUI(HookUI):
    """HookUI variant that does not ask the user any questions."""

    def __init__(self):
        super().__init__(None)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"

    def information(self, text):
        return None

    def yesno(self, text):
        return None

    def choice(self, text, options, multiple=False):
        return None

    def file(self, text):
        return None

    def process_event(self):
        # Give other threads some chance to run
        time.sleep(0.1)
