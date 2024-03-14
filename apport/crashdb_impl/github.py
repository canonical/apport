"""Crash database implementation for Github."""

# Copyright (C) 2022 - 2022 Canonical Ltd.
# Author: Eduard Gómez Escanell <edu.gomez.escandell@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import requests

import apport
import apport.crashdb


class Github:
    """Wrapper around Github API, used to log in and post issues."""

    __last_request: float = time.time()

    def __init__(self, client_id, message_callback):
        self.__client_id = client_id
        self.__authentication_data = None
        self.__access_token = None
        self.__cooldown = None
        self.__expiry = None
        self.message_callback = message_callback

    @staticmethod
    def _stringify(data: dict) -> str:
        """Takes a dict and returns it as a string for POSTing."""
        string = ""
        for key, value in data.items():
            string = f"{string}&{key}={value}"
        return string

    def _post(self, url: str, data: str) -> Any:
        """Posts the given data to the given URL.
        Uses auth token if available"""
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.__access_token:
            headers["Authorization"] = f"token {self.__access_token}"
        try:
            result = requests.post(url, headers=headers, data=data, timeout=5.0)
        except requests.RequestException as err:
            self.message_callback(
                "Failed connection",
                f"Failed connection to {url}.\n"
                + "Please check your internet connection and try again.",
            )
            raise err
        finally:
            self.__last_request = time.time()

        result.raise_for_status()  # Not using UI: the user can't do much here
        return json.loads(result.text)

    def api_authentication(self, url: str, data: dict) -> Any:
        """Authenticate against the GitHub API."""
        return self._post(url, self._stringify(data))

    def api_open_issue(self, owner: str, repo: str, data: dict) -> Any:
        """Open a new issue on the GitHub project."""
        url = f"https://api.github.com/repos/{owner}/{repo}/issues"
        return self._post(url, json.dumps(data))

    def __enter__(self):
        """Enters login process. At exit, login process ends."""
        data = {"client_id": self.__client_id, "scope": "public_repo"}
        url = "https://github.com/login/device/code"
        response = self.api_authentication(url, data)

        prompt = (
            "Posting an issue requires a Github account. If you have "
            "one, please follow these steps to log in.\n"
            "\n"
            "Open the following URL. When requested, write this code "
            "to enable apport to open an issue.\n"
            "URL:  {url}\n"
            "Code: {code}"
        )

        url = response["verification_uri"]
        code = response["user_code"]

        self.message_callback("Login required", prompt.format(url=url, code=code))

        self.__authentication_data = {
            "client_id": self.__client_id,
            "device_code": f'{response["device_code"]}',
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }
        self.__cooldown = response["interval"]
        self.__expiry = int(response["expires_in"]) + time.time()

        return self

    def __exit__(self, *_: Any) -> None:
        self.__authentication_data = None
        self.__cooldown = 0
        self.__expiry = 0

    def authentication_complete(self) -> bool:
        """Asks Github if the user has logged in already.
        It respects the wait-time requested by Github.
        """
        if not self.__authentication_data:
            raise RuntimeError(
                "Authentication not started. Use a with statement to do so"
            )

        current_time = time.time()
        waittime = self.__cooldown - (current_time - self.__last_request)
        if current_time + waittime > self.__expiry:
            self.message_callback(
                "Failed login", "Github authentication expired. Please try again."
            )
            raise RuntimeError("Github authentication expired")
        if waittime > 0:
            time.sleep(waittime)  # Avoids spamming the API

        url = "https://github.com/login/oauth/access_token"
        response = self.api_authentication(url, self.__authentication_data)

        if "error" in response:
            if response["error"] == "authorization_pending":
                return False
            if response["error"] == "slow_down":
                self.__cooldown = int(response["interval"])
                return False
            raise RuntimeError(f"Unknown error from Github: {response}")
        if "access_token" in response:
            self.__access_token = response["access_token"]
            return True
        raise RuntimeError(f"Unknown response from Github: {response}")


@dataclass(frozen=True)
class IssueHandle:  # pylint: disable=missing-class-docstring
    url: str


class CrashDatabase(apport.crashdb.CrashDatabase):
    """Github crash database.
    This is a Apport CrashDB implementation for interacting with Github issues
    """

    def __init__(self, auth_file, options):
        """Initialize some variables. Login is delayed until necessary."""
        apport.crashdb.CrashDatabase.__init__(self, auth_file, options)
        self.repository_owner = options["repository_owner"]
        self.repository_name = options["repository_name"]
        self.app_id = options["github_app_id"]
        self.labels = set(options["labels"])
        self.issue_url = None
        self.github = None

    def _format_report(self, report: apport.Report) -> dict:
        """Formats report info as markdown and creates Github issue JSON."""
        body_markdown = ""
        for key, value in report.items():
            body_markdown += f"**{key}**\n{value}\n\n"

        return {
            "title": "Issue submitted via apport",
            "body": body_markdown,
            "labels": list(self.labels),
        }

    def _github_login(self, user_message_callback):
        with Github(self.app_id, user_message_callback) as github:
            while not github.authentication_complete():
                pass
            return github

    def upload(
        self,
        report: apport.Report,
        progress_callback: Callable | None = None,
        user_message_callback: Callable | None = None,
    ) -> IssueHandle:
        """Upload given problem report return a handle for it.
        In Github, we open an issue.
        """
        assert self.accepts(report)

        self.github = self._github_login(user_message_callback)

        if self.github is None:
            raise RuntimeError("Failed to login to Github")

        data = self._format_report(report)
        if not (self.repository_name is None and self.repository_owner is None):
            response = self.github.api_open_issue(
                self.repository_owner, self.repository_name, data
            )
        elif "SnapGitOwner" in report and "SnapGitName" in report:
            response = self.github.api_open_issue(
                report["SnapGitOwner"], report["SnapGitName"], data
            )
        else:
            raise RuntimeError(
                "Couldn't determine which repository to file the report in"
            )

        return IssueHandle(url=response["html_url"])

    def get_comment_url(self, report: apport.Report, handle: IssueHandle) -> str:
        """Return a URL that should be opened after report has been uploaded
        and upload() returned handle.
        """
        return handle.url

    def _mark_dup_checked(self, crash_id, report):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def can_update(self, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def close_duplicate(self, report, crash_id, master_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def download(self, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def duplicate_of(self, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def get_affected_packages(self, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def get_distro_release(self, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def get_dup_unchecked(self):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def get_fixed_version(self, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def get_id_url(self, report, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def get_unfixed(self):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def get_unretraced(self):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def is_reporter(self, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def mark_regression(self, crash_id, master):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def mark_retrace_failed(self, crash_id, invalid_msg=None):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def mark_retraced(self, crash_id):
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )

    def update(
        self,
        crash_id,
        report,
        comment,
        change_description=False,
        attachment_comment=None,
        key_filter=None,
    ):  # pylint: disable=too-many-arguments
        raise NotImplementedError(
            "This method is not relevant for Github database implementation."
        )
