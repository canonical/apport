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
import urllib.error
import urllib.request
from dataclasses import dataclass

import apport
import apport.crashdb


class Github:
    __last_request: float = time.time()

    def __init__(self, client_id, ui):
        self.__client_id = client_id
        self.__authentication_data = None
        self.__access_token = None
        self.ui = ui

    @staticmethod
    def _stringify(data: dict) -> str:
        "Takes a dict and returns it as a string"
        string = ""
        for key, value in data.items():
            string = f"{string}&{key}={value}"
        return string

    def post(self, url: str, data: str):
        req = urllib.request.Request(url, method="POST")

        req.add_header("Accept", "application/vnd.github.v3+json")
        if self.__access_token:
            req.add_header("Authorization", f"token {self.__access_token}")

        response = urllib.request.urlopen(req, data=data.encode("utf-8"))
        self.__last_request = time.time()

        try:
            response = response.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            raise RuntimeError(f"Failed to post to Github: {text}") from e

        return json.loads(response)

    def api_authentication(self, url: str, data: dict):
        return self.post(url, self._stringify(data))

    def api_open_issue(self, owner: str, repo: str, data: dict):
        url = f"https://api.github.com/repos/{owner}/{repo}/issues"
        return self.post(url, json.dumps(data))

    def __enter__(self):
        data = {"client_id": self.__client_id, "scope": "public_repo"}
        url = "https://github.com/login/device/code"
        response = self.api_authentication(url, data)

        prompt = "Open the following URL. When requested, write this code"
        prompt += "to enable apport to post an issue.\n"
        prompt += f'URL:  {response["verification_uri"]}\n'
        prompt += f'Code: {response["user_code"]}'
        self.ui.ui_info_message("Permissions needed", prompt)

        self.__authentication_data = {
            "client_id": self.__client_id,
            "device_code": f'{response["device_code"]}',
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }
        self.__cooldown = response["interval"]
        self.__expiry = int(response["expires_in"]) + time.time()

        return self

    def __exit__(self, *_) -> None:
        self.__authentication_data = None
        self.__cooldown = 0
        self.__expiry = 0

    def authentication_complete(self) -> bool:
        """
        Asks Github if the user has introduced the code already.
        It respects the wait-time requested by Github.
        """
        if not self.__authentication_data:
            raise RuntimeError(
                "Authentication not started. Use a with statement to do so"
            )

        t = time.time()
        waittime = self.__cooldown - (t - self.__last_request)
        if t + waittime > self.__expiry:
            raise RuntimeError(
                "Failed to log into Github: too much time elapsed."
            )
        if waittime > 0:
            time.sleep(waittime)

        url = "https://github.com/login/oauth/access_token"
        response = self.api_authentication(url, self.__authentication_data)

        if "error" in response:
            if response["error"] == "authorization_pending":
                return False
            if response["error"] == "slow_down":
                self.__cooldown = int(response["interval"])
                return False
            raise RuntimeError(f"Unknown error from Github: {response}")
        elif "access_token" in response:
            self.__access_token = response["access_token"]
            return True
        raise RuntimeError(f"Unknown response from Github: {response}")


@dataclass(frozen=True)
class IssueHandle:
    url: str


class CrashDatabase(apport.crashdb.CrashDatabase):
    """
    Github crash database.
    This is a Apport CrashDB implementation for interacting with Github issues
    """

    def __init__(self, auth_file, options):
        """
        Initialize some variables. Login is delayed until necessary.
        """
        apport.crashdb.CrashDatabase.__init__(self, auth_file, options)
        self.repository_owner = options["repository_owner"]
        self.repository_name = options["repository_name"]
        self.app_id = options["github_app_id"]
        self.labels = set(options["labels"])
        self.issue_url = None
        self.github = None

    def _github_login(self, ui) -> Github:
        with Github(self.app_id, ui) as github:
            while not github.authentication_complete():
                pass
            return github

    def _format_report(self, report: apport.Report) -> dict:
        """
        Formats report info as markdown and creates Github issue JSON.
        """
        body = ""
        for key, value in report.items():
            body += f"**{key}**\n{value}\n\n"

        return {
            "title": "Issue submitted via apport",
            "body": body,
            "labels": [lbl for lbl in self.labels],
        }

    def external_login(self, ui) -> None:
        if self.github is not None:
            return
        self.github = self._github_login(ui)

    def upload(
        self, report: apport.Report, progress_callback=None
    ) -> IssueHandle:
        """Upload given problem report return a handle for it.

        In Github, we open an issue.
        """
        assert self.accepts(report)

        if self.github is None:
            raise RuntimeError("Failed to login to Github")

        data = self._format_report(report)
        response = self.github.api_open_issue(
            self.repository_owner, self.repository_name, data
        )
        return IssueHandle(url=response["html_url"])

    def get_comment_url(
        self, report: apport.Report, handle: IssueHandle
    ) -> str:
        """
        Return an URL that should be opened after report has been uploaded
        and upload() returned handle.
        """
        return handle.url
