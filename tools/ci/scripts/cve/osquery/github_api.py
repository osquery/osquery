#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

from time import sleep
import requests
import time
from datetime import datetime, timedelta
from enum import Enum


class IssueCreationError(Exception):
    pass


class IssuesListingError(Exception):
    pass


class GithubIssueState(Enum):
    Open = "open"
    Close = "close"
    All = "all"


class GithubAPI:
    def __init__(self, source_repo: str, dest_repo: str, github_token: str, debug=False):
        self.github_token_ = github_token
        self.source_repo_url = "https://api.github.com/repos/%s/issues" % source_repo
        self.dest_repo_url = "https://api.github.com/repos/%s/issues" % dest_repo
        self.last_request_time = 0
        self.debug = debug

    def debugPrint(self, message: str):
        if self.debug:
            print(f"DEBUG: {message}")

    def makePostRequest(self, url: str, data: dict):
        time_passed = (time.time_ns() - self.last_request_time) / (1000 * 1000)

        # We should in theory detect if the answer contains a Retry-After,
        # because then that should be the delay to be used.
        # We are not because currently this is only used for creating issues,
        # and the Retry-After header is not sent in that case.
        if time_passed < 5000:
            sleep((5000 - time_passed) / 1000.0)

        self.last_request_time = time.time_ns()

        response = requests.post(
            url,
            json=data,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "Authorization": "token %s" % self.github_token_,
            },
        )

        return response

    def makeGetRequest(self, url, params: dict):
        time_passed = (time.time_ns() - self.last_request_time) / (1000 * 1000)

        # Limit at 1 request every 5 seconds
        if time_passed < 5000:
            sleep((5000 - time_passed) / 1000.0)

        self.last_request_time = time.time_ns()

        response = requests.get(
            url,
            params=params,
            auth=("Bearer", self.github_token_),
            headers={
                "Accept": "application/vnd.github.v3+json",
            },
        )

        return response

    def createIssue(self, title: str, content: str, labels: list):

        data = {
            "title": title,
            "body": content,
            "labels": labels,
        }

        attempts = 0
        while attempts < 3:
            attempts += 1

            self.debugPrint(f"Trying to open issue with title \"{data['title']}\"")

            response = self.makePostRequest(self.dest_repo_url, data)

            if response.status_code != 201:
                self.debugPrint(
                    f"Request to {self.dest_repo_url} to create issue with title"
                    f" {data['title']} failed with {response.status_code}, reason:"
                    f" {response.reason + ' ' + response.text if response.text else response.reason}"
                )
                sleep(attempts * 5)
                continue

            return response

        raise IssueCreationError(
            "Failed to open issue with status code: %s and reason: %s"
            % (response.status_code, response.reason)
        )

    def getRecentOpenIssues(
        self, creator="github-actions[bot]", state=GithubIssueState.Open, labels=[]
    ) -> "list[list[dict]]":
        # Query only issues that are open and have been created or updated in the last 6 months.
        # Issues older than that are most likely not interesting
        # because hopefully a release fixing them
        # or something that ignores the CVEs have been created.
        since = datetime.utcnow() - timedelta(days=180)

        params = {
            "creator": creator,
            "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "per_page": 100,
            "page": 1,
            "state": state.value,
        }

        if len(labels) > 0:
            params["labels"] = labels

        issues_batches = []
        listed_all_pages = False

        # Github returns max 100 elements per page/response,
        # so we loop until we got them all
        while not listed_all_pages:
            attempts = 0
            while attempts < 3:
                self.debugPrint(
                    f"Trying to request issues from {self.source_repo_url}, page {params['page']}"
                )

                response = self.makeGetRequest(self.source_repo_url, params)

                if response.status_code != 200:

                    self.debugPrint(
                        f"Request to {self.source_repo_url} to list issues at page {params['page']}"
                        f" failed with {response.status_code}, reason:"
                        f" {response.reason + ' ' + response.text if response.text else response.reason}"
                    )
                    attempts += 1
                    sleep(attempts * 5)
                    continue

                json_response = response.json()
                issues_count = len(json_response)

                # If the answer is empty, the previous one was the last page
                if issues_count == 0:
                    listed_all_pages = True
                    break

                issues_batches.append(json_response)

                # If we have less issues than what we've request per page,
                # means there's no other page and we can end early
                if issues_count < params["per_page"]:
                    listed_all_pages = True
                else:
                    params["page"] += 1

                break

            if attempts == 3:
                reason = response.reason + " " + response.text if response.text else response.reason
                raise IssuesListingError(
                    f"Failed to list issues with status code: {response.status_code}"
                    f" and reason: {reason}"
                )

        return issues_batches
