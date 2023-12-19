#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import json
import argparse
import os
from typing import Optional
import nvdlib
from osquery.github_api import GithubAPI
from osquery.manifest_api import validateManifestFormat
from osquery.manifest_api import libraries_without_cpe
import re
import sys
import time
from datetime import datetime, timedelta, date

match_cve = re.compile(" (CVE-.*-.*)$")

DEBUG = False


def parseCVEFromTitle(title: str):
    match = match_cve.search(title)
    if match:
        return match.group(1)
    else:
        return None


def print_err(message: str):
    print("Error: " + message, file=sys.stderr)


def getCVES(
    vendor: str,
    product: str,
    api_key,
    interval: int,
    library_name: str,
    version: Optional[str] = None,
    date_string: Optional[str] = None,
):
    attempt = 0
    max_attempts = 3
    nist_cves = []
    global DEBUG
    now = datetime.now()

    while attempt < max_attempts:
        try:
            if version is not None:
                nist_cves = nvdlib.searchCVE(
                    cpeName="cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*"
                    % (vendor, product, version),
                    key=api_key,
                    isVulnerable=True,
                )
                break
            else:
                # Some libraries have a version that corresponds to a date,
                # so we search for CVEs published in the window of time
                # between the library last commit date and the current date,
                # 120 days at a time, since the NVD API is limited

                if attempt == 0:
                    start_date = datetime.strptime(date_string, "%Y-%m-%d")
                    end_date = start_date

                while end_date < now:
                    end_date = start_date + timedelta(days=120)

                    # We use virtualMatchString since it permits to not specify the version,
                    # which we can't specify because we are searching via published date
                    cves = nvdlib.searchCVE(
                        virtualMatchString="cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*"
                        % (vendor, product),
                        pubStartDate=start_date,
                        pubEndDate=end_date,
                        key=api_key,
                    )

                    start_date = end_date
                    nist_cves.extend(cves)

                break

        except Exception as e:
            if DEBUG:
                print(f"Error searching CVE for library {library_name}: {e}. Retrying")

            attempt += 1
            if attempt == max_attempts:
                print(f"Failed to get CVEs for product: {library_name}. Skipping")
            else:
                time.sleep(interval)
                interval *= 2

            continue

    return (nist_cves, attempt > 0)


class CVE:
    def __init__(self, name, severity, description, url) -> None:
        self.name = name
        self.severity = severity
        self.description = "No description" if description is None else description
        self.url = url


parser = argparse.ArgumentParser()
parser.add_argument(
    "--manifest",
    type=str,
    required=True,
    help="Path to the third party libraries JSON manifest",
)

parser.add_argument(
    "--source-repo",
    type=str,
    help=(
        "Specifies where the already opened issues should be searched. Used for testing the script."
        " Defaults to osquery/osquery."
    ),
    default="osquery/osquery",
)


parser.add_argument(
    "--dest-repo",
    type=str,
    help=(
        "Specifies where the issues should be opened. Used for testing the script. Defaults to"
        " osquery/osquery."
    ),
    default="osquery/osquery",
)

parser.add_argument(
    "--create-issues",
    help="When enabled the script will also create a Github issue for each new CVE found",
    required=False,
    action="store_true",
    default=False,
)

parser.add_argument(
    "--github-token",
    required=False,
    type=str,
    help="Optional Github token to open issues about the detected CVEs",
)

parser.add_argument(
    "--api-key",
    required=False,
    type=str,
    help="Optional API key for the NVD NIST APIs, to reduce rate limiting",
)

parser.add_argument(
    "--debug",
    action="store_true",
    default=False,
    required=False,
    help="Enable debug prints",
)

parser.add_argument(
    "--libraries",
    required=False,
    help="List of comma separated library names to check CVEs of",
    type=str,
)

args = parser.parse_args()

if args.manifest == "":
    print_err("No manifest to parse, please provide a path to the json file")
    exit(1)

if not os.path.exists(args.manifest):
    print_err("The provided manifest path doesn't exist. Please provide a valid path")
    exit(1)

api_key = args.api_key
if args.api_key is None:
    api_key = os.environ.get("NIST_API_KEY")
    if api_key is None:
        # Needed for the NVD API later, which uses boolean values for a missing value
        api_key = False

base_nvd_retry_interval = 1 if api_key else 6
nvd_interval = base_nvd_retry_interval

if args.debug:
    DEBUG = True

libraries = {}

with open(args.manifest, "r") as manifest_file:
    libraries = json.load(manifest_file)

if not validateManifestFormat(libraries):
    print_err("The manifest format is not valid, interrupting")
    exit(1)

cves_per_library = []
all_ignored_cves = []
libraries_to_check = []

# If not empty, only check the libraries provided in this list
if args.libraries:
    libraries_to_check.extend(args.libraries.split(","))

# Loop through all the libraries in the manifest
for library_name, library_metadata in libraries.items():
    # Some libraries do not have CPEs so we cannot query them
    if library_name in libraries_without_cpe:
        continue

    # Skip if we want to check a specific set of libraries and this is not in it
    if len(libraries_to_check) > 0:
        if library_name not in libraries_to_check:
            continue

    product = library_metadata["product"]

    if "version" in library_metadata:
        version = library_metadata["version"]
        print(f"Verifying CVEs for library: {library_name} {version}")
        date_string = None
    else:
        date_string = library_metadata["date"]
        print(f"Verifying CVEs for library: {library_name} {date_string}")
        version = None

    vendor = library_metadata["vendor"]
    ignored_cves = library_metadata["ignored-cves"]
    all_ignored_cves.extend(ignored_cves)

    # The underlying nvdlib library will wait around base_nvd_retry_interval already,
    # which is the NVD API required wait time, but sometimes that's not enough.
    # We sleep increasingly more when we are downloading CVEs for a specific library
    # and getting errors, but at the next library we would start again
    # with a base_nvd_retry_interval sleep; that might not be enough again to avoid
    # further errors later.
    # So we add some more sleeping between libraries if the previous download had errors.
    nvd_interval_diff = nvd_interval - base_nvd_retry_interval
    if nvd_interval_diff > 0:
        time.sleep(nvd_interval_diff)

    if version:
        nist_cves, had_errors = getCVES(
            vendor, product, api_key, nvd_interval, library_name, version=version
        )
    else:
        nist_cves, had_errors = getCVES(
            vendor,
            product,
            api_key,
            nvd_interval,
            library_name,
            date_string=date_string,
        )

    # We assume errors are due to rate limiting and double the time we wait for each CVE query
    if had_errors:
        nvd_interval *= 2
    elif nvd_interval_diff > 0:
        # But if we are successful we slowly go down again
        nvd_interval = max(nvd_interval - 1, base_nvd_retry_interval)

    if len(nist_cves) == 0:
        continue

    cves = []

    # Sort by id, so the most recent CVEs are on top
    nist_cves.sort(key=lambda cve: cve.id, reverse=True)

    for cve in nist_cves:
        if hasattr(cve, "v31severity"):
            severity = cve.v31severity
        elif hasattr(cve, "v30severity"):
            severity = cve.v30severity
        elif hasattr(cve, "v2severity"):
            severity = cve.v2severity
        else:
            severity = "UNKNOWN"

        # Find the english description
        description_text = None
        for description in cve.descriptions:
            if description.lang == "en":
                description_text = description.value

        cves.append(CVE(cve.id, severity, description_text, cve.url))

    cves_per_library.append({"name": library_name, "cves": cves})

if len(cves_per_library) == 0:
    exit(0)

# Always print the cves that have been found
print("\nFound the following CVEs:")

libraries_with_cves = []
libraries_with_ignored_cves = []

# Split ignored CVEs from still valid CVEs and organize both for display
for library in cves_per_library:
    cves = library["cves"]

    cves_messages = []
    ignored_cves_messages = []

    for cve in cves:
        if cve.name not in all_ignored_cves:
            cves_messages.append(f"\t Name: {cve.name}\tSeverity: {cve.severity}")
        else:
            ignored_cves_messages.append(
                f"\t Name: {cve.name}\tSeverity: {cve.severity}"
            )

    if len(cves_messages) > 0:
        libraries_with_cves.append((library["name"], cves_messages))

    if len(ignored_cves_messages) > 0:
        libraries_with_ignored_cves.append((library["name"], ignored_cves_messages))

for library in libraries_with_cves:
    print(f"Library: {library[0]}")
    for cve in library[1]:
        print(cve)
    print()

print("\nThe following CVEs have been ignored:")

for library in libraries_with_ignored_cves:
    print(f"Library: {library[0]}")
    for cve in library[1]:
        print(cve)
    print()

if args.create_issues:
    github_token = None
    if not args.github_token:
        github_token = os.environ.get("GITHUB_TOKEN")

        if github_token is None:
            print("Missing github token")
            exit(1)
    else:
        github_token = args.github_token

    github_api = GithubAPI(args.source_repo, args.dest_repo, github_token, DEBUG)

    print("Retrieving already opened issues")
    issues_batches = github_api.getRecentOpenIssues(
        labels=["cve", "security", "libraries"]
    )

    # Process all opened issues and extract a list of CVEs that have been already reported
    opened_cve_issues = set()
    for batch in issues_batches:
        for issue in batch:
            if issue.get("pull_request") is not None:
                continue

            cve_id = parseCVEFromTitle(issue["title"])

            if cve_id is None:
                continue

            opened_cve_issues.add(cve_id)

    # Open issues for each new CVE
    errors = 0
    count = 0
    print("Opening issues for new CVEs")
    for library in cves_per_library:
        cves = library["cves"]
        # We create the CVEs from older to newer
        # so that the newer ones are on top of the Github issues list
        for cve in reversed(cves):
            if cve.name in opened_cve_issues or cve.name in all_ignored_cves:
                continue

            library_name = library["name"]

            try:
                issue_description = f"{cve.url}\n\n{cve.description}"

                github_api.createIssue(
                    f"Library {library_name} has vulnerability {cve.name}",
                    issue_description,
                    [
                        f"severity-{cve.severity.lower()}",
                        "cve",
                        "libraries",
                        "security",
                    ],
                )
            except Exception as e:
                print(f"Failed to create issue for library {library_name}: {e}")
                errors += 1
                continue

            count += 1

    if errors > 0:
        print(f"Done. Opened {count} new issues, {errors} failed to be opened")
        exit(1)
    else:
        print(f"Done. Opened {count} new issues")
