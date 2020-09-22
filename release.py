#! /usr/bin/env python3
#
# Copyright (c) 2020 Linaro Limited
# Copyright (c) 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import netrc
import os
import requests
import re

from datetime import datetime


JIRA_HOST = 'zephyrprojectsec.atlassian.net'
BASEURL = f"https://{JIRA_HOST}/rest/api/2/"

# Zephyr JIRA custom field names.
CVE_FIELD = 'customfield_10035'
EMBARGO_FIELD = 'customfield_10051'

ISSUES = {}

# Get authentication information.


def get_auth(host):
    auth = netrc.netrc().authenticators(host)
    if auth is None:
        raise Exception("Expecting a single authenticator for host")
    return (auth[0], auth[2])


def query(text, field, params={}):
    auth = get_auth(JIRA_HOST)
    result = []
    start = 1

    while True:
        params["startAt"] = start
        r = requests.get(BASEURL + text, auth=auth, params=params)
        if r.status_code != 200:
            print(r)
            raise Exception("Failure in query")
        j = r.json()

        # The Jira API is inconsistent.  If the results returned are
        # directly a list, just use that.
        if isinstance(j, list):
            return j

        result.extend(j[field])

        if len(j[field]) < j["maxResults"]:
            break

        start += j["maxResults"]

    return result


class Issue(object):
    def __init__(self, js):
        self.key = js['key']
        fields = js["fields"]

        # We should use this info to know if the issue
        # is for the current release. Unfortunatelly most
        # issues on JIRA don't have this field properly
        # filled.
        self.fixversion = fields["fixVersions"]
        self.status = fields["status"]['name']

        if fields[CVE_FIELD] is not None:
            self.cve = fields[CVE_FIELD]
            self.has_cve = True
        else:
            self.cve = "".ljust(len("CVE-xxxx-xxxxx"), " ")
            self.has_cve = False

        self.embargo_str = fields[EMBARGO_FIELD]
        if self.embargo_str:
            self.embargo = datetime.strptime(self.embargo_str, "%Y-%m-%d")
        else:
            self.embargo = None

        self.summary = fields["summary"]
        self.parent = not fields['issuetype']['subtask']


def parse_args():
    global args

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-r", "--release", required=False, action="store_true",
                        help="Generate a release report")
    parser.add_argument("-v", "--vulnerabilities", required=False, action="store_true",
                        help="Generate a vulnerability report")
    parser.add_argument("-d", "--debug", required=False, action="store_true",
                        help="Add details more info to report")
    args = parser.parse_args()


def generate_release(issues):
    now = datetime.now()
    notes = []

    for issue in issues:
        if issue.embargo and now < issue.embargo:
            issue.summary = "Under embargo until {}".format(issue.embargo_str)

        if args.debug:
            notes.append(f"* {issue.key} {issue.cve}: {issue.summary}\n")
        else:
            notes.append(f"* {issue.cve}: {issue.summary}\n")
    print(*notes)


# This report definitely deserves more love. We need to put a better
# bug description and the link for the CVE.
def generate_vulnerabilities(issues):
    now = datetime.now()
    notes = []

    for issue in issues:
        if not issue.has_cve:
            continue

        under_embargo = False
        if issue.embargo and now < issue.embargo:
            under_embargo = True
            issue.summary = "Under embargo until {}".format(issue.embargo_str)

        print(issue.cve)
        print("-" * len(issue.cve))
        print("")
        print(issue.summary)

        if not under_embargo:
            print("\n- `Zephyr project bug tracker {}\n  "
                  "<https://zephyrprojectsec.atlasssian.net/browse/{}>`_"
                  .format(issue.key, issue.key))
        print("")


def main():
    parse_args()

    p = {'jql': 'project="ZEPSEC"'}
    j = query("search", "issues", params=p)

    issues = []
    for jissue in j:
        issue = Issue(jissue)
        if (issue.status == "Accepted") and (issue.parent == True):
            issues.append(issue)

    if args.vulnerabilities:
        generate_vulnerabilities(issues)
    else:
        generate_release(issues)


if __name__ == '__main__':
    main()
