#! /usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2020 Linaro Limited

# TODO: Encode/decode impact
# TODO: Problem type
# TODO: References

"""
Generate CVEs based on information from JIRA.

This program extracts data from the JIRA ZEPSEC security issues, and
generates CVE records in the CVE JSON format.  There are a handful of
specific requirements needed on the JIRA tickets for this to work
smoothly.  Some of these are in the form of special comments in the
description.  Others require that certain fields be filled in.
"""

import argparse
import json
import pprint
import re
import sys
import zepsec


def parse_args():
    global args

    parser = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('zepsec', nargs=1,
            help="ZEPSEC-nn issue to generate CVE from")

    args = parser.parse_args()


# Match the CVE marker in the description.  This is just a regex, so
# anything interesting will make this wrong.  Specifically, if there
# are multiple CVE markers, it will match all of the text between the
# first <CVE> and the last </CVE>.
CVE_RE = re.compile(r'<CVE>(.*)</CVE>', flags=re.M)


def build_desc(issue):
    """Build a description for this issue based on the description in
    the JIRA ticket.

    The description field is a free-form text field.  To make this
    practical, we look for a block delimited by <CVE>...</CVE> which
    will be used as the text of the CVE.  If this marker is not
    present, then we will raise an exception to indicate that the CVE
    summary should be indicated.  This is not a true markup, and
    must be filled in."""
    text = issue.fields['description']
    m = CVE_RE.match(text)
    if m is None:
        print("JIRA ticket description does not contain <CVE></CVE> block.")
        sys.exit(1)
    desc = m.group(1)
    return {
            "description_data": [
                {
                    "lang": "eng",
                    "value": desc,
                },
            ]
        }



class CVE(object):
    def __init__(self, issue):
        self.issue = issue

        self.subtasks = []

        for backport in self.issue.subtasks:
            # print(f"  -> {backport}")
            p = {}
            j = zepsec.query(f"issue/{backport}", None, params=p)
            self.subtasks.append(zepsec.Issue(j))

        # This metadata describes the format of the CVE itself.
        self.json = {
                "data_format": "MITRE",
                "data_type": "CVE",
                "data_version": "4.0",
                }

        self.json["CVE_data_meta"] = {
            "ASSIGNER": "vulnerabilities@zephyrproject.org",
            "DATE_PUBLIC": self.issue.embargo,  # TODO: Formatting
            "ID": self.issue.cve,
            "STATE": "PUBLIC",
            "TITLE": self.issue.summary,
        }

        # Collect all of the affects
        affects = set()
        self._add_fix(affects, self.issue)
        for backport in self.subtasks:
            self._add_fix(affects, backport)

        affects = CVE._decode_versions(affects)

        self.json["affects"] = {
                "vendor": {
                    "vendor_data": [
                        {
                            "product": {
                                "product_data": [
                                    {
                                        "product_name": "zephyr",
                                        "version": {
                                            "version_data": affects,
                                        },
                                    },
                                ],
                            },
                            "vendor_name": "zephyrproject-rtos",
                        },
                    ],
                },
            }

        # Many fields can be set from the information in the ticket.
        self.json['description'] = build_desc(issue)

        # Link back to the JIRA ticket.  We'll mark these as external,
        # since most are.  This could be flagged with labels or
        # something like that.
        self.json['source'] = {
            'defect': [f"https://zephyrprojectsec.atlassian.net/browse/{self.issue.key}"],
            'discovery': 'EXTERNAL',
        }

        self.references = []

        # Build the various references.  First is the link to the JIRA
        # ticket.
        self._add_reference(f"https://zephyrprojectsec.atlassian.net/browse/{self.issue.key}")

        # Next reference is to the release notes.
        lower_cve = self.issue.cve.lower()
        self._add_reference(f"https://docs.zephyrproject.org/latest/security/vulnerabilities.html#{lower_cve}")

        # Get all of the links.
        seen = set()
        for link in self.issue.getlinks():
            if link in seen:
                continue
            seen.add(link)
            if "github.com/zephyrproject-rtos" in link:
                self._add_reference(link)

        for child in self.subtasks:
            for link in child.getlinks():
                if link in seen:
                    continue
                seen.add(link)
                if "github.com/zephyrproject-rtos" in link:
                    self._add_reference(link)

    def get_json(self):
        self.json["references"] = {
            "reference_data": self.references,
        }
        return json.dumps(self.json, indent=4)

    def _add_fix(self, affects, issue):
        for ver in issue.versions:
            affects.add(ver['name'])

    def _decode_versions(vers):
        vers = list(vers)
        vers.sort()
        return [ CVE._decode_version(v) for v in vers ]

    def _decode_version(ver):
        return {
            "version_affected": ">=",
            "version_value": ver[1:]
        }

    def _add_reference(self, url):
        """Add the given url as a reference."""

        # These start out as "CONFIRM" until MITRE verifies the links, and
        # they will then convert to MISC.
        self.references.append({
            "refsource": "CONFIRM",
            "url": url,
            "name": url,
        })



def main():
    global args

    parse_args()

    issue_key = args.zepsec[0]

    # p = {'jql': f'issue="{issue_key}"'}
    p = {}
    j = zepsec.query(f"issue/{issue_key}", None, params=p)
    issue = zepsec.Issue(j)

    cv = CVE(issue)
    print(cv.get_json())

    # pp = pprint.PrettyPrinter()
    # pp.pprint(issue.__dict__)
    # print(issue.__dict__)

if __name__ == '__main__':
    main()
