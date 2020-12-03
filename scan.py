#! /usr/bin/env python3
#
# Copyright (c) 2020 Linaro Limited
# Copyright (c) 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

from github import Github
from git import Git
import argparse
import os
import prettytable
import re
import zepsec


def parse_args():
    global args

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-r", "--release", required=False, action="store_true",
                        help="Generate a report for release manager consumption")
    parser.add_argument("-H", "--html", required=False, action="store_true",
                        help="Generate a report in HTML")
    args = parser.parse_args()


def generate_table(issues, zephyr_base, release = False, html = False) -> str:
    gh_token = zepsec.get_auth('github.com')[1]
    gh = Github(gh_token)
    repo = gh.get_repo("zephyrproject-rtos/zephyr")
    table = prettytable.PrettyTable()

    table.field_names = ['JIRA #', 'JIRA Status',
                         'Embargo', 'CVE', 'GH pr', 'Zephyr branch']
    pr_re = re.compile(
        r'^https://github.com/zephyrproject-rtos/zephyr/pull/(\d+)$')
    gitwork = Git(zephyr_base)

    for issue in issues:
        merged = ""
        issue_info = ""
        links = issue.getlinks()
        issue_released = False

        if release and not links:
            continue

        for link in links:
            issue_info += link
            m = pr_re.search(link)
            if m is not None:
                pr = int(m.group(1))
                gpr = repo.get_pull(pr)
                issue_info += " -> {}\n".format(gpr.state)
                issue_info += "{}\n".format(gpr.title)
                if gpr.merged:
                    merged = gitwork.describe(gpr.merge_commit_sha)
                    try:
                        m2 = gitwork.describe(gpr.merge_commit_sha, contains=True)
                        issue_released = True
                        merged += "\n" + m2
                    except:
                        pass
            else:
                issue_info += " -> Invalid\n"

        if issue_released and release:
            continue

        if issue.issuetype() == "Backport":
            issue.key += "\nB({})".format(issue.parent.key)

        embargo = ""
        if issue.embargo != "":
            embargo = issue.embargo
        elif issue.parent:
            embargo = issue.parent.embargo

        table.add_row([issue.key, issue.status(), embargo,
                       issue.cve, issue_info, merged])

    table.hrules = prettytable.ALL
    table.format = True

    if html:
        get_contents = table.get_html_string
    else:
        get_contents = table.get_string

    if release:
        table_contents = get_contents(fields=["Embargo", "GH pr", "Zephyr branch"])
    else:
        table_contents = get_contents()

    return table_contents


def main():
    parse_args()

    zephyr_base = os.getenv("ZEPHYR_BASE")

    if zephyr_base is None:
        print("Environment variable ZEPHYR_BASE not set")
        exit(1)

    p = {'jql': 'project="ZEPSEC"'}
    j = zepsec.query("search", "issues", params=p)

    issues = []
    for jissue in j:
        issue = zepsec.Issue(jissue)
        issues.append(issue)

    parentage = zepsec.Parentage(issues)

    # Filter out the issues that are "Public or Rejected".
    issues = [x for x in issues if (x.status() != "Public") and
              (x.status() != "Rejected")]

    parentage.sort(issues)
    parentage.fill_parents(issues)

    print(generate_table(issues, zephyr_base, args.release, args.html))


if __name__ == '__main__':
    main()
