#! /usr/bin/env python3

from github import Github
from git import Git
import netrc
import os
import pickle
import pprint
import prettytable
import requests
import re


JIRA_HOST = 'zephyrprojectsec.atlassian.net'
BASEURL = f"https://{JIRA_HOST}/rest/api/2/"

# Zephyr JIRA custom field names.
CVE_FIELD = 'customfield_10035'
EMBARGO_FIELD = 'customfield_10051'

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


def get_remote_links(key):
    return query("issue/" + key + "/remotelink", 'unknown')


class Issue(object):
    def __init__(self, js):
        self.key = js["key"]
        fields = js["fields"]

        self.fixversion = fields["fixVersions"]
        self._status = fields["status"]
        self._issuetype = fields["issuetype"]
        if fields[CVE_FIELD] is not None:
            self.cve = fields[CVE_FIELD]
        else:
            self.cve = ""
        if fields[EMBARGO_FIELD] is not None:
            self.embargo = fields[EMBARGO_FIELD]
        else:
            self.embargo = ""

        self.subtasks = fields["subtasks"]
        self.summary = fields["summary"]
        self.fields = fields
        self.remotes = None

    def status(self):
        return self._status["name"]

    def issuetype(self):
        return self._issuetype["name"]

    def getlinks(self):
        if self.remotes is None:
            self.remotes = get_remote_links(self.key)
        return [x["object"]["url"] for x in self.remotes]


def main():
    pr_re = re.compile(
        r'^https://github.com/zephyrproject-rtos/zephyr/pull/(\d+)$')
    gh_token = get_auth('github.com')[1]
    gh = Github(gh_token)
    repo = gh.get_repo("zephyrproject-rtos/zephyr")
    zephyr_base = os.getenv("ZEPHYR_BASE")
    table = prettytable.PrettyTable()

    if zephyr_base is None:
        print("Environment variable ZEPHYR_BASE not set")
        exit(1)

    table.field_names = ['JIRA #', 'JIRA Status',
                         'Embargo', 'CVE', 'GH pr', 'Zephyr branch']

    p = {'jql': 'project="ZEPSEC"'}
    j = query("search", "issues", params=p)
    gitwork = Git(zephyr_base)

    issues = []
    for jissue in j:
        issue = Issue(jissue)
        issues.append(issue)

    # Filter out the issues that are "Public or Rejected".
    issues = [x for x in issues if (x.status() != "Public") and
              (x.status() != "Rejected")]

    for issue in issues:
        merged = ""
        issue_info = ""
        for link in issue.getlinks():
            issue_info += link
            m = pr_re.search(link)
            if m is not None:
                pr = int(m.group(1))
                gpr = repo.get_pull(pr)
                issue_info += " -> {}\n".format(gpr.state)
                issue_info += "{}\n".format(gpr.title)
                if gpr.merged:
                    merged = gitwork.describe(gpr.merge_commit_sha)
            else:
                issue_info += " -> Invalid\n"

        if issue.issuetype() == "Backport":
            issue.key += "\n{}".format("Backport")

        table.add_row([issue.key, issue.status(), issue.embargo,
                       issue.cve, issue_info, merged])

    table.hrules = prettytable.ALL
    print(table)


if __name__ == '__main__':
    main()
