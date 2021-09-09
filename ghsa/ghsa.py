#! /usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2021 Linaro Limited

"""
Process CVE information based on data from GHSA.

The Github Security Advisories (GHSA) contain all of the information
needed to update the Mitre CVE database.  However, at the time of this
writing, Github does not have an API for this information.  Therefore,
it is necessary to extract this information from the HTML web pages.

In order to do this, we need access to cookies from an authenticated
web session to github.  One way to do this is to use an add-on "Export
Cookies" for Firefox.  There should be something similar for Chrome.
"""

import cvejson
import argparse
from bs4 import BeautifulSoup
import http.cookiejar
import os
import requests
import re


def splitver(text):
    return text.split(", ")


#class CVSS():
#    """Conversions between the raw CVSS string and the expanded JSON
#    values used in the CVE."""
#    def __init__(self, pri, raw):
#        """Create a CVSS indicator.  The pri should be from github,
#        and be of the form "n.m Medium".  The score will be used
#        directly in the JSON.  The RAW data should be of the form
#        "CVSS:3.1/AV:P..."."""
#        pri = pri.split(' ')
#        self.score = pri[0]
#        self.severity = pri[1].upper()
#        fields = raw.split('/')
#        assert fields[0] == "CVSS:3.1"
#        self.fields = [f.split(':') for f in fields[1:]]
#        print("score", self.score)
#        print("severity", self.severity)
#        print("fields", self.fields)


class App():
    def __init__(self):
        parser = argparse.ArgumentParser(
                description=__doc__,
                formatter_class=argparse.RawDescriptionHelpFormatter)

        parser.add_argument('--mozilla-cookies', nargs=1,
                help="Cookie file")

        self.args = parser.parse_args()

        if self.args.mozilla_cookies is not None:
            self.cookies = http.cookiejar.MozillaCookieJar(self.args.mozilla_cookies[0])
            self.cookies.load()
        else:
            raise Exception("Must specify cookie file")

        self.ghsa_re = re.compile(r'^/.*/.*/security/advisories/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$')
        self.fix_re = re.compile(r'^- v(\d+(\.\d+)+): (#(\d+)|TBD).*$', re.M)
        self.embargo_re = re.compile(r'^embargo: (\d{4}-\d{2}-\d{2}).*$', re.M)

    def fetch_1_index(self, state, page):
        params = {'page': str(page), 'state': state}
        r = requests.get(self.__url(), params=params, cookies=self.cookies)

        # with open('index-{}-{}.html'.format(state, page), 'w') as fd:
        #     fd.write(r.text)

        soup = BeautifulSoup(r.text, 'html.parser')
        e = soup.select('a')
        result = []
        for elt in e:
            attrs = elt.attrs
            if 'href' not in attrs:
                continue
            m = self.ghsa_re.match(attrs['href'])
            if m is None:
                continue
            # print(m.group(1))
            result.append(m.group(1))

        return result

    def fetch_index(self, state):
        result = []
        page = 1
        while True:
            items = self.fetch_1_index(state=state, page=page)
            if len(items) == 0:
                break
            result.extend(items)
            page += 1
        return result

    def fetch_ghsa(self, ghsa):
        """
        Attempt to fetch and decode a GHSA.  If we have an error or
        permission problems, can return None.
        """
        url = self.__url() + '/' + ghsa
        r = requests.get(url, cookies=self.cookies)
        # print(r.text)

        # Write contents to a file, to help with manual parsing.
        # with open(ghsa + '.html', 'w') as fd:
        #     fd.write(r.text)

        fields = {}

        soup = BeautifulSoup(r.text, 'html.parser')

        # GHSA number.  To verify we got a page.
        # e = soup.select('div.js-details-container div.TableObject-item--primary span')
        e = soup.select('div.TableObject-item--primary span')
        assert len(e) == 1
        e = e[0].contents
        assert len(e) == 1
        fields['ghsa'] = e[0]
        assert fields['ghsa'] == ghsa

        # Affects and fixed versions.
        e = soup.select('div.f4')
        assert len(e) == 2
        assert len(e[0].contents) == 1
        assert len(e[1].contents) == 1
        fields['affects'] = splitver(e[0].contents[0])
        fields['fixed'] = splitver(e[1].contents[0])

        e = soup.select('h1.gh-header-title')
        assert len(e) == 1
        e = e[0].contents
        assert len(e) == 1
        fields['title'] = e[0].strip()

        e = soup.select('div.pl-md-4 div.pt-2')
        assert len(e) == 2
        fields['cve'] = e[0].contents[0]
        fields['cvss-pri'] = e[1].contents[0]

        e = soup.select('div.pl-md-4 div.pt-1')
        assert len(e) == 1
        fields['cvss'] = e[0].contents[0]

        e = soup.select('textarea[name="repository_advisory[description]"]')
        assert len(e) == 1
        assert len(e[0].contents) == 1
        fields['description'] = e[0].contents[0]

        e = soup.select('div.js-cwe-list span')
        assert len(e) % 2 == 0
        res = []
        for i in range(0, len(e), 2):
            desc = e[i].contents
            assert len(desc) == 1
            tag = e[i+1].contents
            assert len(tag) == 1
            res.append("{} {}".format(desc[0], tag[0]))
        fields['cwe'] = res

        # Several fields aren't present in the raw GHSA, but we can
        # extract the data from specially formatted comments.
        fields['patches'] = []
        for m in self.fix_re.finditer(fields['description']):
            fields['patches'].append((m.group(1), m.group(3)))

        m = self.embargo_re.search(fields['description'])
        if m is not None:
            fields['embargo'] = m.group(1)

        return fields

    def __url(self):
        return "https://github.com/zephyrproject-rtos/zephyr/security/advisories"


def pathof(cve):
    """Generate a pathname for this CVE."""
    # print(cve)
    year = cve[4:8]
    # print(year)
    num = cve[9:]
    # print(num)
    sub = num[:-3] + 'xxx'
    os.makedirs(year + '/' + sub, exist_ok=True)
    return year + '/' + sub + '/' + cve + '.json'

def main():
    app = App()

    adv = app.fetch_index(state='published')
    # adv = app.fetch_index(state='draft')
    # print(adv)
    for gh in adv:
        print("Fetching", gh)
        g0 = app.fetch_ghsa(gh)
        # print(g0['cve'])

        build = cvejson.CveBuilder()
        build.ghsa = g0['ghsa']
        build.cve_id = g0['cve']
        build.public_date = g0['embargo']
        build.title = g0['title']
        build.versions = g0['affects']
        build.thanks = []
        build.description = g0['description']
        build.source = "https://github.com/zephyrproject-rtos/zephyr/security/advisories/" + g0['ghsa']
        build.cvss = g0['cvss']
        build.cwe = g0['cwe']
        # for k, v in g0.items():
        #     print(k, "->", v)
        # cvss = CVSS(g0['cvss-pri'], g0['cvss'])
        with open(pathof(g0['cve']), 'w') as fd:
            fd.write(build.to_json())


if __name__ == '__main__':
    main()
