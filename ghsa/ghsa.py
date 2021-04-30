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

import argparse
from bs4 import BeautifulSoup
import http.cookiejar
import requests
import re


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

    def fetch_1_index(self, state, page):
        payload = {'page': str(page), 'state': state}
        r = requests.get(self.__url(state, page), params=payload)

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
            print(m.group(1))
            result.append(m.group(1))

        return result

    def fetch_index(self, state):
        result = []
        page = 1
        while True:
            items = self.fetch_1_index(state, page=page)
            if len(items) == 0:
                break
            result.extend(items)
            page += 1
        return result

    def __url(self, state, page):
        return "https://github.com/zephyrproject-rtos/zephyr/security/advisories"


def main():
    app = App()

    adv = app.fetch_index(state='published')
    print(adv)


if __name__ == '__main__':
    main()
