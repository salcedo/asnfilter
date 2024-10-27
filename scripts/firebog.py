#!/usr/bin/env python
#
# scrape WaLLy3K's Big Blocklist Collection
# return Lists bulleted with a tick have no notable false positives
#

import requests

from bs4 import BeautifulSoup


def main():
    soup = BeautifulSoup(
        requests.get('https://wally3k.github.io').text,
        'html.parser'
    )

    for li in soup.find_all('li', class_='bdTick'):
        count = 0
        for a in li.children:
            count += 1
            if count == 2:
                print(a.get('href'))


if __name__ == '__main__':
    main()
