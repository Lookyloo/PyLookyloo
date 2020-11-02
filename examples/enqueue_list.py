#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from sys import exit

import requests

from pylookyloo import Lookyloo

"""
Get all the URLs from a file, check if they are still working (return code <400) Push them to lookyloo.
"""

list_urls_file = Path('list.txt')
lookyloo_url = "https://lookyloo.circl.lu/"


if not list_urls_file.exists():
    print(list_urls_file, 'does not exists')
    exit()

with list_urls_file.open() as f:
    urls = set(line.strip() for line in f.readlines())

print('To process:', len(urls))

lookyloo = Lookyloo(lookyloo_url)

for url in urls:
    try:
        print(url)
        response = requests.head(url, allow_redirects=True, timeout=3)
        response.raise_for_status()
        permaurl = lookyloo.enqueue(url, listing=True)
        print(f'Enqueued: {url} - Permaurl: {permaurl}')
    except Exception as e:
        print(f"{url} is down: {e}")
