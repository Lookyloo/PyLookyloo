#!/usr/bin/env python3

import argparse
import time

from pathlib import Path
from sys import exit

import requests

from pylookyloo import Lookyloo


def capture_done(lookyloo: Lookyloo, uuid: str) -> bool:
    """Check the status of a capture and print the result."""
    try:
        status = lookyloo.get_status(uuid)
        if status['status_code'] in [-1, 1]:
            return True
        return False

    except Exception as e:
        print(f"Error checking status for {uuid}: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description='Enqueue URLs from a file to Lookyloo.')
    parser.add_argument('--url', default="https://lookyloo.circl.lu/", type=str, help='URL of the instance (defaults to https://lookyloo.circl.lu/, the public instance).')
    parser.add_argument('--nice', type=int, default=100, help='Submit N captures at a time, and wait for them to finish before sending more.')
    parser.add_argument('file', type=Path, help='File containing the list of URLs to enqueue.')
    args = parser.parse_args()

    if not args.file.exists():
        print(f"{args.file} does not exist.")
        exit(1)

    with args.file.open() as f:
        urls = {line.strip() for line in f.readlines()}

    print('To process:', len(urls))

    lookyloo = Lookyloo(args.url)

    ongoing: dict[str, str] = {}
    for url in urls:
        while len(ongoing) >= args.nice:
            print(f'Waiting for {len(ongoing)} captures to finish...')
            for uuid in list(ongoing.keys()):
                if capture_done(lookyloo, uuid):
                    print(f'Capture {uuid} done.')
                    del ongoing[uuid]
            time.sleep(5)

        try:
            response = requests.head(url, allow_redirects=True, timeout=3)
            response.raise_for_status()
            uuid = lookyloo.submit(url=url, listing=True, quiet=True)
            ongoing[uuid] = url
            print(f'Enqueued: {url} - Permaurl: {args.url}/tree/{uuid}')
        except Exception as e:
            print(f"{url} is down: {e}")


if __name__ == '__main__':
    main()
