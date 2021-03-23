import argparse
import json

from .api import Lookyloo


def main():
    parser = argparse.ArgumentParser(description='Enqueue a URL on Lookyloo.', epilog='The capture UUIDs you will receive can be used as permaurls (https://<domain>/tree/<uuid>).')
    parser.add_argument('--url', type=str, help='URL of the instance (defaults to https://lookyloo.circl.lu/, the public instance).')
    parser.add_argument('--query', help='URL to enqueue. The response is the permanent URL where you can see the result of the capture.')
    parser.add_argument('--listing', default=False, action='store_true', help='Should the report be publicly listed.')
    parser.add_argument('--redirects', help='Get redirects for a given capture (parameter is a capture UUID).')
    parser.add_argument('--search-url', help='Get most recent captures containing that URL.')
    parser.add_argument('--search-hostname', help='Get most recent captures containing that hostname.')
    args = parser.parse_args()

    if args.url:
        lookyloo = Lookyloo(args.url)
    else:
        lookyloo = Lookyloo()

    if lookyloo.is_up:
        if args.query:
            url = lookyloo.enqueue(args.query, listing=args.listing)
            print(url)
        else:
            if args.redirects:
                response = lookyloo.get_redirects(args.redirects)
            elif args.search_url:
                response = lookyloo.get_url_occurrences(args.search_url)
            elif args.search_hostname:
                response = lookyloo.get_hostname_occurrences(args.search_hostname)
            else:
                raise Exception('No query given.')
            print(json.dumps(response))
    else:
        print(f'Unable to reach {lookyloo.root_url}. Is the server up?')
