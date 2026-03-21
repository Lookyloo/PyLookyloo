from __future__ import annotations

import argparse
import json
import sys

from typing import TypedDict, Any

if sys.version_info >= (3, 13):
    from warnings import deprecated
else:
    from deprecated import deprecated

from .api import Lookyloo, PyLookylooError, AuthError  # noqa


@deprecated("Use lookyloo-models instead, the Pydantic models.")
class CaptureSettings(TypedDict, total=False):
    '''The capture settings that can be passed to Lookyloo.'''

    url: str | None
    document_name: str | None
    document: str | None
    browser: str | None
    device_name: str | None
    user_agent: str | None
    proxy: str | dict[str, str] | None
    general_timeout_in_sec: int | None
    cookies: list[dict[str, Any]] | None
    storage: str | dict[str, Any] | None
    headers: str | dict[str, str] | None
    http_credentials: dict[str, int] | None
    geolocation: dict[str, float] | None
    timezone_id: str | None
    locale: str | None
    color_scheme: str | None
    java_script_enabled: bool
    viewport: dict[str, str | int] | None
    referer: str | None
    with_screenshot: bool
    with_favicon: bool
    allow_tracking: bool
    headless: bool
    init_script: str | None
    with_trusted_timestamps: bool
    final_wait: int | None

    # Lookyloo specific
    listing: bool | None
    auto_report: bool | dict[str, str] | None
    remote_lacus_name: str | None
    categories: list[str] | None
    monitor_capture: dict[str, str | bool] | None


@deprecated("Use lookyloo-models instead, the Pydantic models.")
class CompareSettings(TypedDict, total=False):
    '''The settings that can be passed to the compare method on lookyloo side to filter out some differences'''

    ressources_ignore_domains: list[str] | None
    ressources_ignore_regexes: list[str] | None


def main() -> None:
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


__all__ = ['Lookyloo', 'PyLookylooError', 'AuthError', 'CaptureSettings', 'CompareSettings']
