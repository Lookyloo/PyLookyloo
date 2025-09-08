#!/usr/bin/env python3

from __future__ import annotations

import os
import base64
import warnings

from datetime import datetime
from hashlib import sha512
from importlib.metadata import version
from io import BytesIO, StringIO
from typing import Any, TypedDict, overload, Literal
from urllib.parse import urljoin, urlparse
from pathlib import PurePosixPath, Path

import requests

from urllib3.util import Retry
from requests.adapters import HTTPAdapter
from requests.sessions import Session
from requests.status_codes import codes


class SafeRedirectRePOSTSession(Session):

    def rebuild_method(self, prepared_request: requests.PreparedRequest, response: requests.Response) -> None:
        # This method will resubmit a POST when we have a http -> https redirect
        if response.status_code == codes.moved and prepared_request.method == 'POST':
            # make sure it is just a redirect http->https and we're not going to a different host
            prec_url = urlparse(response.url)
            next_url = urlparse(prepared_request.url)

            if (prec_url.netloc != next_url.netloc or prec_url.scheme != 'http'
                    or next_url.scheme != 'https'):
                super().rebuild_method(prepared_request, response)
            else:
                # For surely good reasons, requests force-remove the body of the redirected requests unless the statuscode is either 307 or 308
                # https://github.com/psf/requests/issues/1084
                # Doing that makes sure we keep it
                response.status_code = 307
        else:
            super().rebuild_method(prepared_request, response)


class PyLookylooError(Exception):
    pass


class AuthError(PyLookylooError):
    pass


class CaptureSettings(TypedDict, total=False):
    '''The capture settings that can be passed to Lookyloo.'''

    url: str | None
    document_name: str | None
    document: str | None
    browser: str | None
    device_name: str | None
    user_agent: str | None
    proxy: str | dict[str, str] | None
    remote_lacus_name: str | None
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
    with_trusted_timestamps: bool
    headless: bool
    viewport: dict[str, int] | None
    referer: str | None

    listing: bool | None
    auto_report: bool | dict[str, str] | None


class CompareSettings(TypedDict, total=False):
    '''The settings that can be passed to the compare method on lookyloo side to filter out some differences'''

    ressources_ignore_domains: list[str] | None
    ressources_ignore_regexes: list[str] | None


class Lookyloo():

    def __init__(self, root_url: str | None=None, useragent: str | None=None,
                 *, proxies: dict[str, str] | None=None, verify: bool | str=True) -> None:
        '''Query a specific lookyloo instance.

        :param root_url: URL of the instance to query.
        :param useragent: The User Agent used by requests to run the HTTP requests against Lookyloo, it is *not* passed to the captures.
        :param proxies: The proxies to use to connect to lookyloo (not the ones given to the capture itself) - More details: https://requests.readthedocs.io/en/latest/user/advanced/#proxies
        '''
        self.root_url = root_url if root_url else 'https://lookyloo.circl.lu/'
        self.apikey: str | None = None

        if not urlparse(self.root_url).scheme:
            self.root_url = 'http://' + self.root_url
        if not self.root_url.endswith('/'):
            self.root_url += '/'
        self.session = SafeRedirectRePOSTSession()
        self.session.headers['user-agent'] = useragent if useragent else f'PyLookyloo / {version("pylookyloo")}'
        if proxies:
            self.session.proxies.update(proxies)
        retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.verify = verify

    @property
    def is_up(self) -> bool:
        '''Test if the given instance is accessible'''
        try:
            r = self.session.head(self.root_url)
        except requests.exceptions.ConnectionError:
            return False
        return r.status_code == 200

    def get_status(self, tree_uuid: str) -> dict[str, Any]:
        '''Get the status of a capture:
            * -1: Unknown capture.
            * 0: The capture is queued up but not processed yet.
            * 1: The capture is ready.
            * 2: The capture is ongoing and will be ready soon.
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'status'))))
        return r.json()

    def get_remote_lacuses(self) -> list[dict[str, Any]]:
        '''Get the list of Lacus instances configured on the Lookyloo instance'''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', 'remote_lacuses'))))
        return r.json()

    def get_capture_stats(self, tree_uuid: str) -> dict[str, Any]:
        '''Get statistics of the capture'''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'stats'))))
        return r.json()

    def get_info(self, tree_uuid: str) -> dict[str, Any]:
        '''Get information about the capture (url, timestamp, user agent)'''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'info'))))
        return r.json()

    def get_comparables(self, tree_uuid: str) -> dict[str, Any]:
        '''Get comparable information from the capture'''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'comparables'))))
        return r.json()

    def enqueue(self, url: str | None=None, quiet: bool=False,  # type: ignore[no-untyped-def]
                document: Path | BytesIO | None=None,
                document_name: str | None=None, **kwargs) -> str:
        '''Enqueue an URL.

        :param url: URL to enqueue
        :param quiet: Returns the UUID only, instead of the whole URL
        :param document: A document to submit to Lookyloo. It can be anything suported by a browser.
        :param document_name: The name of the document (only if you passed a pseudofile).
        :param kwargs: accepts all the parameters supported by `Lookyloo.capture`
        '''
        warnings.warn('Please use submit instead.', DeprecationWarning, stacklevel=2)
        return self.submit(quiet=quiet, url=url, document=document, document_name=document_name,
                           **kwargs)

    @overload
    def submit(self, *, quiet: bool=False,
               capture_settings: CaptureSettings | None=None) -> str:
        ...

    @overload
    def submit(self, *, quiet: bool=False,
               url: str | None=None,
               document_name: str | None=None, document: Path | BytesIO | None=None,
               browser: str | None=None, device_name: str | None=None,
               user_agent: str | None=None,
               proxy: str | dict[str, str] | None=None,
               remote_lacus_name: str | None=None,
               general_timeout_in_sec: int | None=None,
               cookies: list[dict[str, Any]] | None=None,
               storage: str | dict[str, Any] | None=None,
               headers: str | dict[str, str] | None=None,
               http_credentials: dict[str, int] | None=None,
               geolocation: dict[str, float] | None=None,
               timezone_id: str | None=None,
               locale: str | None=None,
               color_scheme: str | None=None,
               java_script_enabled: bool=True,
               with_trusted_timestamps: bool=False,
               headless: bool=True,
               viewport: dict[str, int] | None=None,
               referer: str | None=None,
               listing: bool | None=None,
               auto_report: bool | dict[str, str] | None=None
               ) -> str:
        ...

    def submit(self, *, quiet: bool=False,
               capture_settings: CaptureSettings | None=None,
               url: str | None=None,
               document_name: str | None=None, document: Path | BytesIO | None=None,
               browser: str | None=None, device_name: str | None=None,
               user_agent: str | None=None,
               proxy: str | dict[str, str] | None=None,
               remote_lacus_name: str | None=None,
               general_timeout_in_sec: int | None=None,
               cookies: list[dict[str, Any]] | None=None,
               storage: str | dict[str, Any] | None=None,
               headers: str | dict[str, str] | None=None,
               http_credentials: dict[str, int] | None=None,
               geolocation: dict[str, float] | None=None,
               timezone_id: str | None=None,
               locale: str | None=None,
               color_scheme: str | None=None,
               java_script_enabled: bool | None=None,
               with_trusted_timestamps: bool=False,
               headless: bool=True,
               viewport: dict[str, int] | None=None,
               referer: str | None=None,
               listing: bool | None=None,
               auto_report: bool | dict[str, str] | None=None
               ) -> str:
        '''Submit a URL to a lookyloo instance.

        :param quiet: Returns the UUID only, instead of the whole URL

        :param capture_settings: Settings as a dictionary. It overwrites all other parmeters.

        :param url: URL to capture (incompatible with document and document_name)
        :param document_name: Filename of the document to capture (required if document is used)
        :param document: Document to capture itself (requires a document_name)
        :param browser: The browser to use for the capture, must be something Playwright knows
        :param device_name: The name of the device, must be something Playwright knows
        :param user_agent: The user agent the browser will use for the capture
        :param proxy: Capture via a proxy. It can either be the full URL to a SOCKS5 proxy, or the name of a specific proxy configured on a remote lacus instance.
        :param remote_lacus_name: The name of the remote Lacus instance to use for the capture (only if lookyloo is configured this way)
        :param general_timeout_in_sec: The capture will raise a timeout it it takes more than that time
        :param cookies: A list of cookies
        :param headers: The headers to pass to the capture
        :param http_credentials: HTTP Credentials to pass to the capture
        :param geolocation: The geolocation of the browser latitude/longitude
        :param timezone_id: The timezone, warning, it m ust be a valid timezone (continent/city)
        :param locale: The locale of the browser
        :param color_scheme: The prefered color scheme of the browser (light or dark)
        :param java_script_enabled: If False, no JS will run during the capture.
        :param with_trusted_timestamps: If True, and a trusted timestamp provider is configured, trigger a request for trusted timestamps for forensic archival.
        :param headless: If False, the browser will be headed, it requires the capture to be done on a desktop.
        :param viewport: The viewport of the browser used for capturing
        :param referer: The referer URL for the capture
        :param listing: If False, the capture will be not be on the publicly accessible index page of lookyloo
        :param auto_report: If set, the capture will automatically be forwarded to an analyst (if the instance is configured this way)
                            Pass True if you want to autoreport without any setting, or a dictionary with two keys:
                                * email (required): the email of the submitter, so the analyst to get in touch
                                * comment (optional): a comment about the capture to help the analyst
        '''
        to_send: CaptureSettings
        if capture_settings:
            to_send = capture_settings
            if 'document' not in to_send and 'url' not in to_send:
                raise PyLookylooError('url or document are required')
        else:
            if not document and not url:
                raise PyLookylooError('url or document are required')
            if document:
                if isinstance(document, Path):
                    if not document_name:
                        document_name = document.name
                    with document.open('rb') as f:
                        document = BytesIO(f.read())
                b64_doc = base64.b64encode(document.getvalue()).decode()
                to_send = {'document': b64_doc, 'document_name': document_name}
            elif url:
                to_send = {'url': url}

            if browser:
                to_send['browser'] = browser
            if device_name:
                to_send['device_name'] = device_name
            if user_agent:
                to_send['user_agent'] = user_agent
            if proxy:
                to_send['proxy'] = proxy
            if general_timeout_in_sec is not None:  # that would be a terrible i
                to_send['general_timeout_in_sec'] = general_timeout_in_sec
            if cookies:
                to_send['cookies'] = cookies
            if storage:
                to_send['storage'] = storage
            if headers:
                to_send['headers'] = headers
            if http_credentials:
                to_send['http_credentials'] = http_credentials
            if geolocation:
                to_send['geolocation'] = geolocation
            if timezone_id:
                to_send['timezone_id'] = timezone_id
            if locale:
                to_send['locale'] = locale
            if color_scheme:
                to_send['color_scheme'] = color_scheme
            if java_script_enabled is not None:
                to_send['java_script_enabled'] = java_script_enabled
            if with_trusted_timestamps is not None:
                to_send['with_trusted_timestamps'] = with_trusted_timestamps
            if headless is not None:
                to_send['headless'] = headless
            if viewport:
                to_send['viewport'] = viewport
            if referer:
                to_send['referer'] = referer
            if listing is not None:
                to_send['listing'] = listing
            if auto_report:
                to_send['auto_report'] = auto_report

        response = self.session.post(urljoin(self.root_url, 'submit'), json=to_send)
        response.raise_for_status()
        uuid = response.json()
        if not uuid:
            raise PyLookylooError('Unable to get UUID from lookyloo instance.')
        if quiet:
            return uuid
        return urljoin(self.root_url, f'tree/{uuid}')

    def get_apikey(self, username: str, password: str) -> dict[str, str]:
        '''Get the API key for the given user.'''
        to_post = {'username': username, 'password': password}
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'get_token'))), json=to_post)
        return r.json()

    def init_apikey(self, username: str | None=None, password: str | None=None, apikey: str | None=None) -> None:
        '''Init the API key for the current session. All the requests against lookyloo after this call will be authenticated.'''
        if apikey:
            self.apikey = apikey
        elif username and password:
            t = self.get_apikey(username, password)
            if 'authkey' in t:
                self.apikey = t['authkey']
        else:
            raise AuthError('Username and password required')
        if self.apikey:
            self.session.headers['Authorization'] = self.apikey
        else:
            raise AuthError('Unable to initialize API key')

    def get_user_config(self) -> dict[str, Any] | None:
        '''Get the configuration enforced by the server for the current user (requires an authenticated user, use init_apikey first)
        '''
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', 'get_user_config'))))
        return r.json()

    def misp_export(self, tree_uuid: str) -> dict[str, Any]:
        '''Export the capture in MISP format'''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'misp_export'))))
        return r.json()

    def misp_push(self, tree_uuid: str) -> dict[str, Any] | list[dict[str, Any]]:
        '''Push the capture to a pre-configured MISP instance (requires an authenticated user, use init_apikey first)
        Note: if the response is a dict, it is an error mesage. If it is a list, it's a list of MISP event.
        '''
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'misp_push'))))
        return r.json()

    def trigger_modules(self, tree_uuid: str, force: bool=False) -> dict[str, Any]:
        '''Trigger all the available 3rd party modules on the given capture.
        :param force: Trigger the modules even if they were already triggered today.
        '''
        to_send = {'force': force}
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'trigger_modules'))),
                              json=to_send)
        return r.json()

    def rebuild_capture(self, tree_uuid: str) -> dict[str, str]:
        '''Force rebuild a capture (requires an authenticated user, use init_apikey first)'''
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('admin', tree_uuid, 'rebuild'))))
        return r.json()

    def hide_capture(self, tree_uuid: str) -> dict[str, str]:
        '''Hide a capture from the index page (requires an authenticated user, use init_apikey first)'''
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('admin', tree_uuid, 'hide'))))
        return r.json()

    def remove_capture(self, tree_uuid: str) -> dict[str, str]:
        '''Remove a capture, it will be impossible to get it by UUID (requires an authenticated user, use init_apikey first)'''
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('admin', tree_uuid, 'remove'))))
        return r.json()

    def get_favicons(self, capture_uuid: str) -> dict[str, Any]:
        '''Returns the potential favicons of the capture.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', capture_uuid, 'favicons'))))
        return r.json()

    def get_redirects(self, capture_uuid: str) -> dict[str, Any]:
        '''Returns the initial redirects.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', capture_uuid, 'redirects'))))
        return r.json()

    def get_urls(self, capture_uuid: str) -> dict[str, Any]:
        '''Returns all the URLs seen during the capture.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', capture_uuid, 'urls'))))
        return r.json()

    def get_hostnames(self, capture_uuid: str) -> dict[str, Any]:
        '''Returns all the hostnames seen during the capture.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', capture_uuid, 'hostnames'))))
        return r.json()

    def get_ips(self, capture_uuid: str) -> dict[str, Any]:
        '''Returns all the IPs seen during the capture.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', capture_uuid, 'ips'))))
        return r.json()

    def get_screenshot(self, capture_uuid: str) -> BytesIO:
        '''Returns the screenshot.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('bin', capture_uuid, 'screenshot'))))
        return BytesIO(r.content)

    def get_data(self, capture_uuid: str) -> BytesIO:
        '''Returns the downloaded data.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('bin', capture_uuid, 'data'))))
        return BytesIO(r.content)

    def get_cookies(self, capture_uuid: str) -> list[dict[str, str]]:
        '''Returns the complete cookies jar.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', capture_uuid, 'cookies'))))
        return r.json()

    def get_storage(self, capture_uuid: str) -> dict[str, Any]:
        '''Returns the complete storage state.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', capture_uuid, 'storage_state'))))
        return r.json()

    def get_html(self, capture_uuid: str) -> StringIO:
        '''Returns the rendered HTML as it would be in the browser after the page loaded.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('tree', capture_uuid, 'html'))))
        return StringIO(r.text)

    def get_hashes(self, capture_uuid: str, algorithm: str='sha512', hashes_only: bool=True) -> StringIO:
        '''Returns all the hashes of all the bodies (including the embedded contents)

        :param capture_uuid: UUID of the capture
        :param algorithm: The algorithm of the hashes
        :param hashes_only: If False, will also return the URLs related to the hashes
        '''
        params: dict[str, str | int] = {'algorithm': algorithm, 'hashes_only': int(hashes_only)}

        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', capture_uuid, 'hashes'))), params=params)
        return r.json()

    def get_complete_capture(self, capture_uuid: str) -> BytesIO:
        '''Returns a zip files that contains the screenshot, the har, the rendered HTML, and the cookies.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('bin', capture_uuid, 'export'))))
        return BytesIO(r.content)

    def get_hash_occurrences(self, h: str, *, with_urls_occurrences: bool=False, cached_captures_only: bool=True, limit: int=20, offset: int=0) -> dict[str, Any]:
        '''Returns the base64 body related the the hash, and a list of all the captures containing that hash.

        :param h: sha512 to search
        :param with_urls_occurrences: If true, add details about the URLs from the URL nodes in the tree.
        :param cached_captures_only: If False, Lookyloo will attempt to re-cache the missing captures. It might take some time.
        :param limit: The max amount of entries to return.
        :param offset: The offset to start from, useful for pagination.
        '''
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'hash_info'))),
                              json={'body_hash': h, 'with_urls_occurrences': with_urls_occurrences,
                                    'cached_captures_only': cached_captures_only, 'limit': limit, 'offset': offset})
        return r.json()

    def get_url_occurrences(self, url: str, *, with_urls_occurrences: bool=False, cached_captures_only: bool=True, limit: int=20, offset: int=0) -> dict[str, Any]:
        '''Returns all the captures contining the URL

        :param url: URL to lookup
        :param with_urls_occurrences: If true, add details about the URLs from the URL nodes in the tree.
        :param cached_captures_only: If False, Lookyloo will attempt to re-cache the missing captures. It might take some time.
        :param limit: The max amount of entries to return.
        :param offset: The offset to start from, useful for pagination.
        '''
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'url_info'))),
                              json={'url': url, 'with_urls_occurrences': with_urls_occurrences,
                                    'cached_captures_only': cached_captures_only,
                                    'limit': limit, 'offset': offset})
        return r.json()

    def get_hostname_occurrences(self, hostname: str, *, with_urls_occurrences: bool=False, cached_captures_only: bool=True, limit: int=20, offset: int=0) -> dict[str, Any]:
        '''Returns all the captures contining the hostname.

        :param hostname: Hostname to lookup
        :param with_urls_occurrences: If true, add details about the related URLs.
        :param cached_captures_only: If False, Lookyloo will attempt to re-cache the missing captures. It might take some time.
        :param limit: The max amount of entries to return.
        :param offset: The offset to start from, useful for pagination.
        '''
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'hostname_info'))),
                              json={'hostname': hostname, 'with_urls_occurrences': with_urls_occurrences,
                                    'cached_captures_only': cached_captures_only,
                                    'limit': limit, 'offset': offset})
        return r.json()

    def get_ip_occurrences(self, ip: str, *, with_urls_occurrences: bool=False, cached_captures_only: bool=True, limit: int=20, offset: int=0) -> dict[str, Any]:
        '''Returns all the captures containing the IP address.

        :param ip: IP to lookup
        :param with_urls_occurrences: If true, add details about the related URLs.
        :param cached_captures_only: If False, Lookyloo will attempt to re-cache the missing captures. It might take some time.
        :param limit: The max amount of entries to return.
        :param offset: The offset to start from, useful for pagination.
        '''
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'ip_info'))),
                              json={'ip': ip, 'with_urls_occurrences': with_urls_occurrences,
                                    'cached_captures_only': cached_captures_only,
                                    'limit': limit})
        return r.json()

    def get_favicon_occurrences(self, favicon: str | BytesIO, *, cached_captures_only: bool=True, limit: int=20, offset: int=0) -> dict[str, Any]:
        '''Returns all the captures containing the favicon.

        :param favicon: Favicon to lookup. Either the hash, or the file in a BytesIO (hash will be generated on the fly)
        :param cached_captures_only: If False, Lookyloo will attempt to re-cache the missing captures. It might take some time.
        :param limit: The max amount of entries to return.
        :param offset: The offset to start from, useful for pagination.
        '''
        if isinstance(favicon, BytesIO):
            favicon = sha512(favicon.read()).hexdigest()
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'favicon_info'))),
                              json={'favicon': favicon, 'cached_captures_only': cached_captures_only,
                                    'limit': limit, 'offset': offset})
        return r.json()

    def get_stats(self) -> dict[str, Any]:
        '''Returns all the captures contining the URL'''

        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', 'stats'))))
        return r.json()

    @overload
    def get_takedown_information(self, capture_uuid: str, filter_contacts: Literal[True]) -> list[str]:
        ...

    @overload
    def get_takedown_information(self, capture_uuid: str, filter_contacts: Literal[False]=False) -> list[dict[str, Any]]:
        ...

    def get_takedown_information(self, capture_uuid: str, filter_contacts: bool=False) -> list[dict[str, Any]] | list[str]:
        '''Returns information required to request a takedown for a capture

        :param capture_uuid: UUID of the capture
        :param filter_contacts: If True, will only return the contact emails and filter out the invalid ones.
        '''
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'takedown'))),
                              json={'capture_uuid': capture_uuid, 'filter': filter_contacts})
        return r.json()

    def compare_captures(self, capture_left: str, capture_right: str, /, *, compare_settings: CompareSettings | None=None) -> dict[str, Any]:
        '''Compares two captures

        :param capture_left: UUID of the capture to compare from
        :param capture_right: UUID of the capture to compare to
        :param compare_settings: The settings for the comparison itself (what to ignore without marking the captures as different)
        '''
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'compare_captures'))),
                              json={'capture_left': capture_left,
                                    'capture_right': capture_right,
                                    'compare_settings': compare_settings})
        return r.json()

    def get_modules_responses(self, tree_uuid: str) -> dict[str, Any]:
        '''Returns information from the 3rd party modules

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'modules'))))
        return r.json()

    def send_mail(self, tree_uuid: str, email: str = '', comment: str | None = None) -> bool | dict[str, Any]:
        '''Reports a capture by sending an email to the investigation team

        :param tree_uuid: UUID of the capture
        :param email: Email of the reporter, used by the analyst to get in touch
        :param comment: Description of the URL, will be given to the analyst
        '''
        to_send = {'email': email}
        if comment:
            to_send['comment'] = comment
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', tree_uuid, 'report'))), json=to_send)
        return r.json()

    def get_recent_captures(self, timestamp: str | datetime | float | None=None) -> list[str]:
        '''Gets the uuids of the most recent captures

        :param timestamp: Oldest timestamp to consider
        '''
        if timestamp:
            if isinstance(timestamp, datetime):
                timestamp = timestamp.timestamp()
            url = urljoin(self.root_url, str(PurePosixPath('json', 'recent_captures', str(timestamp))))
        else:
            url = urljoin(self.root_url, str(PurePosixPath('json', 'recent_captures')))
        r = self.session.get(url)
        return r.json()

    def get_categories_captures(self, category: str | None=None) -> list[str] | dict[str, list[str]] | None:
        '''Get uuids for a specific category or all categorized uuids if category is None

        :param category: The category according to which the uuids are to be returned
        '''
        if category:
            url = urljoin(self.root_url, str(PurePosixPath('json', 'categories', category)))
        else:
            url = urljoin(self.root_url, str(PurePosixPath('json', 'categories')))
        r = self.session.get(url)
        return r.json()

    def push_from_lacus(self, capture: dict[str, Any]) -> dict[str, Any]:
        '''Push a capture from Lacus to Lookyloo

        :param capture: The capture to push from Lacus
        '''
        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'upload'))), json=capture)
        return r.json()

    @overload
    def upload_capture(self, *, quiet: Literal[True],
                       listing: bool = False,
                       full_capture: Path | BytesIO | str | None = None,
                       har: Path | BytesIO | str | None = None,
                       html: Path | BytesIO | str | None = None,
                       last_redirected_url: str | None = None,
                       screenshot: Path | BytesIO | str | None = None) -> str:
        ...

    @overload
    def upload_capture(self, *, quiet: Literal[False]=False,
                       listing: bool = False,
                       full_capture: Path | BytesIO | str | None = None,
                       har: Path | BytesIO | str | None = None,
                       html: Path | BytesIO | str | None = None,
                       last_redirected_url: str | None = None,
                       screenshot: Path | BytesIO | str | None = None) -> tuple[str, dict[str, str]]:
        ...

    def upload_capture(self, *, quiet: bool = False,
                       listing: bool = False,
                       full_capture: Path | BytesIO | str | None = None,
                       har: Path | BytesIO | str | None = None,
                       html: Path | BytesIO | str | None = None,
                       last_redirected_url: str | None = None,
                       screenshot: Path | BytesIO | str | None = None) -> str | tuple[str, dict[str, str]]:
        '''Upload a capture via har-file and others

        :param quiet: Returns the UUID only, instead of the the UUID and the potential error / warning messages
        :param listing: if true the capture should be public, else private - overwritten if the full_capture is given and it contains no_index
        :param full_capture: path to the capture made by another instance
        :param har: Harfile of the capture
        :param html: rendered HTML of the capture
        :param last_redirected_url: The landing page of the capture
        :param screenshot: Screenshot of the capture
        '''
        def encode_document(document: Path | BytesIO | str) -> str:
            if isinstance(document, str):
                if not os.path.exists(document):
                    raise FileNotFoundError(f'{document} does not exist')
                document = Path(document)
            if isinstance(document, Path):
                with document.open('rb') as f:
                    document = BytesIO(f.read())
            return base64.b64encode(document.getvalue()).decode()

        to_send: dict[str, Any] = {'listing': listing}

        if full_capture:
            b64_full_capture = encode_document(full_capture)
            to_send['full_capture'] = b64_full_capture
        elif har:
            b64_har = encode_document(har)
            to_send['har_file'] = b64_har

            if html:
                b64_html = encode_document(html)
                to_send['html_file'] = b64_html

            if last_redirected_url:
                to_send['landing_page'] = last_redirected_url

            if screenshot:
                b64_screenshot = encode_document(screenshot)
                to_send['screenshot_file'] = b64_screenshot
        else:
            raise PyLookylooError("Full capture or at least har-file are required")

        r = self.session.post(urljoin(self.root_url, str(PurePosixPath('json', 'upload'))), json=to_send)
        r.raise_for_status()
        json_response = r.json()
        uuid = json_response['uuid']
        messages = json_response['messages']

        if not uuid:
            raise PyLookylooError('Unable to get UUID from lookyloo instance.')
        if quiet:
            return uuid
        return uuid, messages
