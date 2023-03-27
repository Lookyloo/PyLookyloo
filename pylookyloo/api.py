#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import warnings

from importlib.metadata import version
from io import BytesIO, StringIO
from typing import Optional, Dict, Any, List, Union, TypedDict, overload
from urllib.parse import urljoin, urlparse
from pathlib import Path

import requests


class PyLookylooError(Exception):
    pass


class AuthError(PyLookylooError):
    pass


class CaptureSettings(TypedDict, total=False):
    '''The capture settings that can be passed to Lookyloo.'''

    url: Optional[str]
    document_name: Optional[str]
    document: Optional[str]
    browser: Optional[str]
    device_name: Optional[str]
    user_agent: Optional[str]
    proxy: Optional[Union[str, Dict[str, str]]]
    general_timeout_in_sec: Optional[int]
    cookies: Optional[List[Dict[str, Any]]]
    headers: Optional[Union[str, Dict[str, str]]]
    http_credentials: Optional[Dict[str, int]]
    viewport: Optional[Dict[str, int]]
    referer: Optional[str]

    listing: Optional[bool]


class CompareSettings(TypedDict, total=False):
    '''The settings that can be passed to the compare method on lookyloo side to filter out some differences'''

    ressources_ignore_domains: Optional[List[str]]
    ressources_ignore_regexes: Optional[List[str]]


class Lookyloo():

    def __init__(self, root_url: str='https://lookyloo.circl.lu/', useragent: Optional[str]=None):
        '''Query a specific lookyloo instance.

        :param root_url: URL of the instance to query.
        :param useragent: The User Agent used by requests to run the HTTP requests against Lookyloo, it is *not* passed to the captures.
        '''
        self.root_url = root_url

        if not urlparse(self.root_url).scheme:
            self.root_url = 'http://' + self.root_url
        if not self.root_url.endswith('/'):
            self.root_url += '/'
        self.session = requests.session()
        self.session.headers['user-agent'] = useragent if useragent else f'PyLookyloo / {version("pylookyloo")}'
        self.apikey: Optional[str] = None

    @property
    def is_up(self) -> bool:
        '''Test if the given instance is accessible'''
        try:
            r = self.session.head(self.root_url)
        except requests.exceptions.ConnectionError:
            return False
        return r.status_code == 200

    def get_status(self, tree_uuid: str) -> Dict[str, Any]:
        '''Get the status of a capture:
            * -1: Unknown capture.
            * 0: The capture is queued up but not processed yet.
            * 1: The capture is ready.
            * 2: The capture is ongoing and will be ready soon.
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('json', tree_uuid, 'status'))))
        return r.json()

    def get_capture_stats(self, tree_uuid: str) -> Dict[str, Any]:
        '''Get statistics of the capture'''
        r = self.session.get(urljoin(self.root_url, str(Path('json', tree_uuid, 'stats'))))
        return r.json()

    def get_info(self, tree_uuid: str) -> Dict[str, Any]:
        '''Get information about the capture (url, timestamp, user agent)'''
        r = self.session.get(urljoin(self.root_url, str(Path('json', tree_uuid, 'info'))))
        return r.json()

    def enqueue(self, url: Optional[str]=None, quiet: bool=False,
                document: Optional[Union[Path, BytesIO]]=None,
                document_name: Optional[str]=None, **kwargs) -> str:
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
               capture_settings: Optional[CaptureSettings]=None) -> str:
        ...

    @overload
    def submit(self, *, quiet: bool=False,
               url: Optional[str]=None,
               document_name: Optional[str]=None, document: Optional[Union[Path, BytesIO]]=None,
               browser: Optional[str]=None, device_name: Optional[str]=None,
               user_agent: Optional[str]=None,
               proxy: Optional[Union[str, Dict[str, str]]]=None,
               general_timeout_in_sec: Optional[int]=None,
               cookies: Optional[List[Dict[str, Any]]]=None,
               headers: Optional[Union[str, Dict[str, str]]]=None,
               http_credentials: Optional[Dict[str, int]]=None,
               viewport: Optional[Dict[str, int]]=None,
               referer: Optional[str]=None,
               listing: Optional[bool]=None,
               ) -> str:
        ...

    def submit(self, *, quiet: bool=False,
               capture_settings: Optional[CaptureSettings]=None,
               url: Optional[str]=None,
               document_name: Optional[str]=None, document: Optional[Union[Path, BytesIO]]=None,
               browser: Optional[str]=None, device_name: Optional[str]=None,
               user_agent: Optional[str]=None,
               proxy: Optional[Union[str, Dict[str, str]]]=None,
               general_timeout_in_sec: Optional[int]=None,
               cookies: Optional[List[Dict[str, Any]]]=None,
               headers: Optional[Union[str, Dict[str, str]]]=None,
               http_credentials: Optional[Dict[str, int]]=None,
               viewport: Optional[Dict[str, int]]=None,
               referer: Optional[str]=None,
               listing: Optional[bool]=None,
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
        :param proxy: SOCKS5 proxy to use for capturing
        :param general_timeout_in_sec: The capture will raise a timeout it it takes more than that time
        :param cookies: A list of cookies
        :param headers: The headers to pass to the capture
        :param http_credentials: HTTP Credentials to pass to the capture
        :param viewport: The viewport of the browser used for capturing
        :param referer: The referer URL for the capture
        :param listing: If False, the capture will be not be on the publicly accessible index page of lookyloo
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
            if headers:
                to_send['headers'] = headers
            if http_credentials:
                to_send['http_credentials'] = http_credentials
            if viewport:
                to_send['viewport'] = viewport
            if referer:
                to_send['referer'] = referer
            if listing is not None:
                to_send['listing'] = listing

        response = self.session.post(urljoin(self.root_url, 'submit'), json=to_send)
        response.raise_for_status()
        uuid = response.json()
        if not uuid:
            raise PyLookylooError('Unable to get UUID from lookyloo instance.')
        if quiet:
            return uuid
        return urljoin(self.root_url, f'tree/{uuid}')

    def get_apikey(self, username: str, password: str) -> Dict[str, str]:
        '''Get the API key for the given user.'''
        to_post = {'username': username, 'password': password}
        r = self.session.post(urljoin(self.root_url, str(Path('json', 'get_token'))), json=to_post)
        return r.json()

    def init_apikey(self, username: Optional[str]=None, password: Optional[str]=None, apikey: Optional[str]=None):
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

    def misp_export(self, tree_uuid: str) -> Dict:
        '''Export the capture in MISP format'''
        r = self.session.get(urljoin(self.root_url, str(Path('json', tree_uuid, 'misp_export'))))
        return r.json()

    def misp_push(self, tree_uuid: str) -> Union[Dict, List]:
        '''Push the capture to a pre-configured MISP instance (requires an authenticated user, use init_apikey first)
        Note: if the response is a dict, it is an error mesage. If it is a list, it's a list of MISP event.
        '''
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.get(urljoin(self.root_url, str(Path('json', tree_uuid, 'misp_push'))))
        return r.json()

    def trigger_modules(self, tree_uuid: str, force: bool=False) -> Dict:
        '''Trigger all the available 3rd party modules on the given capture.
        :param force: Trigger the modules even if they were already triggered today.
        '''
        to_send = {'force': force}
        r = self.session.post(urljoin(self.root_url, str(Path('json', tree_uuid, 'trigger_modules'))),
                              json=to_send)
        return r.json()

    def rebuild_capture(self, tree_uuid: str) -> Dict:
        '''Force rebuild a capture (requires an authenticated user, use init_apikey first)'''
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.get(urljoin(self.root_url, str(Path('admin', tree_uuid, 'rebuild'))))
        return r.json()

    def hide_capture(self, tree_uuid: str) -> Dict:
        '''Hide a capture from the index page (requires an authenticated user, use init_apikey first)'''
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.get(urljoin(self.root_url, str(Path('admin', tree_uuid, 'hide'))))
        return r.json()

    def get_redirects(self, capture_uuid: str) -> Dict[str, Any]:
        '''Returns the initial redirects.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('json', capture_uuid, 'redirects'))))
        return r.json()

    def get_urls(self, capture_uuid: str) -> Dict[str, Any]:
        '''Returns all the URLs seen during the capture.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('json', capture_uuid, 'urls'))))
        return r.json()

    def get_hostnames(self, capture_uuid: str) -> Dict[str, Any]:
        '''Returns all the hostnames seen during the capture.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('json', capture_uuid, 'hostnames'))))
        return r.json()

    def get_screenshot(self, capture_uuid: str) -> BytesIO:
        '''Returns the screenshot.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('bin', capture_uuid, 'screenshot'))))
        return BytesIO(r.content)

    def get_cookies(self, capture_uuid: str) -> List[Dict[str, str]]:
        '''Returns the complete cookies jar.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('json', capture_uuid, 'cookies'))))
        return r.json()

    def get_html(self, capture_uuid: str) -> StringIO:
        '''Returns the rendered HTML as it would be in the browser after the page loaded.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('tree', capture_uuid, 'html'))))
        return StringIO(r.text)

    def get_hashes(self, capture_uuid: str, algorithm: str='sha512', hashes_only: bool=True) -> StringIO:
        '''Returns all the hashes of all the bodies (including the embedded contents)

        :param capture_uuid: UUID of the capture
        :param algorithm: The algorithm of the hashes
        :param hashes_only: If False, will also return the URLs related to the hashes
        '''
        params: Dict[str, Union[str, int]] = {'algorithm': algorithm, 'hashes_only': int(hashes_only)}

        r = self.session.get(urljoin(self.root_url, str(Path('json', capture_uuid, 'hashes'))), params=params)
        return r.json()

    def get_complete_capture(self, capture_uuid: str) -> BytesIO:
        '''Returns a zip files that contains the screenshot, the har, the rendered HTML, and the cookies.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('bin', capture_uuid, 'export'))))
        return BytesIO(r.content)

    def get_hash_occurrences(self, h: str) -> Dict[str, Any]:
        '''Returns the base 64 body related the the hash, and a list of all the captures containing that hash.

        :param h: sha512 to search
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('json', 'hash_info', h))))
        return r.json()

    def get_url_occurrences(self, url: str, limit: int=20, cached_captures_only: bool=True) -> Dict[str, Any]:
        '''Returns all the captures contining the URL

        :param url: URL to lookup
        :param limit: The max amount of entries to return.
        :param cached_captures_only: If False, Lookyloo will attempt to re-cache the missing captures. It might take some time.
        '''
        r = self.session.post(urljoin(self.root_url, str(Path('json', 'url_info'))), json={'url': url,
                                                                                           'limit': limit})
        return r.json()

    def get_hostname_occurrences(self, hostname: str, with_urls_occurrences: bool=False, limit: int=20, cached_captures_only: bool=True) -> Dict[str, Any]:
        '''Returns all the captures contining the hostname. It will be pretty slow on very common domains.

        :param hostname: Hostname to lookup
        :param with_urls_occurrences: If true, add details about the related URLs.
        :param limit: The max amount of entries to return.
        :param cached_captures_only: If False, Lookyloo will attempt to re-cache the missing captures. It might take some time.
        '''
        r = self.session.post(urljoin(self.root_url, str(Path('json', 'hostname_info'))), json={'hostname': hostname,
                                                                                                'with_urls_occurrences': with_urls_occurrences,
                                                                                                'limit': limit})
        return r.json()

    def get_stats(self) -> Dict[str, Any]:
        '''Returns all the captures contining the URL'''

        r = self.session.get(urljoin(self.root_url, str(Path('json', 'stats'))))
        return r.json()

    def get_takedown_information(self, capture_uuid: str) -> Dict[str, Any]:
        '''Returns information required to request a takedown for a capture

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.post(urljoin(self.root_url, str(Path('json', 'takedown'))),
                              json={'capture_uuid': capture_uuid})
        return r.json()

    def compare_captures(self, capture_left: str, capture_right: str, /, *, compare_settings: Optional[CompareSettings]=None) -> Dict[str, Any]:
        '''Compares two captures

        :param capture_left: UUID of the capture to compare from
        :param capture_right: UUID of the capture to compare to
        :param compare_settings: The settings for the comparison itself (what to ignore without marking the captures as different)
        '''
        r = self.session.post(urljoin(self.root_url, str(Path('json', 'compare_captures'))),
                              json={'capture_left': capture_left,
                                    'capture_right': capture_right,
                                    'compare_settings': compare_settings})
        return r.json()
