#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from io import BytesIO, StringIO
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin
from pathlib import Path

import requests


class PyLookylooError(Exception):
    pass


class AuthError(PyLookylooError):
    pass


class Lookyloo():

    def __init__(self, root_url: str='https://lookyloo.circl.lu/'):
        '''Query a specific lookyloo instance.

        :param root_url: URL of the instance to query.
        '''
        self.root_url = root_url
        if not self.root_url.endswith('/'):
            self.root_url += '/'
        self.session = requests.session()
        self.apikey: Optional[str] = None

    @property
    def is_up(self) -> bool:
        '''Test if the given instance is accessible'''
        r = self.session.head(self.root_url)
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

    def enqueue(self, url: Optional[str]=None, quiet: bool=False, **kwargs) -> str:
        '''Enqueue an URL.

        :param url: URL to enqueue
        :param quiet: Returns the UUID only, instead of the whole URL
        :param kwargs: accepts all the parameters supported by `Lookyloo.scrape`
        '''
        if not url and 'url' not in kwargs:
            raise PyLookylooError(f'url entry required: {kwargs}')

        if url:
            to_send = {'url': url, **kwargs}
        else:
            to_send = kwargs
        response = self.session.post(urljoin(self.root_url, 'submit'), json=to_send)
        if quiet:
            return response.text
        else:
            return urljoin(self.root_url, f'tree/{response.text}')

    def get_apikey(self, username: str, password: str) -> Dict[str, str]:
        to_post = {'username': username, 'password': password}
        r = self.session.post(urljoin(self.root_url, str(Path('json', 'get_token'))),
                              json=to_post)
        return r.json()

    def init_apikey(self, username: Optional[str]=None, password: Optional[str]=None, apikey: Optional[str]=None):
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
        r = self.session.get(urljoin(self.root_url, str(Path('json', tree_uuid, 'misp_export'))))
        return r.json()

    def misp_push(self, tree_uuid: str) -> Dict:
        if not self.apikey:
            raise AuthError('You need to initialize the apikey to use this method (see init_apikey)')
        r = self.session.get(urljoin(self.root_url, str(Path('json', tree_uuid, 'misp_push'))))
        return r.json()

    def get_redirects(self, capture_uuid: str) -> Dict[str, Any]:
        '''Returns the initial redirects.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('json', capture_uuid, 'redirects'))))
        return r.json()

    def get_screenshot(self, capture_uuid: str) -> BytesIO:
        '''Returns the screenshot.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('tree', capture_uuid, 'image'))))
        return BytesIO(r.content)

    def get_cookies(self, capture_uuid: str) -> List[Dict[str, str]]:
        '''Returns the complete cookies jar.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('tree', capture_uuid, 'cookies'))))
        return r.json()

    def get_html(self, capture_uuid: str) -> StringIO:
        '''Returns the rendered HTML as it would be in the browser after the page loaded.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('tree', capture_uuid, 'html'))))
        return StringIO(r.text)

    def get_hashes(self, capture_uuid: str) -> StringIO:
        '''Returns all the hashes of all the bodies (including the embedded contents)

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('tree', capture_uuid, 'hashes'))))
        return StringIO(r.text)

    def get_complete_capture(self, capture_uuid: str) -> BytesIO:
        '''Returns a zip files that contains the screenshot, the har, the rendered HTML, and the cookies.

        :param capture_uuid: UUID of the capture
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('tree', capture_uuid, 'export'))))
        return BytesIO(r.content)

    def get_hash_occurrences(self, h: str) -> Dict[str, Any]:
        '''Returns the base 64 body related the the hash, and a list of all the captures containing that hash.

        :param h: sha512 to search
        '''
        r = self.session.get(urljoin(self.root_url, str(Path('json', 'hash_info', h))))
        return r.json()

    def get_url_occurrences(self, url: str) -> Dict[str, Any]:
        '''Returns all the captures contining the URL

        :param url: URL to lookup
        '''
        r = self.session.post(urljoin(self.root_url, str(Path('json', 'url_info'))), json={'url': url})
        return r.json()

    def get_hostname_occurrences(self, hostname: str, with_urls_occurrences: bool=False) -> Dict[str, Any]:
        '''Returns all the captures contining the hostname. It will be pretty slow on very common domains.

        :param hostname: Hostname to lookup
        :param with_urls_occurrences: If true, add details about the related URLs.
        '''
        r = self.session.post(urljoin(self.root_url, str(Path('json', 'hostname_info'))), json={'hostname': hostname,
                                                                                                'with_urls_occurrences': with_urls_occurrences})
        return r.json()

    def get_stats(self) -> Dict[str, Any]:
        '''Returns all the captures contining the URL'''

        r = self.session.get(urljoin(self.root_url, str(Path('json', 'stats'))))
        return r.json()
