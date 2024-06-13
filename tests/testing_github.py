#!/usr/bin/env python3

import json
import unittest
import time

from zipfile import ZipFile

import requests

from pylookyloo import Lookyloo


class UnitTesting(unittest.TestCase):

    github_instance: Lookyloo

    def _wait_capture_done(self, uuid: str) -> None:
        seconds_elapsed = 0

        # get_status returns 1 in 'status_code' key if capture is ready
        while status := self.github_instance.get_status(uuid)['status_code'] != 1:
            if status == -1:
                raise Exception('The capture failed and was removed.')
            # Raise exception in case capture takes too long to avoid infinite while loop
            if seconds_elapsed > 100:
                raise Exception("Capture time limit exceeded!")
            time.sleep(1)
            seconds_elapsed += 1

    @classmethod
    def setUpClass(cls) -> None:
        setattr(cls, "github_instance", Lookyloo('http://127.0.0.1:5100'))
        # Check that the local instance is up
        assert cls.github_instance.is_up
        requests.head('https://rafiot.eu.pythonanywhere.com/')
        time.sleep(10)

    # Check that the local instance (started in github actions of lookyloo) is up
    def test_github_instance_is_up(self) -> None:
        self.assertTrue(self.github_instance.is_up)

    # Check that a capture is properly made
    def test_capture(self) -> None:
        # Query a url for capture; save uuid of the capture in a variable
        uuid = self.github_instance.submit(url='https://rafiot.eu.pythonanywhere.com/redirect_http', quiet=True)
        self._wait_capture_done(uuid)
        response = self.github_instance.get_redirects(uuid)
        self.assertEqual('https://rafiot.eu.pythonanywhere.com/redirect_http', response['response']['url'])
        self.assertEqual('https://www.youtube.com/watch?v=iwGFalTRHDA', response['response']['redirects'][1])

        # test export - import
        capture_export = self.github_instance.get_complete_capture(uuid)
        new_uuid, messages = self.github_instance.upload_capture(full_capture=capture_export, quiet=False)
        self.assertNotEqual(uuid, new_uuid)
        self.assertFalse(messages['errors'])
        self.assertEqual(len(messages['warnings']), 1)
        self.assertEqual(messages['warnings'][0], f'UUID {uuid} already exists, set a new one.')

    def test_referer(self) -> None:
        uuid = self.github_instance.submit(url='https://rafiot.eu.pythonanywhere.com/referer', quiet=True)
        self._wait_capture_done(uuid)
        response = self.github_instance.get_info(uuid)
        self.assertEqual('https://rafiot.eu.pythonanywhere.com/referer', response['url'])
        self.assertFalse(response.get('referer'))
        response = self.github_instance.get_redirects(uuid)
        self.assertEqual('https://www.google.dk/', response['response']['redirects'][-1])
        uuid = self.github_instance.submit(url='https://rafiot.eu.pythonanywhere.com/referer', quiet=True, referer='http://circl.lu')
        self._wait_capture_done(uuid)
        response = self.github_instance.get_info(uuid)
        self.assertEqual('https://rafiot.eu.pythonanywhere.com/referer', response['url'])
        self.assertEqual('http://circl.lu/', response['referer'])

    def test_comparables(self) -> None:
        uuid = self.github_instance.submit(url='https://rafiot.eu.pythonanywhere.com/referer', quiet=True)
        self._wait_capture_done(uuid)
        response = self.github_instance.get_comparables(uuid)
        self.assertEqual(200, response['final_status_code'])

    def test_capture_settings(self) -> None:
        # uuid = self.github_instance.submit(url='http://127.0.0.1:5000/all_settings',
        uuid = self.github_instance.submit(url='https://rafiot.eu.pythonanywhere.com/all_settings',
                                           user_agent="MyTestAgent",
                                           headers={'Manual-Test': "blahhh", "DNT": "1"},
                                           geolocation={'latitude': 50, 'longitude': 40},
                                           timezone_id='Europe/Berlin',
                                           locale='en_US',
                                           color_scheme="dark",
                                           referer="https://circl.lu",
                                           quiet=True)
        self._wait_capture_done(uuid)
        cookies = self.github_instance.get_cookies(uuid)
        print(json.dumps(cookies, indent=2))
        for cookie in cookies:
            if cookie['name'] == 'manual_test_header':
                self.assertEqual(cookie['value'], 'blahhh', cookie.get('value'))
            elif cookie['name'] == 'referer':
                self.assertEqual(cookie['value'], 'https://circl.lu', cookie.get('value'))
            elif cookie['name'] == 'user_agent':
                self.assertEqual(cookie['value'], 'MyTestAgent', cookie.get('value'))
            elif cookie['name'] == 'dnt':
                self.assertEqual(cookie['value'], '1', cookie.get('value'))
            elif cookie['name'] == 'timezone':
                self.assertEqual(cookie['value'], 'Europe/Berlin', cookie.get('value'))
            elif cookie['name'] == 'locale':
                self.assertEqual(cookie['value'], 'en_US', cookie.get('value'))
            elif cookie['name'] == 'color_scheme':
                self.assertEqual(cookie['value'], 'dark', cookie.get('value'))
            elif cookie['name'] == 'mobile':
                self.assertEqual(cookie['value'], '', cookie.get('value'))
            elif cookie['name'] == 'latitude':
                self.assertEqual(cookie['value'], '50', cookie.get('value'))
            elif cookie['name'] == 'longitude':
                self.assertEqual(cookie['value'], '40', cookie.get('value'))
            else:
                raise Exception(cookie)

    def test_js_download(self) -> None:
        # uuid = self.github_instance.submit(url='http://127.0.0.1:5000/sneaky_download?version=foo',
        uuid = self.github_instance.submit(url='https://rafiot.eu.pythonanywhere.com/sneaky_download?version=foo',
                                           user_agent="MyTestAgent",
                                           quiet=True)
        self._wait_capture_done(uuid)
        data = self.github_instance.get_data(uuid)
        with ZipFile(data) as z:
            self.assertEqual(z.namelist()[0], 'TOS.pdf', z.namelist())

    def test_takedown_information(self) -> None:
        expected_takedown_info = [{'hostname': 'www.circl.lu', 'contacts': ['support@eurodns.com'], 'ips': {'185.194.93.14': ['info@circl.lu'], '2a00:5980:93::14': ['info@circl.lu']}, 'asns': {'197869': ['info@circl.lu']}, 'all_emails': ['info@circl.lu', 'support@eurodns.com', 'nfo@circl.lu'], 'securitytxt': {'contact': 'info@circl.lu', 'encryption': 'https://openpgp.circl.lu/pks/lookup?op=get&search=0xeaadcffc22bd4cd5', 'policy': 'https://www.circl.lu/pub/responsible-vulnerability-disclosure/'}}]
        expected_mails = ['info@circl.lu', 'support@eurodns.com', 'nfo@circl.lu']
        uuid = self.github_instance.submit(url="https://www.circl.lu/", quiet=True)
        self._wait_capture_done(uuid)
        # get all takedown information
        takedown_info = self.github_instance.get_takedown_information(capture_uuid=uuid)
        self.assertEqual(set(expected_takedown_info[0]), set(takedown_info[0]))
        # get only the filtered emails
        filtered_mails = self.github_instance.get_takedown_information(capture_uuid=uuid, filter_contacts=True)
        self.assertEqual(set(expected_mails), set(filtered_mails))


if __name__ == '__main__':
    unittest.main()
