#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import time

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
        print(response)
        self.assertEqual('https://rafiot.eu.pythonanywhere.com/redirect_http', response['response']['url'])
        self.assertEqual('https://www.youtube.com/watch?v=iwGFalTRHDA', response['response']['redirects'][1])

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


if __name__ == '__main__':
    unittest.main()
