#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import time
from pylookyloo import Lookyloo


class UnitTesting(unittest.TestCase):

    github_instance: Lookyloo

    @classmethod
    def setUpClass(cls) -> None:
        setattr(cls, "github_instance", Lookyloo('http://127.0.0.1:5100'))

    # Check that the local instance (started in github actions of lookyloo) is up
    def test_github_instance_is_up(self) -> None:
        self.assertTrue(self.github_instance.is_up)

    # Check that a capture is properly made
    def test_capture(self) -> None:
        # Query a url for capture; save uuid of the capture in a variable
        uuid = self.github_instance.enqueue('https://lookyloo-testing.herokuapp.com/redirect_http', True)
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
        response = self.github_instance.get_redirects(uuid)
        self.assertEqual('https://lookyloo-testing.herokuapp.com/redirect_http', response['response']['url'])
        self.assertEqual('https://www.youtube.com/watch?v=iwGFalTRHDA', response['response']['redirects'][0])


if __name__ == '__main__':
    unittest.main()