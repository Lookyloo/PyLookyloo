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
        uuid = self.github_instance.enqueue('http://lookyloo-testing.herokuapp.com/', True)
        # Wait 60 seconds for the capture to complete (could be reduced)
        time.sleep(60)
        # get_status returns 1 in 'status_code' key if capture is ready
        self.assertEqual(1, self.github_instance.get_status(uuid)['status_code'])


if __name__ == '__main__':
    unittest.main()
