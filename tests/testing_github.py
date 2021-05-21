#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from pylookyloo import Lookyloo


class UnitTesting(unittest.TestCase):

    github_instance: Lookyloo

    @classmethod
    def setUpClass(cls) -> None:
        setattr(cls, "github_instance", Lookyloo('http://127.0.0.1:5100'))

    # Check that lookyloo.circl.lu is up
    def test_github_instance_is_up(self) -> None:
        self.assertTrue(self.github_instance.is_up)


if __name__ == '__main__':
    unittest.main()
