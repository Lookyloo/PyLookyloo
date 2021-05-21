#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from pylookyloo import Lookyloo


class UnitTesting(unittest.TestCase):

    public_instance: Lookyloo

    @classmethod
    def setUpClass(cls) -> None:
        setattr(cls, "public_instance", Lookyloo('http://127.0.0.1:5100'))

    # Check that lookyloo.circl.lu is up
    def test_public_instance_is_up(self) -> None:
        self.assertTrue(self.public_instance.is_up)


if __name__ == '__main__':
    unittest.main()
