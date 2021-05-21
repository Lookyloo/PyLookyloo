#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from pylookyloo import Lookyloo


class UnitTesting(unittest.TestCase):

    public_instance: Lookyloo

    @classmethod
    def setUpClass(cls) -> None:
        setattr(cls, "public_instance", Lookyloo())

    # Check that lookyloo.circl.lu is up
    def test_public_instance_is_up(self) -> None:
        self.assertTrue(self.public_instance.is_up)

    # Check that the database is not corrupted
    def test_stats(self) -> None:
        self.assertEqual(self.public_instance.get_stats()['years'][0]['yearly_submissions'], 29548)

    # Checks that this years yearly submissions number is superior to the number of captures when this test was made
    def test_stats_2021(self) -> None:
        self.assertTrue(self.public_instance.get_stats()['years'][1]['yearly_submissions'] > 84100)


if __name__ == '__main__':
    unittest.main()
