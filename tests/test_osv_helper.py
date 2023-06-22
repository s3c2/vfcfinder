"""
Unit Tests for osv_helper.py
"""
import unittest
import json
from vfcfinder.utils import osv_helper


class TestOSVHelper(unittest.TestCase):
    """OSV Helper Unit Test"""

    def test_parse_osv(self):
        """
        Testing OSV Parser to load a GHSA file
        Example GHSA: GHSA-xrcv-f9gm-v42c
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/01/GHSA-xrcv-f9gm-v42c/GHSA-xrcv-f9gm-v42c.json
        """
        # Open the json
        with open("./tests/data/osv_schema.json", "r") as f:
            osv_schema = json.load(f)
            f.close()

        parsed = osv_helper.parse_osv(
            osv_json_filename="./tests/data/GHSA-xrcv-f9gm-v42c.json",
            osv_schema=osv_schema,
        )

        # Length of parsed DF should be one based on one fixed versions
        self.assertEqual(len(parsed[1]), 1)


if __name__ == "__main__":
    unittest.main()
