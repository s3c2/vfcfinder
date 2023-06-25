"""
Unit Tests for the full ranking pipeline
"""
import unittest
from vfcfinder import vfc_ranker


class TestRanker(unittest.TestCase):
    """Feature Unit Test"""

    def test_ranker(self):
        """
        Testing commit rank
        Example GHSA: GHSA-fj7c-vg2v-ccrm
            - GHSA-g53w-52xc-2j85
        """

        # Set args for cloning a repo
        # ADVISORY_PATH = "./tests/data/GHSA-v65g-f3cj-fjp4.json"
        ADVISORY_PATH = "./tests/data/GHSA-g53w-52xc-2j85.json"
        CLONE_PATH = "./../test_clone_repo/"

        # Get the commits between a prior and current tag
        ranked_commits = vfc_ranker.rank(
            advisory_path=ADVISORY_PATH, clone_path=CLONE_PATH, return_results=True
        )

        # Rank should be 70f89be700df0d5f08ef696252c88741f8414060
        self.assertEqual(
            ranked_commits.iloc[0].sha,
            # "70f89be700df0d5f08ef696252c88741f8414060", # for GHSA-fj7c-vg2v-ccrm
            "94a9a3e752fe089ab23f3a90c26d20d46d62ab10"
        )


if __name__ == "__main__":
    unittest.main()
