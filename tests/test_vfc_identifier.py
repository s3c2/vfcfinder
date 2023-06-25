"""
Unit Tests for the full ranking pipeline
"""
import unittest
from vfcfinder import vfc_identifier
from vfcfinder.utils import git_helper


class TestVFCIdentifier(unittest.TestCase):
    """Feature Unit Test"""

    def test_vfc_identifier(self):
        """
        Testing commit rank
        Example GHSA: GHSA-fj7c-vg2v-ccrm
        """

        # Set args for cloning a repo
        repo_owner = "ckeditor"
        repo_name = "ckeditor4"
        target_shas = ["d158413449692d920a778503502dcb22881bc949"]
        clone_directory = "./../test_clone_repo/"
        full_repo_path = f"{clone_directory}{repo_owner}/{repo_name}/"

        # clone the repository
        git_helper.clone_repo(
            repo_owner=repo_owner, repo_name=repo_name, clone_path=clone_directory
        )

        # generate VFC probability
        probs = vfc_identifier.vfc_prob(clone_path=full_repo_path,
                                        commits=target_shas)

        # Rank should be 70f89be700df0d5f08ef696252c88741f8414060
        self.assertEqual(
            round(probs.iloc[0].vfc_prob, 2),
            0.99,
        )


if __name__ == "__main__":
    unittest.main()
