"""
Unit Tests for git_helper.py
"""
import unittest
import os
import pandas as pd
from vfcfinder.utils import git_helper


class TestGitHelper(unittest.TestCase):
    """OSV Helper Unit Test"""

    def test_git_clone(self):
        """
        Testing git repo cloner
        Example GHSA: GHSA-xrcv-f9gm-v42c
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/
            github-reviewed/2022/01/GHSA-xrcv-f9gm-v42c/GHSA-xrcv-f9gm-v42c.json
        Repo Link: https://github.com/python-pillow/Pillow
        """

        # Set args for cloning a repo
        repo_owner = "python-pillow"
        repo_name = "Pillow"
        clone_directory = "./../test_clone_repo/"

        git_helper.clone_repo(
            repo_owner=repo_owner, repo_name=repo_name, clone_path=clone_directory
        )

        # Length of parsed DF should be one based on one fixed versions
        self.assertEqual(
            os.path.exists(
                "./../test_clone_repo/python-pillow/Pillow/LICENSE"
            ),
            True,
        )

    def test_get_tags(self):
        """
        Testing git get tags
        Example GHSA: GHSA-xrcv-f9gm-v42c
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/01/GHSA-xrcv-f9gm-v42c/GHSA-xrcv-f9gm-v42c.json
        Repo Link: https://github.com/python-pillow/Pillow
        """

        # Set args for cloning a repo
        repo_owner = "python-pillow"
        repo_name = "Pillow"
        clone_directory = "./../test_clone_repo/"

        # Get the tags for a given repository
        tags = git_helper.get_tags(
            repo_owner=repo_owner, repo_name=repo_name, clone_path=clone_directory
        )

        # Length of parsed DF should be equal to 84
        self.assertGreater(
            len(tags),
            80,
        )

    def test_get_prior_tag(self):
        """
        Testing get_prior_tag. Given a fixed tag, return the prior tag.
        Example GHSA: GHSA-xrcv-f9gm-v42c
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/01/GHSA-xrcv-f9gm-v42c/GHSA-xrcv-f9gm-v42c.json
        Repo Link: https://github.com/python-pillow/Pillow
        Fix tag: 9.0.0
        """

        # Set args for cloning a repo
        repo_owner = "python-pillow"
        repo_name = "Pillow"
        clone_directory = "./../test_clone_repo/"
        fix_tag = "9.0.0"

        # Get the tags for a given repository
        tags = git_helper.get_prior_tag(
            repo_owner=repo_owner,
            repo_name=repo_name,
            clone_path=clone_directory,
            target_tag=fix_tag,
        )

        # Prior tag to 9.0.0 is 8.4.0
        # https://github.com/python-pillow/Pillow/tags
        self.assertEqual(
            tags["prior_tag"],
            "8.4.0",
        )

    def test_get_commits(self):
        """
        Testing to obtain commits between versions
        Example GHSA: GHSA-xrcv-f9gm-v42c
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/01/GHSA-xrcv-f9gm-v42c/GHSA-xrcv-f9gm-v42c.json
        Repo Link: https://github.com/python-pillow/Pillow
        """

        # Set args for cloning a repo
        repo_owner = "python-pillow"
        repo_name = "Pillow"
        clone_directory = "./../test_clone_repo/"

        # Get the commits between a prior and current tag
        commits = git_helper.get_commits_between_tags(
            prior_tag="8.4.0",
            current_tag="9.0.0",
            temp_repo_path=f"{clone_directory}{repo_owner}/{repo_name}",
        )

        # Should be 272: https://github.com/python-pillow/Pillow/compare/8.4.0...9.0.0
        self.assertEqual(
            len(commits),
            272,
        )

    def test_git_diff(self):
        """
        Testing patchparser to obtain git diff data
        Example GHSA: GHSA-xrcv-f9gm-v42c
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/01/GHSA-xrcv-f9gm-v42c/GHSA-xrcv-f9gm-v42c.json
        Repo Link: https://github.com/python-pillow/Pillow
        Known VFC: https://github.com/python-pillow/Pillow/commit/5543e4e2d409cd9e409bc64cdc77be0af007a31f
        """

        # Set args for cloning a repo
        repo_owner = "python-pillow"
        repo_name = "Pillow"
        clone_directory = "./../test_clone_repo/"
        commit_sha = "5543e4e2d409cd9e409bc64cdc77be0af007a31f"

        # Get the commits between a prior and current tag
        diff = git_helper.git_diff(
            clone_path=f"{clone_directory}{repo_owner}/{repo_name}",
            commit_sha=commit_sha,
        )

        diff_df = pd.DataFrame(diff)

        total_file_changes = (
            diff_df[["file_name", "total_file_changes"]]
            .drop_duplicates()["total_file_changes"]
            .sum()
        )

        # Should be 37
        # VFC: https://github.com/python-pillow/Pillow/commit/5543e4e2d409cd9e409bc64cdc77be0af007a31f
        # Total additions (22) + deletions (15) = 37
        self.assertEqual(
            total_file_changes,
            37,
        )


if __name__ == "__main__":
    unittest.main()
