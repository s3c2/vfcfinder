"""
Unit Tests for Features
"""
import unittest
import json
from vfcfinder.utils import git_helper, osv_helper
from vfcfinder.features import (
    semantic_similarity,
    vfc_identification,
    static_features,
)

import numpy as np
import torch
import random

seed_val = 42
random.seed(seed_val)
np.random.seed(seed_val)
torch.manual_seed(seed_val)
torch.cuda.manual_seed_all(seed_val)


class TestFeatures(unittest.TestCase):
    """Feature Unit Test"""

    @unittest.skip("Skipping for now")
    def test_commit_rank(self):
        """
        Testing commit rank
        Example GHSA: GHSA-fj7c-vg2v-ccrm
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

        # Check if CVE is in commit
        rank = static_features.normalized_commit_rank(
            commit_list=commits, target_sha="82541b6dec8452cb612067fcebba1c5a1a2bfdc8"
        )

        # Rank should be 0.004
        self.assertEqual(
            round(rank.iloc[0], 3),
            0.004,
        )


    @unittest.skip("Skipping for now")
    def test_cve_in_commit_message(self):
        """
        Testing if the CVE is in the commit message
        Example GHSA: GHSA-fj7c-vg2v-ccrm
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/07/GHSA-fj7c-vg2v-ccrm/GHSA-fj7c-vg2v-ccrm.json
        VFC: https://github.com/undertow-io/undertow/commit/c7e84a0b7efced38506d7d1dfea5902366973877
        Repo Link: https://github.com/undertow-io/undertow
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

        # Check if CVE is in commit
        commits["cve_in_message"] = commits.apply(
            lambda x: static_features.cve_in_commit_message(
                x["full_message"], "CVE-1000-500"
            ),
            axis=1,
        )

        # Semantic similarity should be 0.88 for example
        self.assertEqual(
            commits[
                commits["sha"] == "82541b6dec8452cb612067fcebba1c5a1a2bfdc8"
            ].cve_in_message.iloc[0],
            False,
        )


    @unittest.skip("Skipping for now")
    def test_semantic_similarity(self):
        """
        Testing semantic similarity
        Example GHSA: GHSA-fj7c-vg2v-ccrm
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/07/GHSA-fj7c-vg2v-ccrm/GHSA-fj7c-vg2v-ccrm.json
        VFC: https://github.com/undertow-io/undertow/commit/c7e84a0b7efced38506d7d1dfea5902366973877
        Repo Link: https://github.com/undertow-io/undertow
        """

        # Set args for cloning a repo
        repo_owner = "undertow-io"
        repo_name = "undertow"
        clone_directory = "./../test_clone_repo/"
        full_repo_path = f"{clone_directory}{repo_owner}/{repo_name}/"
        target_sha = f"c7e84a0b7efced38506d7d1dfea5902366973877"

        # clone the repository
        git_helper.clone_repo(
            repo_owner=repo_owner, repo_name=repo_name, clone_path=clone_directory
        )

        # parse the advisory
        # Open the json
        with open("./tests/data/osv_schema.json", "r") as f:
            osv_schema = json.load(f)
            f.close()

        parsed = osv_helper.parse_osv(
            osv_json_filename="./tests/data/GHSA-fj7c-vg2v-ccrm.json",
            osv_schema=osv_schema,
        )

        # set the advisory details message
        advisory_details = parsed[0]["details"]

        # get the tags
        tags = git_helper.get_prior_tag(
            repo_owner=repo_owner,
            repo_name=repo_name,
            clone_path=clone_directory,
            target_tag=parsed[1].iloc[1].fixed,
        )

        # get the commits
        commits = git_helper.get_commits_between_tags(
            prior_tag=tags["prior_tag"],
            current_tag=tags["current_tag"],
            temp_repo_path=full_repo_path,
        )

        # target commit from VFC c7e84a0b7efced38506d7d1dfea5902366973877
        commit_message = commits[commits["sha"] == target_sha].full_message.iloc[0]

        # semantic similarity
        similarity = semantic_similarity.semantic_similarity(
            full_message=commit_message, advisory_details=advisory_details
        )

        # Semantic similarity should be 0.88 for example
        self.assertEqual(
            round(similarity, 2),
            0.88,
        )
        
        
    @unittest.skip("Skipping for now")
    def test_semantic_similarity_batch(self):
        """
        Testing semantic similarity batches
        Example GHSA: GHSA-fj7c-vg2v-ccrm
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/07/GHSA-fj7c-vg2v-ccrm/GHSA-fj7c-vg2v-ccrm.json
        VFC: https://github.com/undertow-io/undertow/commit/c7e84a0b7efced38506d7d1dfea5902366973877
        Repo Link: https://github.com/undertow-io/undertow
        """

        # Set args for cloning a repo
        repo_owner = "undertow-io"
        repo_name = "undertow"
        clone_directory = "./../test_clone_repo/"
        full_repo_path = f"{clone_directory}{repo_owner}/{repo_name}/"
        target_sha = f"c7e84a0b7efced38506d7d1dfea5902366973877"

        # clone the repository
        git_helper.clone_repo(
            repo_owner=repo_owner, repo_name=repo_name, clone_path=clone_directory
        )

        # parse the advisory
        # Open the json
        with open("./tests/data/osv_schema.json", "r") as f:
            osv_schema = json.load(f)
            f.close()

        parsed = osv_helper.parse_osv(
            osv_json_filename="./tests/data/GHSA-fj7c-vg2v-ccrm.json",
            osv_schema=osv_schema,
        )

        # set the advisory details message
        advisory_details = parsed[0]["details"]

        # get the tags
        tags = git_helper.get_prior_tag(
            repo_owner=repo_owner,
            repo_name=repo_name,
            clone_path=clone_directory,
            target_tag=parsed[1].iloc[1].fixed,
        )

        # get the commits
        commits = git_helper.get_commits_between_tags(
            prior_tag=tags["prior_tag"],
            current_tag=tags["current_tag"],
            temp_repo_path=full_repo_path,
        )

        # batch all the commits for a semantic similarity
        commits["semantic_similarity"] = semantic_similarity.semantic_similarity_batch(
            temp_commits=commits.copy(), advisory_details=advisory_details
        )
        
        # target commit from VFC c7e84a0b7efced38506d7d1dfea5902366973877
        similarity = commits[commits["sha"] == target_sha].semantic_similarity.iloc[0]

        # Semantic similarity should be 0.88 for example
        self.assertEqual(
            round(similarity, 2),
            0.88,
        )
        

    # @unittest.skip("Skipping for now")
    def test_vfc_identification(self):
        """
        Testing semantic similarity
        Example GHSA: GHSA-fj7c-vg2v-ccrm
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/07/GHSA-fj7c-vg2v-ccrm/GHSA-fj7c-vg2v-ccrm.json
        VFC: https://github.com/undertow-io/undertow/commit/c7e84a0b7efced38506d7d1dfea5902366973877
        VFC: https://github.com/ckeditor/ckeditor4/commit/d158413449692d920a778503502dcb22881bc949
        Repo Link: https://github.com/undertow-io/undertow
        """

        # Set args for cloning a repo
        # load the data
        # Set args for cloning a repo
        # repo_owner = "undertow-io"
        # repo_name = "undertow"
        # target_sha = f"4af3e7f7921b4fb4436363e46e5b4785655f5d7d"

        repo_owner = "ckeditor"
        repo_name = "ckeditor4"
        target_sha = f"d158413449692d920a778503502dcb22881bc949"
        clone_directory = "./../test_clone_repo/"
        full_repo_path = f"{clone_directory}{repo_owner}/{repo_name}/"

        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        # device = "cpu"

        # clone the repository
        git_helper.clone_repo(
            repo_owner=repo_owner, repo_name=repo_name, clone_path=clone_directory
        )
        
        commit = git_helper.git_diff(clone_path=full_repo_path, commit_sha=target_sha)

        commit_data = vfc_identification.load_ghsa_vfc_data(
            vuln_file=commit,
            class_name="vfc_label",
            group_level=["message", "file_type"],
        )

        commit_data["label"] = 0

        tokenizer, model = vfc_identification.load_vfc_identification_model()

        commit_dataloader = vfc_identification.convert_df_to_dataloader(
            tokenizer=tokenizer,
            temp_df=commit_data,
            text="message",
            text_pair="file_pure_modified_code",
            target="label",
            batch_size=32,
        )

        # load the model to the device
        model.to(device)

        # get the preds and probs
        preds, probs = vfc_identification.validation_model_single_epoch(
            model,
            val_dataloader=commit_dataloader,
            device=device,
            binary_classification=True,
            class_weights=None,
        )

        self.assertEqual(
            round(probs[0], 2),
            0.99,
        )

    @unittest.skip("Skipping for now")
    def test_vfc_type(self):
        """
        Testing semantic similarity
        Example GHSA: GHSA-fj7c-vg2v-ccrm
        Web Link: https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/07/GHSA-fj7c-vg2v-ccrm/GHSA-fj7c-vg2v-ccrm.json
        VFC: https://github.com/undertow-io/undertow/commit/c7e84a0b7efced38506d7d1dfea5902366973877
        VFC: https://github.com/ckeditor/ckeditor4/commit/d158413449692d920a778503502dcb22881bc949
        Repo Link: https://github.com/undertow-io/undertow
        """

        # Set args for cloning a repo
        # load the data
        # Set args for cloning a repo
        # repo_owner = "undertow-io"
        # repo_name = "undertow"
        # target_sha = f"4af3e7f7921b4fb4436363e46e5b4785655f5d7d"

        repo_owner = "ckeditor"
        repo_name = "ckeditor4"
        target_sha = f"d158413449692d920a778503502dcb22881bc949"
        clone_directory = "./../test_clone_repo/"
        full_repo_path = f"{clone_directory}{repo_owner}/{repo_name}/"

        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        # device = "cpu"

        commit = git_helper.git_diff(clone_path=full_repo_path, commit_sha=target_sha)

        commit_data = vfc_identification.load_ghsa_vfc_data(
            vuln_file=commit,
            class_name="vfc_label",
            group_level=["message", "file_type"],
        )

        commit_data["label"] = 0

        tokenizer, model = vfc_identification.load_vfc_type_model()

        commit_dataloader = vfc_identification.convert_df_to_dataloader(
            tokenizer=tokenizer,
            temp_df=commit_data,
            text="message",
            text_pair="file_pure_modified_code",
            target="label",
            batch_size=32,
        )

        # load the model to the device
        model.to(device)

        # get the preds and probs
        preds, probs = vfc_identification.validation_model_single_epoch(
            model,
            val_dataloader=commit_dataloader,
            device=device,
            binary_classification=False,
            class_weights=None,
        )

        labels = vfc_identification.get_owasp_label_map()

        self.assertEqual(
            labels[labels["label"] == preds[0]].name.values[0],
            "Injection",
        )


if __name__ == "__main__":
    unittest.main()
