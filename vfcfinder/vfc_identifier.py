"""
Easy helper function for identifying if a commit fixed a VFC
"""
import pandas as pd
import torch

from pathlib import Path
from vfcfinder.utils import git_helper
from vfcfinder.features import vfc_identification


def vfc_prob(temp_clone_path: str, temp_commits:list) -> pd.DataFrame:
    """Generates a probability for if a commit fixed a vulnerability
    Low probability = 0
    High probability = 1

    Args:
        temp_clone_path (str): Path to clone a repository
        commits (bool): List of commits 

    Returns:
        pd.DataFrame: commit with associated VFC probability
    """
    # SET args
    CLONE_DIRECTORY = temp_clone_path

    # dynamically set variables
    PARENT_PATH = f"{str(Path(__file__).resolve().parent.parent)}/"
    DEVICE = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    # Convert the list a DF
    commits = pd.DataFrame([temp_commits], columns = ["sha"])

    #####################################################################################
    # generate features
    # patchparser for each commit
    commits_diff = pd.DataFrame()

    # get the diff of each commit
    for idx, row in commits.iterrows():
        print(f"Obtaining diff for commit {idx+1}/{len(commits)} || {row['sha']}")
        temp_diff = git_helper.git_diff(
            clone_path=CLONE_DIRECTORY,
            commit_sha=row["sha"],
        )
        temp_diff_df = pd.DataFrame(temp_diff)

        commits_diff = pd.concat([commits_diff, temp_diff_df])

    #####################################################################################
    # vfc_identification
    print("\nGenerating VFC probability inference for each commit...")

    commit_vfc_data = vfc_identification.load_ghsa_vfc_data(
        vuln_file=commits_diff,
        class_name="vfc_label",
        group_level=["message", "file_type"],
    )

    commit_vfc_data["label"] = 0

    tokenizer, model = vfc_identification.load_vfc_identification_model()

    commit_dataloader = vfc_identification.convert_df_to_dataloader(
        tokenizer=tokenizer,
        temp_df=commit_vfc_data,
        text="message",
        text_pair="file_pure_modified_code",
        target="label",
        batch_size=32,
    )

    model.to(DEVICE)

    preds, probs = vfc_identification.validation_model_single_epoch(
        model,
        val_dataloader=commit_dataloader,
        device=DEVICE,
        binary_classification=True,
        class_weights=None,
    )

    commit_vfc_data["vfc_prob"] = probs

    # merge the probabilities back to the commits
    commits = pd.merge(
        commits, commit_vfc_data[["sha", "vfc_prob"]], on=["sha"], how="left"
    )

    commits["vfc_prob"] = commits.vfc_prob.fillna(0)

    return commits