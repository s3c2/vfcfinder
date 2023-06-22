"""
Generates static features:
    - Normalized Commit Rank
    - CVE/GHSA-ID in message
"""
import pandas as pd


def normalized_commit_rank(commit_list: pd.DataFrame, target_sha: str) -> float:
    """Returns the normalized commit rank for a given commit

    Args:
        commit_list (pd.DataFrame): See git_helper.get_commits_between_tags()
        target_sha (str): Target SHA to obtain the normalized_commit_rank

    Returns:
        float: Normalized commit rank
    """

    temp_normalized_commit_rank = commit_list[
        commit_list["sha"] == target_sha
    ].normalized_commit_rank

    return temp_normalized_commit_rank


def cve_in_commit_message(full_message: str, cve: str) -> float:
    """Checks is a CVE is in the commit message

    Args:
        full_message (str): Full message of the commit
        cve (str): CVE-ID for a given report

    Returns:
        bool: True/False if CVE is in message
    """

    # check if CVE-ID is in the full message
    if cve.lower() in full_message.lower():
        return True
    else:
        return False


def ghsa_in_commit_message(full_message: str, ghsa: str) -> float:
    """Checks is a GHSA-ID is in the commit message

    Args:
        full_message (str): Full message of the commit
        ghsa (str): GHSA-ID for a given report

    Returns:
        bool: True/False if GHSA-ID is in message
    """

    # check if GHSA-ID is in the full message
    if ghsa.lower() in full_message.lower():
        return True
    else:
        return False
