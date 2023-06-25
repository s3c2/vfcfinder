"""
Helper functions for locally cloned Git repos
"""
import datetime
import os
import subprocess
import git
import pandas as pd
import patchparser

from packaging.version import Version


def clone_repo(repo_owner:str, repo_name:str, clone_path:str, local_name=False):
    """Clone a Git repository to a local path

    Args:
        repo_owner (str): Repo Owner
        repo_name (str): Repo Name
        clone_path (str): Desired clone path
        local_name (bool): If a unique clone path is set
    """
    # set path
    if not local_name:
        clone_path = f"{clone_path}{repo_owner}/"
    else:
        clone_path = f"{clone_path}"

    if not os.path.exists(clone_path):
        os.makedirs(clone_path)

    if not local_name:
        # check if clone already exists
        if os.path.exists(f"{clone_path}{repo_name}"):
            print(f"Path already exists: {clone_path}{repo_name}")
        else:
            # clone repo
            # git.Git(clone_path).clone(f"https://{GITHUB_USERNAME}:
            # {GITHUB_TOKEN}@github.com/{repo_owner}/"
            #                           f"{repo_name.replace('.git', '')}.git")
            print(f"Cloning repo to: {clone_path}{repo_name}")
            git.Git(clone_path).clone(
                f"https://github.com/{repo_owner}/"
                f"{repo_name.replace('.git', '')}.git"
            )

    else:  # specific local folder name
        # check if clone already exists
        if os.path.exists(f"{clone_path}{local_name}"):
            print(f"Path already exists: {clone_path}{local_name}")
        else:
            # clone repo
            # git.Git(clone_path).clone(
            #     f"https://{GITHUB_USERNAME}:{GITHUB_TOKEN}@github.com/{repo_owner}/"
            #     f"{repo_name.replace('.git', '')}.git"
            # )
            print(f"Cloning repo to: {clone_path}{local_name}")
            git.Git(clone_path).clone(
                f"https://github.com/{repo_owner}/"
                f"{repo_name.replace('.git', '')}.git"
            )


def semver_sort(temp_versions):
    """Sorts semver tags based on pythons packaging.version

    Args:
        temp_versions (list): List of tags

    Returns:
        pd.DataFrame: Sorted tags based on semver
    """
    if temp_versions is not None:
        if len(temp_versions) > 0:
            clean_parse = []
            for each in temp_versions:
                try:
                    temp_version = Version(each)
                    temp_version.raw_version = each
                    temp_version.error = False
                    clean_parse.append(temp_version)
                except Exception as err:
                    print(err)
                    # TODO: this needs to be handled better
                    try:
                        clean_each = ".".join(each.split(".")[:3])
                        temp_version = Version(clean_each)
                        temp_version.raw_version = each
                        temp_version.error = True
                        clean_parse.append(temp_version)
                    except Exception as last_err:
                        print(f"Unkown version type, skipping: {each}")

            # sort the clean versions
            clean_parse.sort()

            clean_return = []

            for clean in clean_parse:
                clean_return.append(clean.raw_version)

            # create a df to sort the versions
            clean_return_df = pd.DataFrame(clean_return, columns=["tag"])
            clean_return_df["tag_order"] = clean_return_df.index

            return clean_return_df
    else:
        return []


def get_tags(repo_owner, repo_name, clone_path):
    """Obtains the local git repo tags for a given repository in a certain path

    Args:
        repo_owner (str): Repo owner
        repo_name (str): Name of repo
        clone_path (str): Local clone path of repo

    Returns:
        pd.DataFrame: A sorted pandas df of tags
    """

    # create repo path
    repo_path = f"{clone_path}{repo_owner}/{repo_name}/"

    # execute the git tags command
    git_tags_command = (
        f"(cd {repo_path} && "
        f"git for-each-ref --sort=v:refname --format '%(refname) %(creatordate)' refs/tags)"
    )

    # this is all trusted input....not a vulnerability
    git_tags = subprocess.check_output(
        git_tags_command, shell=True, encoding="UTF-8"
    ).splitlines()

    # load in the tag outputs
    if len(git_tags) > 0:
        temp_df = pd.DataFrame(git_tags, columns=["raw_out"])
        temp_df["repo_owner"] = repo_owner
        temp_df["repo_name"] = repo_name
        temp_df["tag_count"] = len(temp_df)

        # extract the creatordate
        temp_df["creatordate"] = temp_df.apply(
            lambda x: datetime.datetime.strptime(
                " ".join(x["raw_out"].strip("\n").split(" ")[1:-1]),
                "%a %b %d %H:%M:%S %Y",
            ),
            axis=1,
        )
        # extract the tag from the list
        temp_df["tag"] = temp_df.apply(
            lambda x: x["raw_out"].strip("\n").split(" ")[0].replace("refs/tags/", ""),
            axis=1,
        )

        # get the correct semver tag order
        temp_tags = temp_df["tag"].values.tolist()

        # sort the tags
        sorted_tags = semver_sort(temp_tags)

        # add the sorted tags back to the original df
        temp_df_sorted = pd.merge(temp_df, sorted_tags, on="tag", how="left")

    else:
        temp_df_sorted = pd.DataFrame(
            [["NO_TAGS", repo_owner, repo_name]],
            columns=["raw_out", "repo_owner", "repo_name"],
        )
        temp_df_sorted["tag_count"] = None
        temp_df_sorted["creatordate"] = None
        temp_df_sorted["tag"] = None
        temp_df_sorted["tag_order"] = None

    return temp_df


def get_prior_tag(
    repo_owner: str, repo_name: str, clone_path: str, target_tag: str
) -> dict:
    """Gets the prior tag to a fixed tag and matches the
    tag to the local git tags

    Args:
        repo_owner (str): Repo owner
        repo_name (str): Name of repo
        clone_path (str): Local clone path of repo
        target_tag (str): Known vulnerable tag

    Returns:
        {prior_tag: Prior tag that matches git version
        fixed_tag: Fixed tag that matches git version}
    """

    temp_tags = get_tags(repo_owner, repo_name, clone_path)

    # get the matching tag
    tag_match = temp_tags[temp_tags["tag"].str.contains(target_tag)].tag

    # get the tag rank based on the index
    tag_match_rank = tag_match.index[0]

    # get the prior tag, based on the index
    prior_tag_rank = tag_match_rank - 1

    # prior tag
    prior_tag = temp_tags.iloc[prior_tag_rank].tag

    # return the git tag_match
    return {"prior_tag": prior_tag, "current_tag": tag_match.iloc[0]}


def get_commits_between_tags(
    prior_tag: str, current_tag: str, temp_repo_path: str
) -> pd.DataFrame:
    """Returns the commits between two tags (prior_tag...current_tag)
    Columns:
        raw_git_log,
        sha,
        message

    Args:
        prior_tag (str): prior tag
        current_tag (str): target tag
        temp_repo_path (str): locally cloned repository path

    Returns:
        pd.DataFrame: DF of commits between two tags
    """
    # get the repo owner/name
    temp_repo_owner = temp_repo_path.split("/")[-2]
    temp_repo_name = temp_repo_path.split("/")[-1]

    # set the git.Git class for the repo
    temp_repo = git.Git(temp_repo_path)

    # obtain all commits
    temp_commits = pd.DataFrame(
        temp_repo.log(f"{prior_tag}...{current_tag}", "--pretty=oneline").split("\n"),
        columns=["raw_git_log"],
    )
    # set sha
    temp_commits["sha"] = temp_commits.apply(
        lambda x: x["raw_git_log"].split(" ")[0], axis=1
    )
    # set the message
    temp_commits["message"] = temp_commits.apply(
        lambda x: " ".join(x["raw_git_log"].split(" ")[1:]), axis=1
    )

    # get the full message
    temp_commits["full_message"] = temp_commits.apply(
        lambda x: get_full_commit_message(
            sha=x["sha"],
            temp_git=temp_repo,
        ),
        axis=1,
    )

    # add the normalized commit rank. A future feature. Add 1 so it matches length
    temp_commits["commit_rank"] = temp_commits.index + 1

    # normalize the commit rank based on the commits
    temp_commits["normalized_commit_rank"] = temp_commits.apply(
        lambda x: int(x["commit_rank"]) / len(temp_commits), axis=1
    )

    return temp_commits


def get_full_commit_message(sha: str, temp_git: git.Git) -> str:
    """Returns the full commit message for a given commit sha

    Args:
        sha (str): Target Sha
        temp_git (git.Git): git.Git repo

    Returns:
        str: The output message
    """
    message = (
        temp_git.log(f"{sha}", "--oneline", "--format=%H %s %b", "-n", "1")
        .split("\n")[0]
        .split(" ")
    )
    final_message = " ".join(message[1:])

    return final_message


def git_diff(clone_path: str, commit_sha: str) -> dict:
    """Obtains the git diff information using patchparser
    Info: https://github.com/tdunlap607/patchparser

    Args:
        clone_path (str): Location of source code
        commit_sha (_type_): Target commit to parse

    Returns:
        (dict): Dictionary of git diff info
    """

    repo_owner = clone_path.split("/")[-3]
    repo_name = clone_path.split("/")[-2]

    diff = patchparser.github_parser_local.commit_local(
        repo_owner=repo_owner,
        repo_name=repo_name,
        sha=commit_sha,
        base_repo_path=clone_path,
    )

    return diff
