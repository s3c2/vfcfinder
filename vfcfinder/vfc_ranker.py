"""
The primary function for finding VFCs for a given security advisory
Returns a set of five potential VFCs for the advisory
"""
import json
import pandas as pd
import torch
import numpy as np
import xgboost as xgb
import argparse

from pathlib import Path
from vfcfinder.utils import osv_helper, git_helper
from vfcfinder.features import vfc_identification, static_features, semantic_similarity


def rank(advisory_path: str, clone_path: str, return_results=False, output_path=None):
    """Ranks commits in relevance to a given security advisory

    Args:
        advisory_path (str): Local path to a security advisory
        clone_path (str): Local path to clone a repository
        return_restuls (bool): Returns sorted commits in a pd.DataFrame
        output_path (str): Path to save results in a CSV form
    """
    # SET args
    GHSA_ID = advisory_path
    CLONE_DIRECTORY = clone_path

    # dynamically set variables
    PARENT_PATH = f"{str(Path(__file__).resolve().parent.parent)}/"
    DEVICE = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    #####################################################################################
    # load/parse report
    with open(f"{PARENT_PATH}vfcfinder/data/osv_schema.json", "r") as f:
        osv_schema = json.load(f)
        f.close()

    # parse the JSON
    parsed = osv_helper.parse_osv(
        osv_json_filename=f"{GHSA_ID}",
        osv_schema=osv_schema,
    )

    # create a dataframe that's easier to handle
    parsed_df = parsed[1].copy()

    # identify the repo_url
    repo_url = parsed[0]["reference_url"][parsed[0]["reference_type"].index("PACKAGE")]

    # extract the base repo owner/name
    repo_owner = repo_url.split("/")[-2]
    repo_name = repo_url.split("/")[-1]

    # set a clone path
    CLONE_PATH = f"{CLONE_DIRECTORY}{repo_owner}/{repo_name}/"

    #####################################################################################
    # clone repo
    print(f"\nCloning repository: {repo_owner}/{repo_name}")
    git_helper.clone_repo(
        repo_owner=repo_owner, repo_name=repo_name, clone_path=CLONE_DIRECTORY
    )

    #####################################################################################
    # find fixed/vulnerable version
    fix_tag = parsed[1].fixed.iloc[-1]

    #####################################################################################
    # load the OWASP Lookup table and map
    owasp_data = pd.read_csv(
        f"{PARENT_PATH}/vfcfinder/utils/data_lookup/owasp2021_map.csv"
    )
    owasp_data["cwe_ids"] = owasp_data.apply(lambda x: f"CWE-{x['cwe']}", axis=1)
    owasp_map = vfc_identification.get_owasp_label_map()

    # set the owasp_label from training
    owasp_data = pd.merge(
        owasp_data,
        owasp_map[["rank", "label"]],
        left_on="owasp_rank",
        right_on="rank",
        how="left",
    )

    # set the parsed owasp_label
    parsed_df = parsed_df.merge(
        owasp_data[["owasp_rank", "cwe_ids", "label"]], on="cwe_ids", how="left"
    )

    #####################################################################################
    # get the prior and fixed tag of the local repo
    tags = git_helper.get_prior_tag(
        repo_owner=repo_owner,
        repo_name=repo_name,
        clone_path=CLONE_DIRECTORY,
        target_tag=fix_tag,
    )

    # set the vulnerable/fixed tags
    repo_vuln_tag = tags["prior_tag"]
    repo_fix_tag = tags["current_tag"]

    #####################################################################################
    # load all commits
    commits = git_helper.get_commits_between_tags(
        prior_tag=repo_vuln_tag,
        current_tag=repo_fix_tag,
        temp_repo_path=CLONE_PATH,
    )

    #####################################################################################
    # generate features
    # patchparser for each commit
    commits_diff = pd.DataFrame()

    # get the diff of each commit
    for idx, row in commits.iterrows():
        print(f"Obtaining diff for commit {idx+1}/{len(commits)} || {row['sha'][:7]}")
        temp_diff = git_helper.git_diff(
            clone_path=CLONE_PATH,
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

    # delete the model
    del model

    #####################################################################################
    # vfc_type
    print("\nGenerating VFC type inference for each commit...")
    tokenizer, model = vfc_identification.load_vfc_type_model()

    model.to(DEVICE)

    type_preds, type_probs = vfc_identification.validation_model_single_epoch(
        model,
        val_dataloader=commit_dataloader,
        device=DEVICE,
        binary_classification=False,
        class_weights=None,
    )

    commit_vfc_data["vfc_type"] = list(type_probs)

    commit_vfc_data["vfc_type_top_5"] = commit_vfc_data.apply(
        lambda x: np.array(list(x["vfc_type"])).argsort()[-5:][::-1].tolist(),
        axis=1,
    )

    commit_vfc_data["vfc_type_top_1"] = commit_vfc_data.apply(
        lambda x: True if parsed_df.iloc[0].label == x["vfc_type_top_5"][0] else False,
        axis=1,
    )

    commit_vfc_data["vfc_type_top_5"] = commit_vfc_data.apply(
        lambda x: True if parsed_df.iloc[0].label in x["vfc_type_top_5"] else False,
        axis=1,
    )

    # merge the probabilities back to the commits
    commits = pd.merge(
        commits,
        commit_vfc_data[["sha", "vfc_type_top_1", "vfc_type_top_5"]],
        on=["sha"],
        how="left",
    )

    commits["vfc_type_top_1"] = commits.vfc_type_top_1.fillna(False)
    commits["vfc_type_top_5"] = commits.vfc_type_top_5.fillna(False)

    del model

    #####################################################################################
    # semantic similarity
    print("\n")
    # similarity_df = pd.DataFrame()

    # for idx, row in commits.iterrows():
    #     print(
    #         f"Generating semantic similarity scores: {idx+1}/{len(commits)} || {row['sha'][:7]}"
    #     )
    #     temp_sim = semantic_similarity.semantic_similarity(
    #         full_message=row["full_message"], advisory_details=parsed[0]["details"]
    #     )
    #     similarity_df = pd.concat(
    #         [
    #             similarity_df,
    #             pd.DataFrame(
    #                 [[row.sha, temp_sim]], columns=["sha", "semantic_similarity"]
    #             ),
    #         ]
    #     )
        
    print("Generating semantic similarity scores...")
        
    # batch all the commits for a semantic similarity
    commits["semantic_similarity"] = semantic_similarity.semantic_similarity_batch(
        temp_commits=commits.copy(), advisory_details=parsed[0]["details"]
    )

    # merge similarity scores back to commits
    # commits = commits.merge(similarity_df, on=["sha"], how="left")

    #####################################################################################
    # cve/ghsa in message
    commits["cve_in_message"] = commits.apply(
        lambda x: static_features.cve_in_commit_message(
            x["full_message"], parsed[0]["aliases"][0]
        ),
        axis=1,
    )

    commits["ghsa_in_message"] = commits.apply(
        lambda x: static_features.ghsa_in_commit_message(
            x["full_message"], parsed[0]["id"]
        ),
        axis=1,
    )

    #####################################################################################
    # commit rank
    ranking_model = xgb.Booster()
    ranking_model.load_model(
        f"{PARENT_PATH}/vfcfinder/models/xgboost_model_20230618.json"
    )

    # set the features to use
    features = [
        "normalized_commit_rank",
        "vfc_prob",
        "vfc_type_top_1",
        "vfc_type_top_5",
        "semantic_similarity",
        "ghsa_in_message",
        "cve_in_message",
    ]
    # rename from the original trained model
    ranking_model.feature_names = features

    # create a new dataset for the features data
    ranking_data = commits[features].reset_index(drop=True)

    # convert labels to ints for XGBoost
    ranking_data["vfc_type_top_1"] = ranking_data["vfc_type_top_1"].astype(int)
    ranking_data["vfc_type_top_5"] = ranking_data["vfc_type_top_5"].astype(int)
    ranking_data["ghsa_in_message"] = ranking_data["ghsa_in_message"].astype(int)
    ranking_data["cve_in_message"] = ranking_data["cve_in_message"].astype(int)

    # convert to a DMatrix, XGBoost speed
    d_ranking = xgb.DMatrix(ranking_data)

    # make the predictions
    ranked_data_probs = ranking_model.predict(d_ranking)

    # merge back to the commits DF
    ranked_data_probs_list = list(ranked_data_probs)
    commits["ranking_prob"] = ranked_data_probs_list

    # make final ranked prediction
    commits = commits.sort_values("ranking_prob", ascending=False).reset_index(
        drop=True
    )

    # print the top ranked commits
    print(f"\nRanked commits in relevance to advisory {GHSA_ID}:")
    for idx, row in commits[:5].iterrows():
        print(
            f"Rank {idx+1} || "
            f" SHA: {row.sha[:7]} || "
            f" Commit Message: {row.message[:40]} || "
            f"VFC Prob: {round(row.vfc_prob, 2)}"
        )
    
    # save results
    if output_path is not None:
        commits.to_csv(output_path, encoding='utf-8', index=False)

    # return results for later use
    if return_results:
        return commits
