"""
Helper function for the final ranking model
"""
import pandas as pd
import xgboost as xgb


def rank_commits(temp_commits: pd.DataFrame, temp_features: list) -> pd.DataFrame:
    """Ranks a set of commit in how relevant they are to a given security advisory

    Args:
        temp_commits (pd.DataFrame): Commits with associated features
        temp_features (list): List of features

    Returns:
        pd.DataFrame: Ranked commits in relevance to a given security advisory
    """

    # load the pre-trained XGBoost model
    loaded_model = xgb.Booster()
    loaded_model.load_model("./model/xgboost_model_20230617.json")

    # prepare the data for inference
    temp_data = temp_commits.loc[:, temp_commits.columns.isin(temp_features)]

    # convert to a DMatrix
    dPredict = xgb.DMatrix(temp_data)

    # get the predictions
    predictions = loaded_model.predict(dPredict)
