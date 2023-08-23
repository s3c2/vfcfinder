"""
Provides the semantic similarity between a given commit and an advisory.
"""
import pandas as pd
from sentence_transformers import SentenceTransformer, util


def semantic_similarity(full_message: str, advisory_details: str) -> float:
    """Calculate the semantic similarity using sentence-transformers and cosign similarity

    Args:
        full_message (str): Full message of the commit
        advisory_details (str): Full details of the advisory

    Returns:
        float: Similarity score
    """
    # set the model
    model = SentenceTransformer("all-mpnet-base-v2")

    # encode the sentences to their respective embeddings
    if pd.isna(full_message) or pd.isna(advisory_details):
        return float(0)
    else:
        # encode the message and advisory text
        mess_encode = model.encode(full_message)
        adv_encode = model.encode(advisory_details)

        # calculate the cosine similarity
        result = util.cos_sim(mess_encode, adv_encode)

        # convert to a float
        result_float = result.item()

        return result_float


def semantic_similarity_batch(temp_commits: pd.DataFrame, advisory_details: str) -> pd.DataFrame:
    """Calculate the semantic similarity for a batch using sentence-transformers and cosign similarity

    Args:
        commits (pd.DataFrame): Commits DF generated from git_helper.get_commits_between_tags
        advisory_details (str): Full details of the advisory

    Returns:
        pd.DataFrame: Updated commits DF with the similarity score
    """
    # set the model
    model = SentenceTransformer("all-mpnet-base-v2")
    
    # set the advisory details in the commits DF
    temp_commits['advisory_details'] = advisory_details

    # encode the sentences to their respective embeddings
    # encode the message and advisory text
    mess_encode = model.encode(temp_commits['full_message'].values.tolist(), 
                               convert_to_tensor=True)
    adv_encode = model.encode(temp_commits['advisory_details'].values.tolist(),
                              convert_to_tensor=True)

    # calculate the cosine similarity
    result = util.cos_sim(mess_encode, adv_encode)
    
    # convert the tensor to a list
    result_list = [x[0] for x in result.tolist()]

    return result_list