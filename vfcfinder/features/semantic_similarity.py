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
