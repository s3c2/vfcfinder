"""
Provides the VFC identification probability
"""
import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, AdamW
import torch.nn as nn
from transformers import AutoModel, AutoConfig
from transformers.modeling_utils import PreTrainedModel

from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import numpy as np
from tqdm import tqdm



def get_owasp_label_map() -> pd.DataFrame:
    """Custom mapping of the OWASP labels for our trained XGBoost Model

    Returns:
        pd.DataFrame: Custom mapping of OWASP labels
    """
    
    # the order of the label is mixed because we didn't have A06 in training data
    owasp_list = [
        ["Broken Access Control", "A01", 0, 1],
        ["Cryptographic Failures", "A02", 1, 2],
        ["Injection", "A03", 2, 3],
        ["Insecure Design", "A04", 3, 4],
        ["Security Misconfiguration", "A05", 4, 5],
        ["Vulnerable and Outdated Components", "A06", 10, 6],
        ["Identification and Authentication Failures", "A07", 5, 7],
        ["Software and Data Integrity Failures", "A08", 6, 8],
        ["Security Logging and Monitoring Failures", "A09", 7, 9],
        ["Server-Side Request Forgery", "A10", 8, 10],
        ["Other", "Other", 9, 11],
    ]

    # convert to a dataframe
    owasp_map = pd.DataFrame(
        owasp_list, columns=["name", "short_name", "label", "rank"]
    )

    return owasp_map


def pure_modified_code(temp_raw_patch: str) -> str:
    """Obtains +/- aspects of the git diff
    Split the code so we can parse line by line

    Args:
        temp_raw_patch (str): Raw patch string from patchparser

    Returns:
        str: Cleaned concat of the modified code
    """
    # make sure it's a string
    temp_raw_patch = str(temp_raw_patch)
    split_code = temp_raw_patch.splitlines()

    temp_modified_code = ""

    # obtain the modified/removed/added code
    for line in split_code:
        if line.startswith("-") or line.startswith("+"):
            temp_modified_code = temp_modified_code + " " + line

    return temp_modified_code


def load_ghsa_vfc_data(
    vuln_file: str, class_name: str, group_level: list
) -> pd.DataFrame:
    """Creates a clean pd.DataFrame of the commits to analyze

    Args:
        vuln_file (str): Commits
        class_name (str): 
        group_level (list): Granularity to make predictions

    Returns:
        pd.DataFrame: Clean DF of commits
    """

    # create a group level
    unique_groups = ["repo_owner", "repo_name", "sha"] + group_level

    # # load data
    # vuln_commits = pd.read_csv(vuln_file, low_memory=False)

    vuln_commits = pd.DataFrame(vuln_file)

    # Only look at the following code types
    # look at only important languages
    imporant_languages = {
        "c": "C/C++",
        "cpp": "C/C++",
        "cc": "C/C++",
        "java": " Java",
        "py": "Python",
        "go": "Go",
        "php": "PHP",
        "rb": "Ruby",
        "ts": "TypeScript",
        "js": "JavaScript",
        "cs": "C#",
        "rs": "Rust",
    }

    vuln_commits["important_language"] = vuln_commits.apply(
        lambda x: True if x["file_extension"] in imporant_languages else False, axis=1
    )

    # keep only important languages
    vuln_commits = vuln_commits[vuln_commits["important_language"] == True].reset_index(
        drop=True
    )

    vuln_commits["vfc_label"] = True
    vuln_commits["file_type"] = vuln_commits["file_extension"]

    commits = vuln_commits.reset_index(drop=True)

    # create a unique id
    commits["id"] = commits.apply(
        lambda x: f"{x['repo_owner']}_{x['repo_name']}_{x['sha']}", axis=1
    )

    # get pure modified code
    commits["pure_modified_code"] = commits.apply(
        lambda x: pure_modified_code(x["raw_patch"]), axis=1
    )

    # grouping for aggregation
    agg_group = unique_groups + ["pure_modified_code"]
    # Group by Language
    commits["file_pure_modified_code"] = (
        commits[agg_group]
        .groupby(unique_groups)["pure_modified_code"]
        .transform(lambda x: " ".join(x))
    )

    # Keep certain levels (e.g., message/file)
    commits = commits.drop_duplicates(subset=unique_groups, keep="first")

    # remove NANs and duplicates
    commits_clean = commits.dropna(
        subset=["vfc_label", "file_pure_modified_code", "message"]
    )

    # Double check duplicates are dropped. Also drop duplicates on the class_name (e.g., owasp_desc)
    commits_clean = commits_clean.drop_duplicates(
        subset=unique_groups + ["vfc_label"], keep="first"
    )

    # make sure raw_patch is a string
    commits_clean["message"] = commits_clean["message"].astype(str)
    commits_clean["file_pure_modified_code"] = commits_clean[
        "file_pure_modified_code"
    ].astype(str)

    # really make sure file_pure_modified_code is clean
    commits_clean["agg_length"] = commits_clean.apply(
        lambda x: len(x["file_pure_modified_code"]), axis=1
    )
    commits_clean = commits_clean[commits_clean["agg_length"] > 0]

    # Create labels suitable for ML
    le = LabelEncoder()
    labels = le.fit_transform(commits_clean["vfc_label"])
    commits_clean["label"] = labels

    # OneHotEncoder
    enc = OneHotEncoder(handle_unknown="ignore")
    transformed = enc.fit_transform(commits_clean[["label"]])
    commits_clean["onehot_label"] = transformed.toarray().tolist()

    # reset the index
    commits_clean = commits_clean[
        unique_groups
        + ["id", "file_pure_modified_code", "label", "onehot_label", class_name]
    ].reset_index(drop=True)

    # sort by ID
    commits_clean = commits_clean.sort_values(by="id").reset_index(drop=True)

    return commits_clean


def load_vfc_identification_model():
    """Loads the tokenizer/model from huggingface to predict if a commit is a VFC
    https://huggingface.co/tdunlap607/vfc-identification
    """
    # load tokenizer
    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")

    # loads the model
    model = AutoModel.from_pretrained(
        "tdunlap607/vfc-identification", trust_remote_code=True
    )

    return tokenizer, model


def load_vfc_type_model():
    """Loads the tokenizer/model from huggingface to predict if a commit is a VFC
    https://huggingface.co/tdunlap607/vfc-type
    """
    # load tokenizer
    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")

    # loads the model
    model = AutoModel.from_pretrained("tdunlap607/vfc-type", trust_remote_code=True)

    return tokenizer, model


class ConvertDataset(Dataset):
    def __init__(
        self, df, tokenizer, text_name: str, text_pair_name: str, target_label: str
    ):
        self.df_data = df
        self.tokenizer = tokenizer
        self.text_name = text_name  # e.g., message
        self.text_pair_name = text_pair_name  # e.g., file_pure_modified_code
        self.target_label = target_label  # e.g., onehot_label

    def __getitem__(self, index):
        # get the sentence from the dataframe
        text = self.df_data.loc[index, self.text_name]
        text_pair = self.df_data.loc[index, self.text_pair_name]

        # Process the sentence
        # ---------------------
        # Tokenize the sentence using the above tokenizer from BERT
        # Special tokens will add [CLS]parent_sentence[SEP]child_sentence[SEP]
        # Return attenion masks
        # https://huggingface.co/docs/transformers/v4.22.2/en/internal/tokenization_utils#transformers.PreTrainedTokenizerBase.encode_plus
        # encoded_dict = self.tokenizer.encode_plus(
        # encode_plus is deprecated
        # https://huggingface.co/docs/transformers/v4.24.0/en/internal/tokenization_utils#transformers.PreTrainedTokenizerBase.__call__
        encoded_dict = self.tokenizer.__call__(
            text=text,
            text_pair=text_pair,
            add_special_tokens=True,
            padding="max_length",
            truncation=True,
            return_attention_mask=True,
            return_token_type_ids=True,
            return_tensors="pt",
        )

        # each of these are in the form of a pt
        padded_token_list = encoded_dict["input_ids"][0]
        att_mask = encoded_dict["attention_mask"][0]
        token_type_ids = encoded_dict["token_type_ids"][0]

        # Convert the target to a torch tensor
        target = torch.tensor(self.df_data.loc[index, self.target_label])

        sample = (padded_token_list, att_mask, token_type_ids, target)

        return sample

    def __len__(self):
        return len(self.df_data)


def convert_df_to_dataloader(
    tokenizer,
    temp_df: pd.DataFrame,
    text: str,
    text_pair: str,
    target: str,
    batch_size: int,
):
    """_summary_

    Args:
        tokenizer : Loaded tokenizer
        temp_df (pd.DataFrame): Commits DF
        text (str): Commit message
        text_pair (str): Code diff
        target (str): Target Label
        batch_size (int): Batch size

    Returns:
        dataloader for downstream use
    """
    # Does the tokenization
    temp_data = ConvertDataset(
        df=temp_df,
        tokenizer=tokenizer,
        text_name=text,
        text_pair_name=text_pair,
        target_label=target,
    )

    # No need to shuffle as the data has already been shuffled in the splits
    temp_dataloader = torch.utils.data.DataLoader(
        temp_data, batch_size=batch_size, num_workers=8, shuffle=False
    )

    return temp_dataloader



def validation_model_single_epoch(
    model,
    val_dataloader,
    device: str,
    binary_classification=False,
    class_weights=None,
):
    """_summary_

    Args:
        model : Loaded HF model
        val_dataloader (_type_): convert_df_to_dataloader()
        device (str): Device type
        binary_classification (bool, optional): Defaults to False.
        class_weights (list, optional): Class weights. Defaults to None.

    Returns:
        Model predictions (prediction, raw_prediction)
    """

    # place model in evaluation mode
    model.eval()

    # arrays to hold predictions and
    val_prediction_labels = np.array([])
    if class_weights is None:
        # TODO: Better way to handle the length of this when we don't pass class weights
        if binary_classification:
            val_raw_probs_preds = np.array([]).reshape(0, 2)
        else:
            val_raw_probs_preds = np.array([]).reshape(0, 10)
    else:
        val_raw_probs_preds = np.array([]).reshape(
            0, len(class_weights)
        )  # reshape to handle better appends

    with torch.no_grad():
        # create a progress bar
        val_bar = tqdm(enumerate(val_dataloader), total=len(val_dataloader))

        # loop through each batch
        for i, val_batch in val_bar:
            # obtain all the various ids/masks/tokens/labels from the train_dataloader
            val_batch_input_ids = val_batch[0].to(device)
            val_batch_attention_mask = val_batch[1].to(device)
            val_batch_token_type_ids = val_batch[2].to(device)
            # val_batch_labels = val_batch[3].to(device)

            # Get the model output
            val_output = model(
                input_ids=val_batch_input_ids,
                attention_mask=val_batch_attention_mask,
                token_type_ids=val_batch_token_type_ids,
            )

            # collect raw probabilities for each class of the prediction. Helps later when aggregating results to commit-level
            if binary_classification:
                # no need for softmax on already Sigmoid values for probs
                val_raw_probs = val_output.cpu().detach().numpy()
                val_raw_probs_preds = np.append(val_raw_probs_preds, val_raw_probs)
                # for binary if the value is above 0.5 then 1, else 0
                output_label = (val_raw_probs > 0.5).squeeze(1).astype(int)

            else:
                val_raw_probs = torch.softmax(val_output, dim=1).cpu().detach().numpy()
                val_raw_probs_preds = np.append(
                    val_raw_probs_preds, val_raw_probs, axis=0
                )  # axis=0 keeps the shape of the probs

                output_label = np.argmax(val_raw_probs, axis=1)

            val_prediction_labels = np.append(val_prediction_labels, output_label)

        return val_prediction_labels, val_raw_probs_preds
