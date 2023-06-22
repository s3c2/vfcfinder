"""
Helper functions to read OSV formats
"""
import json
import pandas as pd


def parse_osv(osv_json_filename: str, osv_schema: dict) -> dict:
    """The purpose of this function is to open and parse OSV formatted files
    OSV Schema: https://ossf.github.io/osv-schema/

    Args:
        osv_json_filename (str): File Location of OSV JSON to parse
        osv_schema (dict): https://github.com/ossf/osv-schema/blob/main/validation/schema.json

    Returns:
        dict: _description_
    """
    # Open the json
    with open(osv_json_filename, "r") as f:
        osv_json = json.load(f)

    # OSV Properities or the keys of the schema
    osv_keys = osv_schema["properties"]

    osv_parsed = dict()
    affected_base = pd.DataFrame()

    # Parse the data for a specific manner that will load in DFs better
    for key in osv_keys:
        if osv_keys[key]["type"] == "string":
            if key in osv_json:
                osv_parsed[key] = osv_json[key]
            else:
                osv_parsed[key] = None
        elif osv_keys[key]["type"] == "array":
            if osv_keys[key]["items"]["type"] == "string":
                if key in osv_json:
                    osv_parsed[key] = [item for item in osv_json[key]]
                else:
                    osv_parsed[key] = []
            elif osv_keys[key]["items"]["type"] == "object":
                if key == "references":
                    if key in osv_json:
                        osv_parsed["reference_type"] = [
                            ref["type"] for ref in osv_json[key]
                        ]
                        osv_parsed["reference_url"] = [
                            ref["url"] if "url" in ref else None
                            for ref in osv_json[key]
                        ]
                        osv_parsed["reference_combined"] = [
                            [ref["type"], ref["url"]] if "url" in ref else None
                            for ref in osv_json[key]
                        ]

                    else:
                        osv_parsed["reference_type"] = []
                        osv_parsed["reference_url"] = []
                        osv_parsed["reference_combined"] = []

                if key == "affected":
                    if key in osv_json:
                        osv_parsed["ecosystem"] = osv_json[key][0]["package"][
                            "ecosystem"
                        ]
                        osv_parsed["package_name"] = osv_json[key][0]["package"]["name"]

                        try:
                            # affected complete
                            affected_base = pd.json_normalize(
                                osv_json, record_path=["affected"]
                            )
                            affected_base = pd.json_normalize(osv_json[key])

                            # affected ranges (versions)
                            affected_ranges = pd.json_normalize(
                                osv_json[key], record_path=["ranges"]
                            )

                            affected_ranges["introduced"] = affected_ranges.apply(
                                lambda x: x["events"][0]["introduced"], axis=1
                            )

                            affected_ranges["fixed"] = affected_ranges.apply(
                                lambda x: x["events"][1]["fixed"]
                                if "fixed" in str(x["events"])
                                else None,
                                axis=1,
                            )

                            affected_ranges["limit"] = affected_ranges.apply(
                                lambda x: x["events"][1]["limit"]
                                if "limit" in str(x["events"])
                                else None,
                                axis=1,
                            )

                            affected_base = pd.merge(
                                affected_base,
                                affected_ranges,
                                right_index=True,
                                left_index=True,
                                how="inner",
                            )

                            affected_base = affected_base.drop(
                                columns=["ranges", "events"]
                            )

                            affected_base["id"] = osv_parsed["id"]
                        except:
                            # Issues will be handled downstream
                            affected_base["id"] = osv_parsed["id"]

                    else:
                        osv_parsed["ecosystem"] = []
                        osv_parsed["package_name"] = []
                        osv_parsed["package_purl"] = []
        elif osv_keys[key]["type"] == "object":
            if key == "database_specific":
                if key in osv_json:
                    osv_parsed["cwe_ids"] = osv_json[key]["cwe_ids"]
                    osv_parsed["severity"] = osv_json[key]["severity"]
                    # TODO: Handle all CWEs instead of just the first one listed
                    affected_base["cwe_ids"] = osv_json[key]["cwe_ids"][0]
                else:
                    osv_parsed["cwe_ids"] = None
                    osv_parsed["severity"] = None
                    affected_base["cwe_ids"] = None

    return osv_parsed, affected_base


def pull_ghsa_web(ghsa_id: str):
    """Pulls the raw json GHSA from GitHub

    Args:
        ghsa_id (str): GHSA-ID

    Returns:
        ghsa_json (dict)
    """
    # TODO: Handle a web request
    return None
