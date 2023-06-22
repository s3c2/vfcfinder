"""
The command line utility to match commits to a VFC
Returns a set of five potential VFCs for the advisory
"""
import argparse

from vfcfinder import vfc_ranker


def main():
    # Parsing arguments
    parser = argparse.ArgumentParser(
        description="VFCFinder - matches commits to a security advisory.",
        epilog="More info: https://github.com/s3c2/vfcfinder",
    )

    # Add required paths
    requiredNamed = parser.add_argument_group("required arguments")
    requiredNamed.add_argument(
        "--advisory_path",
        type=str,
        help="Path to target OSV security advisory",
        required=True,
    )
    requiredNamed.add_argument(
        "--clone_path",
        type=str,
        help="Path to clone the GitHub Repository",
        required=True,
    )

    # Add optional args
    parser.add_argument(
        "--output_path",
        type=str,
        help="Path to save output to a CSV",
        required=False,
    )

    args = parser.parse_args()

    if not args.advisory_path and not args.clone_path:
        parser.print_usage()
        parser.exit()
    else:
        GHSA_ID = args.advisory_path
        CLONE_DIRECTORY = args.clone_path

    if args.output_path:
        vfc_ranker.rank(temp_clone_path=CLONE_DIRECTORY, temp_ghsa_path=GHSA_ID, save_path=args.output_path)
    else:
        # call the ranker
        vfc_ranker.rank(temp_clone_path=CLONE_DIRECTORY, temp_ghsa_path=GHSA_ID)


if __name__ == '__main__':
    main()