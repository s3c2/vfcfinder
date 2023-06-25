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
        help="Local path to clone the GitHub Repository",
        required=True,
    )

    # Add optional args
    parser.add_argument(
        "--output_path",
        type=str,
        help="Local path to save output to a CSV",
        required=False,
    )

    args = parser.parse_args()

    if not args.advisory_path and not args.clone_path:
        parser.print_usage()
        parser.exit()
    else:
        ADVISORY_PATH = args.advisory_path
        CLONE_PATH = args.clone_path

    if args.output_path:
        vfc_ranker.rank(advisory_path=ADVISORY_PATH, clone_path=CLONE_PATH, save_path=args.output_path)
    else:
        # call the ranker
        vfc_ranker.rank(advisory_path=ADVISORY_PATH, clone_path=CLONE_PATH)


if __name__ == '__main__':
    main()