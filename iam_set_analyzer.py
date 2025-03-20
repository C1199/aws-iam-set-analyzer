import argparse
import scrape_iam_actions.load_service_auth
import set_analyzer.analyzer
import scrape_iam_actions
import set_analyzer.reporter
import pandas as pd


def build_arg_parser():

    arg_parser = argparse.ArgumentParser()
    basic_usage = arg_parser.add_argument_group()

    basic_usage.add_argument(
        "--policy",
        help="File location of the iam policy json file to analyse"
    )

    return arg_parser


if __name__ == "__main__":

    arg_parser = build_arg_parser()
    arguments = arg_parser.parse_args()

    if arguments.policy:
        policy = set_analyzer.analyzer.load_policy_from_file(arguments.policy)
        result = set_analyzer.analyzer.determine_effective_permissions_for_policy(policy)
        set_analyzer.reporter.render_template(policy,result.to_html())

        #result.to_html('tmp.html')