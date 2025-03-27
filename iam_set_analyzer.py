import argparse
import json
import set_analyzer.analyzer
import set_analyzer.reporter

def build_arg_parser():

    arg_parser = argparse.ArgumentParser()
    basic_usage = arg_parser.add_argument_group()

    basic_usage.add_argument(
        "--policy",
        help="File location of the iam policy json file to analyse"
    )

    basic_usage.add_argument(
        "--boundaries",
        nargs='+',
        help="List of file names for boundary analysis",
        required=False
    )

    return arg_parser


if __name__ == "__main__":

    arg_parser = build_arg_parser()
    arguments = arg_parser.parse_args()

    if arguments.policy:
        policy = set_analyzer.analyzer.load_policy_from_file(arguments.policy)
        result = set_analyzer.analyzer.determine_effective_permissions_for_policy(policy)
        data = json.loads(result.to_json(orient='table'))['data']
        set_analyzer.reporter.render_template(policy,data)
    if arguments.boundaries is not None:
        policy = set_analyzer.analyzer.load_policy_from_file(arguments.policy)
        boundary_policies = [set_analyzer.analyzer.load_policy_from_file(x) for x in arguments.boundaries]
        result = set_analyzer.analyzer.determine_effective_permissions_for_policy_and_boundary(policy, boundary_policies)
        data = json.loads(result.to_json(orient='table'))['data']
        set_analyzer.reporter.render_template(policy,data, boundary_policies)

