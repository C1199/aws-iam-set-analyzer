import pandas as pd
import json
from scrape_iam_actions import load_service_auth
import importlib
from collections import defaultdict
from fnmatch import fnmatch

importlib.reload(load_service_auth)

def extract_service_from_arn(arn):
    '''
    Takes in an ARN an returns the service
    arn:partition:service:region:account-id:resource-id
    arn:partition:service:region:account-id:resource-type/resource-id
    arn:partition:service:region:account-id:resource-type:resource-id
    '''
    service_prefix = arn.split(":")[2]
    return service_prefix

def extract_resource_type_from_arn(arn):
    '''
    Takes in an ARN an returns the service
    arn:partition:service:region:account-id:resource-id
    arn:partition:service:region:account-id:resource-type/resource-id
    arn:partition:service:region:account-id:resource-type:resource-id
    '''
    resource_type = arn.split(":")[6].split("/")[0]
    return resource_type

def check_if_arn_is_the_weird_typless_one(arn):
    '''
    This might come in handy later
    '''
    return

def load_policy_from_file(policy_file):
    '''
    policy_file str location of thing
    '''

    with open(policy_file, "r") as r:
        policy_json = json.loads(r.read())

    return policy_json

def wildcard_match_list(string_to_search, check_list: list):
    '''
    Iterates through a list of items to use fnmatch against and returns True if any item matches.
    This is useful when applied as a function to a pandas dataframe.
    string_to_search str the exact item you want to match with
    check_list list the list of items you want to check for matches (including wildcards)
    '''
    match =  False

    for item in check_list:
        if fnmatch(string_to_search.lower(), item.lower()):
            match = True

    return match

def wildcard_match_list_reverse(string_to_search, check_list: list, match_prefix='', match_suffix=''):
    '''
    Iterates through a list of items to use fnmatch against and returns True if any item matches.
    This is useful when applied as a function to a pandas dataframe.
    string_to_search str the wildcard item you want to find matches for
    check_list list the list of items you want to check for matches (including wildcards)
    '''
    match =  False
    # in this check
    for item in check_list:
        if fnmatch(item.lower(), f"{match_prefix}{string_to_search.lower()}{match_suffix}"):
            match = True

    return match

def calculate_set_of_actions(statement):
    '''
    Takes in a statement chunk from a policy. 
    Identifies the total set of actions described in the Actions list
    '''

    # create a dictionary of the services and corresponding actions
    actions_dict = defaultdict(list)

    for action in statement['Action']:
        if action == "*":
            actions_dict['*'].append('*')
        else:
            service = action.split(":")[0]
            action = action.split(":")[1]
            actions_dict[service].append(action)

    actions_set = pd.DataFrame()

    # for each service, load the service data, pull out the set of relevant IAM actions
    for key in actions_dict:
        service_auth = load_service_auth.load_service_auth(key)
        service_auth = service_auth.reset_index()
        service_auth['in_policy'] = service_auth['Actions'].apply(wildcard_match_list, check_list=actions_dict[key])
        actions_set = pd.concat((actions_set, service_auth))

    actions_set = actions_set.loc[actions_set['in_policy']==True]

    return actions_set

def calculate_set_of_resources(statement):
    '''
    Takes in a statement chunk from a policy
    Identifies the total set of resource types described by the Resources list
    '''
    # resources dict
    resources_dict = defaultdict(list)

    for resource in statement['Resource']:
        if resource == "*":
            resources_dict["*"].append("*")
        else:
            service = extract_service_from_arn(resource)
            resources_dict[service].append(resource)

    resources_set = pd.DataFrame()

    for key in resources_dict:
        resources_auth = load_service_auth.load_service_auth(key,'resources')
        resources_auth['in_policy'] = resources_auth['Resource types'].apply(wildcard_match_list_reverse,check_list=resources_dict[key], match_prefix="*:",match_suffix="*")
        resources_set = pd.concat((resources_set, resources_auth))

    return resources_set

### test

thing = load_policy_from_file("test/test-amplify.json")
statement = thing['Statement'][0]

result = calculate_set_of_actions(statement)

result = calculate_set_of_resources(statement)
result