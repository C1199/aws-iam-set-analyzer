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
    resource_type = arn.split(":")[5].split("/")[0]
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

    if 'Action' in statement:
        act_key = 'Action'
    else:
        act_key = 'NotAction'

    for action in statement[act_key]:
        if action == "*":
            actions_dict['*'].append('*')
        else:
            service = action.split(":")[0]
            action = action.split(":")[1]
            actions_dict[service].append(action)

    actions_set = pd.DataFrame()

    # for each service, load the service data, pull out the set of relevant IAM actions
    for key in actions_dict:
        if key == '*':
            service_auth = load_service_auth.load_all_service_auth()
            service_auth['in_policy'] = True
            actions_set = service_auth
            break
        else:
            service_auth = load_service_auth.load_service_auth(key)
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

    if 'Resource' in statement:
        res_key = 'Resource'
    else:
        res_key = 'NotResource'

    for resource in statement[res_key]:
        if resource == "*":
            resources_dict["*"].append("*")
        else:
            service = extract_service_from_arn(resource)
            resources_dict[service].append(resource)

    resources_set = pd.DataFrame()

    for key in resources_dict:
        if key == '*':
            resources_auth = load_service_auth.load_all_resource_auth()
            resources_auth['in_policy'] = True
            resources_set = resources_auth
            break
        else:
            resources_auth = load_service_auth.load_service_auth(key,'resources')
            check_list = [extract_resource_type_from_arn(x) for x in resources_dict[key]]
            resources_auth['in_policy'] = resources_auth['Resource types'].apply(wildcard_match_list,check_list=check_list)
            resources_set = pd.concat((resources_set, resources_auth))

    return resources_set


def calculate_actions_by_resource_lst(service_actions, resources):
    '''
    service_actions: pandas dataframe containing an "Actions" table
    resources: list, of resources types in a single policy statement
    '''

    actions = service_actions
    # Deduplicate the set of actions
    actions_list = actions['Actions'].drop_duplicates()

    # explode the 'Resource types (required)' column
    actions = actions.explode('Resource types (*required)')
    # Group the resources together into a set per action
    actions_groupby =  actions[['Prefix','Actions','Resource types (*required)']].groupby(['Actions'],dropna=False)['Resource types (*required)'].apply(set)
    # Merge the resource sets onto the list of actions
    actions_list = pd.merge(actions_list, actions_groupby, 'left', left_on='Actions', right_on='Actions')
    # identify the required resources by the presence of '*'
    actions_list['Required resources'] = [{t for t in x if (type(t)==str)} for x in actions_list['Resource types (*required)']]
    actions_list['Required resources'] = [{t for t in x if t.endswith('*')} for x in actions_list['Required resources']]
    # Use set maths to identity the optional resources
    actions_list['Optional resources'] = actions_list['Resource types (*required)'] - actions_list['Required resources']

    # below we are duplicating our resource list into:
    # # a list with '*' on each
    # # a list without '*' on each
    # sanitising our resource list
    # attached the * to them
    resource_with_star = []
    resources_without_star = []
    none_in_resource_list = False
    for x in resources:
        if x == None:
            resource_with_star.append(x)
            print(f"appending none type {x} to list")
            none_in_resource_list = True
            pass
        else:
            try:
                if x.endswith('*'):
                    resource_with_star.append(x)
                    t = x.replace('*','')
                    resources_without_star.append(t)
                else:
                    t = x +"*"
                    resource_with_star.append(t)
                    resources_without_star.append(x)
            except Exception as e:
                print(x)

    resource_with_star = set(resource_with_star)
    resources_without_star = set(resources_without_star)
    # calculate which Actions have required resources that are subsets of our chosen resources
    actions_list['Valid'] = (actions_list['Required resources'] <= set(resource_with_star)) & (len(actions_list['Required resources'])>0)
    actions_list['Valid'] = actions_list['Required resources'] <= set(resource_with_star)

    # remove empty sets from the solution
    actions_list.loc[actions_list['Required resources']==set(), ['Valid']] = False

    # Calcuate actions that might be Valid
    actions_list['Maybe'] = [ set.intersection(x, resources_without_star) for x in actions_list['Optional resources']]
    actions_list.loc[(actions_list['Required resources']==set())&(actions_list['Maybe']!=set()), ['Valid']] = True
    if none_in_resource_list:
        actions_list.loc[(actions_list['Optional resources'] == actions_list['Resource types (*required)']), ['Valid']] = True

    return actions_list


def calculate_set_of_valid_action_resource_pairs_for_statement(statement):
    '''
    Takes in a policy statement chunk. Calculates the sets of actions and resources mentioned.
    Identifies all valid action+resource pairs for the statement
    '''

    actions_set = calculate_set_of_actions(statement)
    resources_set = calculate_set_of_resources(statement)
    resource_list = resources_set.loc[resources_set['in_policy']==True]['Resource types'].drop_duplicates().to_list()
    actions_list = calculate_actions_by_resource_lst(actions_set,resource_list)

    return actions_list

def determine_effective_permissions_for_policy(policy):
    '''
    Takes in an IAM policy and for each statement chunk, calculates the set of Allowed or Denied actions
    This iterative process uses set theory to calculate the final set of allowed or denied actions
    '''

    actions_allowed = pd.DataFrame()
    actions_denied = pd.DataFrame()

    for chunk in policy['Statement']:
        effect = chunk['Effect']
        valid_action_resources = calculate_set_of_valid_action_resource_pairs_for_statement(chunk)
        if effect == "Allow":
            actions_allowed = pd.concat((actions_allowed, valid_action_resources))
        else:
            actions_denied = pd.concat((actions_denied, valid_action_resources))

    actions_denied["Effect"] = "Denied"
    actions_allowed["Effect"] = "Allowed"

    actions_allowed = actions_allowed.where(~actions_allowed['Actions'].isin(actions_denied['Actions'])).dropna()
    

    actions = pd.concat((actions_denied, actions_allowed))
    actions = actions.drop_duplicates(("Actions"))
    actions = actions.loc[actions['Valid']==True]
    
    return actions


if __name__ == "__main__":

    thing = load_policy_from_file("tests/test-policy.json")
    policy=thing
    actions = determine_effective_permissions_for_policy(policy)

    statement = thing['Statement'][0]

    result = calculate_set_of_actions(statement)

    result = calculate_set_of_resources(statement)
    result
    resource_list = result.loc[result['in_policy']==True]['Resource types'].to_list()