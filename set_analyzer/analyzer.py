import pandas as pd
import json
from scrape_iam_actions import load_service_auth
import importlib
from collections import defaultdict
from fnmatch import fnmatch

importlib.reload(load_service_auth)

def action_notaction_resource_notresource(d):
    '''
    Returns the keys for Action, NotAction, or Resource and NotResource
    param d: dict
    '''

    if 'Action' in statement:
        act_key = 'Action'
    else:
        act_key = 'NotAction'

    
    if 'Resource' in statement:
        res_key = 'Resource'
    else:
        res_key = 'NotResource'

    return act_key, res_key

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
            try:
                service_auth = load_service_auth.load_service_auth(key)
                service_auth['in_policy'] = service_auth['Actions'].apply(wildcard_match_list, check_list=actions_dict[key])
                actions_set = pd.concat((actions_set, service_auth))
            except Exception as e:
                print(f"Error {e}")

    actions_set = actions_set.loc[actions_set['in_policy']==True]

    if act_key == 'NotAction':
        not_list = actions_set.loc[actions_set['in_policy']==True][['Prefix','Actions']].drop_duplicates(ignore_index=True)
        service_auth = load_service_auth.load_all_service_auth()
        service_auth = service_auth.merge(not_list, how='left',on=['Prefix','Actions'],indicator='Exist')
        service_auth['in_policy'] = service_auth['Exist']!='both'
        actions_set = service_auth.loc[service_auth['in_policy']==True]
    
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
            resources_auth = load_service_auth.load_global_resources_set()
            resources_auth['in_policy'] = True
            resources_set = resources_auth
            break
        else:
            try:
                resources_auth = load_service_auth.load_service_auth(key,'resources')
                check_list = [extract_resource_type_from_arn(x) for x in resources_dict[key]]
                resources_auth['in_policy'] = resources_auth['Resource types'].apply(wildcard_match_list,check_list=check_list)
                resources_set = pd.concat((resources_set, resources_auth))
            except Exception as e:
                print(f"Error {e}")

    if res_key == 'NotResource':
        not_list = resources_set.loc[resources_set['in_policy']==True]['Resource types'].drop_duplicates()
        resources_auth = load_service_auth.load_global_resources_set()
        resources_auth = resources_auth.merge(not_list, how='left',on=['Resource types'],indicator='Exist')
        resources_auth['in_policy'] = resources_auth['Exist']!='both'
        resources_set = resources_auth

    return resources_set


def calculate_actions_by_resource_lst(actions: pd.DataFrame, resources: pd.DataFrame):
    '''
    service_actions: pandas dataframe containing an "Actions" table
    resources: list, of resources types in a single policy statement
    '''
    # Prep the actions
    # Deduplicate the set of actions
    actions = actions.reset_index(drop=True)
    actions.loc[actions['resource_service'].isna(), 'resource_service'] = actions['Prefix']
    actions_list = actions[['Prefix','Actions']].drop_duplicates()

    # explode the 'Resource types (required)' column
    actions_exploded = actions.explode('Resource types (*required)')
    # Group the resources together into a set per action
    # these steps use the Service Auth details to figure out what the required and options resources are
    actions_groupby =  actions_exploded[['Prefix','Actions','Resource types (*required)','resource_service']].groupby(['Prefix','Actions','resource_service'],dropna=False)['Resource types (*required)'].apply(set)
    # Merge the resource sets onto the list of actions
    actions_list = pd.merge(actions_list.reset_index(), actions_groupby.reset_index(), 'left', left_on=['Prefix','Actions'], right_on=['Prefix','Actions'])
    # identify the required resources by the presence of '*'
    actions_list['Required resources'] = [{t for t in x if isinstance(t,str)} for x in actions_list['Resource types (*required)']]
    actions_list['Required resources'] = [{t for t in x if t.endswith('*')} for x in actions_list['Required resources']]
    # Use set maths to identity the optional resources
    actions_list['Optional resources'] = actions_list['Resource types (*required)'] - actions_list['Required resources']
    actions_list['Required resources'] = [{t.replace("*","") for t in x if t.endswith('*')} for x in actions_list['Required resources']]

    # The logic here is hard.
    # 
    resources = resources.loc[resources['in_policy']==True]
    resources = resources[['Resource types','resource_service']].groupby(['resource_service'],dropna=False)['Resource types'].apply(set).to_frame()
    actions_list = pd.merge(actions_list, resources, how='left', left_on=['resource_service'], right_on=['resource_service'])
    actions_list['Valid'] = actions_list['Required resources'] <= actions_list['Resource types']

    # remove empty sets from the solution
    actions_list.loc[actions_list['Required resources']==set(), ['Valid']] = False

    # Calcuate actions that might be Valid
    actions_list['Maybe'] = actions_list['Optional resources'] <= actions_list['Resource types']
    actions_list.loc[(actions_list['Required resources']==set())&(actions_list['Maybe']!=False), ['Valid']] = True
    #if none_in_resource_list:
    #    actions_list.loc[(actions_list['Optional resources'] == actions_list['Resource types (*required)']), ['Valid']] = True
    actions_list = actions_list.drop(['Resource types'], axis=1)

    return actions_list


def calculate_set_of_valid_action_resource_pairs_for_statement(statement):
    '''
    Takes in a policy statement chunk. Calculates the sets of actions and resources mentioned.
    Identifies all valid action+resource pairs for the statement
    '''

    actions_set = calculate_set_of_actions(statement)
    resources_set = calculate_set_of_resources(statement)
    actions_list = calculate_actions_by_resource_lst(actions_set,resources_set)

    return actions_list

def determine_effective_permissions_for_policy(policy):
    '''
    Takes in an IAM policy and for each statement chunk, calculates the set of Allowed or Denied actions
    This iterative process uses set theory to calculate the final set of allowed or denied actions
    '''

    actions_allowed_list = list()
    actions_denied_list = list()

    for chunk in policy['Statement']:
        effect = chunk['Effect']
        valid_action_resources = calculate_set_of_valid_action_resource_pairs_for_statement(chunk)
        if effect == "Allow":
            actions_allowed_list.append(valid_action_resources)
        else:
            actions_denied_list.append(valid_action_resources)

    column_names = valid_action_resources.columns
    actions_allowed = pd.DataFrame(columns=column_names)
    actions_denied = pd.DataFrame(columns=column_names)

    if len(actions_allowed_list) > 0:
        actions_allowed = pd.concat(actions_allowed_list)
        actions_allowed = actions_allowed.loc[actions_allowed['Valid']==True]
        actions_allowed["Effect"] = "Allowed"
    
    if len(actions_denied_list) > 0:
        actions_denied = pd.concat(actions_denied_list)
        actions_denied = actions_denied.loc[actions_denied['Valid']==True]
        actions_denied["Effect"] = "Denied"

    effective_permissions = pd.merge(actions_allowed,actions_denied,how='outer',on=['Prefix','Actions'],indicator='Exist',suffixes=['_allow','_deny'])
    effective_permissions.loc[effective_permissions['Exist'] == 'left_only', 'Effect'] = "Allowed"
    effective_permissions.loc[effective_permissions['Exist'] == 'both', 'Effect'] = "Denied"
    effective_permissions.loc[effective_permissions['Exist'] == 'right_only', 'Effect'] = "Denied"
    effective_permissions = effective_permissions.drop(labels=['index_allow','index_deny'], axis=1)

    return effective_permissions

def calculate_boundary_effect(data: pd.Series, boundary_allow = True):
    '''
    
    '''
    if boundary_allow:
        if data['bound'] == 'both':
            if (data['Effect_boundary'] == "Denied") or (data['Effect_final'] == "Denied"):
                effect = "Denied"
            else:
                effect = "Allowed"
        else:
            effect = "Denied"
        return effect

    if data['bound'] == 'left_only':
        effect = data['Effect_final']
    elif data['bound'] == 'both':
        if (data['Effect_boundary'] == "Denied") or (data['Effect_final'] == "Denied"):
            effect = "Denied"
        else:
            effect = "Allowed"
    else:
        effect = "Denied"
    return effect

def determine_effective_permissions_for_policy_and_boundary(policy, boundary_policies: list):
    '''
    Takes in an IAM policy and a set of permissions boundary policies (i.e. SCPs or a permissions boundary)
    '''

    policy_permissions = determine_effective_permissions_for_policy(policy)

    total_actions_set = policy_permissions.copy()
    total_actions_set['Effect_final'] = total_actions_set['Effect']

    for boundary in boundary_policies:
        # If a boundary contains an Effect:Deny statement, we only deny those actions
        # if a boundary contains an Effect:Allow statement, then any action not contained in that list ends up being denied
        boundary_permissions = determine_effective_permissions_for_policy(boundary)
        boundary_allow = False
        if 'Allowed' in boundary_permissions['Effect'].drop_duplicates().to_list():
            boundary_allow = True
        boundary_permissions['Effect_boundary'] = boundary_permissions['Effect']
        total_actions_set = pd.merge(total_actions_set[['Prefix','Actions','Effect_final']], boundary_permissions[['Prefix','Actions','Effect_boundary']], how='outer', on=['Prefix','Actions'],indicator="bound",suffixes=['_policy','_boundary'])[['Prefix','Actions','Effect_final','Effect_boundary','bound']]
        total_actions_set['Effect_final'] = total_actions_set[['Effect_final','Effect_boundary','bound']].apply(calculate_boundary_effect,axis=1,boundary_allow=boundary_allow)

    policy_permissions = pd.merge(policy_permissions, total_actions_set[['Prefix','Actions','Effect_final']], on=['Prefix','Actions'], how='left')

    return policy_permissions

if __name__ == "__main__":

    thing = load_policy_from_file("tests/test-policy-8.json")
    policy=thing
    actions = determine_effective_permissions_for_policy(policy)
    actions.loc[actions['Prefix']=='ec2']
    boundary = load_policy_from_file("tests/boundary/deny-iam-2.json")

    statement = thing['Statement'][0]

    result = calculate_set_of_actions(statement)

    result = calculate_set_of_resources(statement)
    result
    resource_list = result.loc[result['in_policy']==True]['Resource types'].to_list()