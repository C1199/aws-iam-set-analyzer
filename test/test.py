import pandas as pd
import json
from scrape_iam_actions import load_service_auth
import importlib
from collections import defaultdict
from fnmatch import fnmatch

importlib.reload(load_service_auth)

def load_policy_from_file(policy_file):
    '''
    policy_file str location of thing
    '''

    with open(policy_file, "r") as r:
        policy_json = json.loads(r.read())

    return policy_json

def wildcard_match_list(check, actions_list: list):
    
    match =  False

    if isinstance(actions_list, list):
        print("ok")
    else:
        actions_list =  [actions_list]
    
    print(type(actions_list))
    print(actions_list)

    for item in actions_list:
        #print(check, item)
        if fnmatch(check.lower(), item.lower()):
            print("fnmatch!")
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
        service_auth['in_policy'] = service_auth['Actions'].apply(wildcard_match_list, actions_list=actions_dict[key])
        actions_set = pd.concat((actions_set, service_auth))

    actions_set = actions_set.loc[actions_set['in_policy']==True]

    return actions_set

### test

thing = load_policy_from_file("test/test-amplify.json")
statement = thing['Statement'][0]

result = calculate_set_of_actions(statement)