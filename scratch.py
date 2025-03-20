import importlib
import scrape_iam_actions.load_service_auth
import set_analyzer.analyzer
import scrape_iam_actions
import pandas as pd

# checking for duplicate Actions names across Services
a = scrape_iam_actions.load_service_auth.load_all_service_auth()
b = a.drop_duplicates(subset=('Prefix','Actions')).duplicated(subset=('Actions'))
c = b.loc[b==True]
d = a.loc[c.index]
d.loc[d['Actions']=='UpdateProfile']
# 3563 duplicate Action names
# matching multiple columns against dfs
amplify = scrape_iam_actions.load_service_auth.load_service_auth('amplify')
len(amplify)
len(a.loc[a['Prefix']=='amplify'])
a.merge(amplify[['Prefix','Actions']].drop_duplicates(), how='left',on=['Prefix','Actions'],indicator='Exist')
thing = a.merge(amplify[['Prefix','Actions']].drop_duplicates(), how='left',on=['Prefix','Actions'],indicator='Exist')
thing['Exist'].drop_duplicates()
thing.loc[thing['Exist']=='both']
thing.loc[thing['Prefix']==True]


#
importlib.reload(set_analyzer.analyzer)

policy = set_analyzer.analyzer.load_policy_from_file("tests/allow-all.json")

statement = policy['Statement'][6]

valid_actions = set_analyzer.analyzer.calculate_set_of_valid_action_resource_pairs_for_statement(statement)

valid_actions.loc[valid_actions['Valid']==True][['Prefix','Actions','Valid','Required resources']]
valid_actions.loc[valid_actions['Valid']==False][['Prefix','Actions','Valid','Required resources']]
valid_actions.loc[valid_actions['Prefix']=='iam'][['Prefix','Actions','Valid','Required resources']]

valid_actions.loc[valid_actions['Required resources']!=set()]
valid_actions.loc[valid_actions['Required resources']==set()]

valid_actions.loc[(valid_actions['Required resources']==set())&(valid_actions['Resource types (*required)']=={None}), 'Required resources'].add(None)
valid_actions['Required resources'].loc[(valid_actions['Required resources']==set())&(valid_actions['Resource types (*required)']=={None})] = {None}

# calculate actions by resource

actions_set = set_analyzer.analyzer.calculate_set_of_actions(statement)
resources_set = set_analyzer.analyzer.calculate_set_of_resources(statement)
resource_list = resources_set.loc[resources_set['in_policy']==True]['Resource types'].drop_duplicates().to_list()
service_actions = actions_set

# effective perms for policy
valid_actions.loc[valid_actions['Valid']==True]


policy = set_analyzer.analyzer.load_policy_from_file("tests/test-amplify.json")
actions = set_analyzer.analyzer.determine_effective_permissions_for_policy(policy)
actions
actions.loc[actions["Effect"]=="Allowed"][['Prefix','Actions','Effect_allow', 'Effect_deny', 'Effect']]
actions.loc[actions["Effect"]=="Denied"]
actions.loc[actions["Effect"]=="Denied"][['Prefix','Actions','Effect_allow', 'Effect_deny', 'Effect']]


actions['Effect'] = actions['Effect_y'].isna()