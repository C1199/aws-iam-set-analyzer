import importlib
import tests.test

importlib.reload(tests.test)

policy = tests.test.load_policy_from_file("tests/allow-all.json")

statement = policy['Statement'][4]

valid_actions = tests.test.calculate_set_of_valid_action_resource_pairs_for_statement(statement)

valid_actions.loc[valid_actions['Valid']==True]
valid_actions.loc[valid_actions['Valid']==False]
valid_actions.loc[valid_actions['Required resources']!=set()]
valid_actions.loc[valid_actions['Required resources']==set()]

valid_actions.loc[(valid_actions['Required resources']==set())&(valid_actions['Resource types (*required)']=={None}), 'Required resources'].add(None)
valid_actions['Required resources'].loc[(valid_actions['Required resources']==set())&(valid_actions['Resource types (*required)']=={None})] = {None}


valid_actions.loc[valid_actions['Valid']==True]

actions = tests.test.determine_effective_permissions_for_policy(policy)

actions.loc[actions["Effect"]=="Allowed"]
actions.loc[actions["Effect"]=="Denied"]