import pandas as pd
import os

base_path = "scrape_iam_actions"

def load_service_auth(service, type = "actions"):
    try:
        df = pd.read_json(f"{base_path}/{type}/{service}.json",orient="table")
        # The index of the actions data is funky, so we reset to make it easier to work with
        df = df.reset_index()
    except Exception as e:
        print(f"Data for {service} {type} does not exist!")
        raise e
    return df

def load_all_service_auth():
    '''
    Loads all actions data from the service auth
    Returns a dataframe that represents the cartesian product of the permissions cross resources space
    Crucially, because this is built from the actions data, it does not contain invalid action resource pairs
    '''

    type = "actions"

    services = os.listdir(f"{base_path}/{type}")

    auth_list = []

    for service in services:
        df = pd.read_json(f"{base_path}/{type}/{service}",orient="table")
        auth_list.append(df)

    service_auth = pd.concat(auth_list)

    service_auth = service_auth.explode('Resource types (*required)')
    service_auth = service_auth.reset_index()

    service_auth.loc[service_auth['Resource types (*required)'].isnull()]
    service_auth.loc[service_auth['Condition keys'].isnull()]

    return service_auth

def load_all_resource_auth():
    '''
    Loads all resources data from the service auth
    Adds on the 'None' resource types as well for good measure
    '''
    print('loading all resources')
    type = 'resources'

    services = os.listdir(f"{base_path}/{type}")

    auth_list = []

    for service in services:
        df = pd.read_json(f"{base_path}/{type}/{service}",orient="table")
        auth_list.append(df)

    resources_auth = pd.concat(auth_list)
    resources_auth = resources_auth.dropna(subset='Resource types')
    none_list = resources_auth['Prefix'].drop_duplicates()
    none_list = pd.DataFrame(none_list)
    none_list['Resource types'] = None

    resources_auth = pd.concat((resources_auth, none_list))
    resources_auth = resources_auth.reset_index(drop=True)

    return resources_auth

def create_resources_global_set():
    '''
    Service have their own resources. But some services have actions whose valid resource pairs are from another service.
    A notable example of this is STS, which uses IAM roles in it's policies.
    This function creates a master dataset of all resources, and identifies the "parent" service that the resource is from
    '''
    resources = load_all_resource_auth()
    resources.loc[resources['Resource types'].isna(), 'resource_service'] = resources['Prefix']

    resources.to_json(f"{base_path}/global_resources/global_resources.json", orient="table")

    return resources

def load_global_resources_set():
    df = pd.read_json(f"{base_path}/global_resources/global_resources.json",orient="table")
    return df

if __name__ == "__main__":
    create_resources_global_set()