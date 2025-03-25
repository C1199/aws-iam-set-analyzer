import pandas as pd
from bs4 import BeautifulSoup
import requests
from pathlib import Path

base_url = "https://docs.aws.amazon.com/service-authorization/latest/reference/"
base_path = "scrape_iam_actions"
base_tables = ["actions","resources","conditions"]

# setup data paths
for item in base_tables:
    path = Path(base_path+"/"+item)
    if Path(base_path+"/"+item).exists():
        print(Path(base_path+"/"+item).absolute())
        continue
    else:
        Path(base_path+"/"+item).mkdir()

def extract_service_from_arn(arn):
    '''
    Takes in an ARN an returns the service
    arn:partition:service:region:account-id:resource-id
    arn:partition:service:region:account-id:resource-type/resource-id
    arn:partition:service:region:account-id:resource-type:resource-id
    '''
    try:
        if arn is not None:
            service_prefix = arn.split(":")[2]
        else:
            service_prefix = None
    except Exception as e:
        service_prefix = None
    return service_prefix

# lifted from Orca-toolbox IAM-APE
def get_soup(url: str) -> BeautifulSoup:
    html_doc = requests.get(url).content.decode("utf-8")
    return BeautifulSoup(html_doc, "html.parser")

def identify_service_prefix(url):

    soup = get_soup(url)
    # identify the service prefix by looking for the html tags
    try:
        prefix = soup.find('code', class_='code').get_text()
    except AttributeError as e:
        raise e

    return prefix

def read_service_auth(url):

    try:
        prefix = identify_service_prefix(url)

        data = pd.read_html(url)

        # identify what dataframe have been returned
        resources_data_present = True
        conditions_data_present = True
        if len(data) == 2:
            # Either Resources or Conditions data is missing
            if 'Resource types' not in data[1].columns:
                # This means that resources data is missing
                resources_data_present = False
            else:
                conditions_data_present = False
        if len(data) == 1:
            # only actions data is present
            resources_data_present = False
            conditions_data_present = False

        # calculate the actions table
        actions = data[0]
        actions['Prefix'] = prefix
        
        # assoicate the resource_service with the resource types
        try: 
            actions['Resource types'] = actions['Resource types (*required)'].str.replace("*","")
        except Exception as e:
            print(f"{prefix} does not have resource types in Actions list")
            actions['Resource types'] = None
        
        if resources_data_present:
            resources = data[1]
            resources['Prefix'] = prefix
            resources["resource_service"] = resources['ARN'].apply(extract_service_from_arn)
            actions = actions.merge(resources[['Resource types', 'resource_service']], how='left', left_on=['Resource types'], right_on=['Resource types'])
        else:
            actions['resource_service'] = pd.NA
            print(f"No resource list for {prefix}")
            resources = pd.DataFrame()

        try:
            actions['Condition keys'] = actions['Condition keys'].str.split()
        except Exception:
            print(f"No condition keys for any action in {prefix}")
            actions['Condition keys'] = ''
        # create a copy
        act = actions.copy()
        act = act.explode(['Condition keys'])
        act = act[['Prefix','Actions','Resource types (*required)','Condition keys','resource_service']].groupby(['Prefix','Actions','Condition keys','resource_service'],dropna=False)['Resource types (*required)'].apply(list)
        # the actions dataframe is a multiindex frame with index "Prefix","Actions","Condition keys"
        actions = pd.DataFrame(act)

        # calculate the conditions table
        if conditions_data_present:
            if resources_data_present:
                conditions = data[2]
            else:
                conditions = data[1]
            conditions['Prefix'] = prefix
        else:
            print(f"No conditions list for {prefix}")
            conditions = pd.DataFrame()

    except AttributeError as e:
        print(f"Page does not have service prefix. {url}")
        raise e

    return actions, resources, conditions, prefix

def identify_all_services():
    # iterates through the service auth reference and scrapes all the data
    # code adapted from Orca Tools IAM-APE
    
    soup = get_soup(base_url + "reference_policies_actions-resources-contextkeys.html")
    all_a = soup.find_all("a")
    all_links = [
        a.get("href") for a in all_a if a.get("href", "").startswith("./list_")
    ]
    return all_links

def store_data(filename, data: pd.DataFrame):

    data.to_json(filename, orient="table")

    return

def scrape_service_auth():

    all_links = identify_all_services()

    for link in all_links:
        try:
            a,r,c, prefix = read_service_auth(base_url + link[2:])
            store_data(f"scrape_iam_actions/actions/{prefix}.json",a)
            store_data(f"scrape_iam_actions/resources/{prefix}.json",r)
            store_data(f"scrape_iam_actions/conditions/{prefix}.json",c)
        except Exception as e:
            print(f"error sourcing url: {link} - error: {e}")

    return

if __name__ == "__main__":
    scrape_service_auth()
    exit