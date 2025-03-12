import pandas as pd

base_path = "scrape_iam_actions"

def load_service_auth(service, type = "actions"):

    df = pd.read_json(f"{base_path}/{type}/{service}.json",orient="columns")

    return df