from dotenv import load_dotenv
load_dotenv()
import requests
import os
print(requests.get("https://discord.com/api/v6/users/@me/billing/subscriptions",headers={"Authorization":os.getenv("Authorization")}).json()[0])