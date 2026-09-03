import jwt
import time
import os
from dotenv import load_dotenv
import requests

load_dotenv()
APP_ID = os.getenv("APP_ID")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")  # <-- changed: now reads key content directly
INSTALLATION_ID = os.getenv("INSTALLATION_ID")

# Generate a JWT for GitHub App authentication
def generate_jwt():
    private_key = PRIVATE_KEY.replace('\\n', '\n') 
    payload = {
        'iat': int(time.time()),
        'exp': int(time.time()) + (10 * 60),
        'iss': APP_ID
    }
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token

# Get an installation access token for the GitHub App
def get_installation_token():
    a = generate_jwt()
    headers = {
        'Authorization': f'Bearer {a}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    url = f'https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens'
    response = requests.post(url, headers=headers)
    return response.json()["token"]