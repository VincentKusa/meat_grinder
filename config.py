import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    WORKSPACE_DIR = Path(os.getenv("WORKSPACE_DIR", "./workspaces"))
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    SUBFINDER_BIN = "subfinder"
    HTTPX_BIN = "httpx"
    NAABU_BIN = "naabu"
    GITLEAKS_BIN = "gitleaks"
    NUCLEI_BIN = "nuclei"
    GOWITNESS_BIN = "gowitness"