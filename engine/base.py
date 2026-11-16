import subprocess
import json
from abc import ABC, abstractmethod
from database import DatabaseManager

class BaseReconModule(ABC):
    def __init__(self, target: str, db: DatabaseManager, workspace: Path):
        self.target = target
        self.db = db
        self.workspace = workspace

    @staticmethod
    def run_cmd(cmd: str, timeout: int = 300) -> str:
        """Securely execute CLI tools with timeout handling."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                check=True, timeout=timeout
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[!] Command failed: {cmd}\n{e.stderr}")
            return ""
        except subprocess.TimeoutExpired:
            print(f"[!] Command timed out: {cmd}")
            return ""

    @staticmethod
    def parse_ndjson(raw: str) -> list:
        data = []
        for line in raw.strip().split('\n'):
            if line:
                try: data.append(json.loads(line))
                except json.JSONDecodeError: continue
        return data

    @abstractmethod
    def execute(self):
        pass