import os
import json
from config.config import Config


class ConfigService:
    def __init__(self, config_file: str = "config/config.json"):
        self.config_file = config_file
        self.config = self.load_config()

    def load_config(self):
        # Check if config file exists
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Config file {self.config_file} not found")

        # Load config file
        with open(self.config_file, "r") as f:
            config_data = json.load(f)

        return Config(**config_data)

    def get_config(self):
        return self.config







