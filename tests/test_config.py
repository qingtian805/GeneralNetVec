import os, sys
sys.path.append(f"{os.path.abspath(".")}")

from config import Config

config = Config("test/config.json")
