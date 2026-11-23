import os, sys
sys.path.append(f"{os.path.abspath(".")}")

import time
from config import Config

TEST_FILE = "tests/config.json"

if os.path.exists(TEST_FILE):
    os.remove(TEST_FILE)
    time.sleep(1)

config = Config(TEST_FILE)

assert os.path.exists(TEST_FILE)

with open(TEST_FILE, "r") as f:
    content = f.readlines()

for i in range(len(content)):
    if content[i].find("\"algorithm\":"):
        content[i] = content[i].replace("LBPSO", "RSA")

with open(TEST_FILE, "w") as f:
    f.writelines(content)

config = Config(TEST_FILE)

assert config.algorithm == "RSA"
