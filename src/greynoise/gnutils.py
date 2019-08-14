import json
import os
import sys


CONFIG_PATH = os.path.expanduser("~/.config/greynoise")
CONFIG_FILE = os.path.join(CONFIG_PATH, "config.json")
CONFIG_DEFAULTS = {"api_key": ""}


def setup():
    # Called when <-k or --api-key + some argument> used.
    # TODO: key verification using ping endpoint
    # Auto-check at some interval? Configurable?
    # If query is run w/o valid credentials,
    # it will be unsuccessful - speaks for itself

    if len(sys.argv) >= 4 and (sys.argv[2] == "-k" or sys.argv[2] == "--api-key"):
        print(" Generating config.json...\n")
        if not os.path.isfile(CONFIG_FILE):
            if not os.path.exists(CONFIG_PATH):
                os.makedirs(CONFIG_PATH)
            config = CONFIG_DEFAULTS
            config["api_key"] = sys.argv[3]  # wip
            with open(CONFIG_FILE, "w") as file:
                json.dump(config, file, indent=4, separators=(",", ": "))
                # TODO: Test if running this overwrites or appends.
                # It needs to overwrite.
                print(
                    " Success!\n"
                    "~/.config/greynoise/config.json file generated.\n"
                )
                exit()
    else:  # If you are w/o the above things, there's a mistake
        print(
            "Setup requires an API key.\n"
            "Usage: greynoise setup -k <your API key>"
        )
        exit()


# Turns input file into a python list
def list_file(list_file):
    try:
        with open(list_file) as f:
            ip_list = []
            input_file = f.readlines()
            for i in input_file:
                i = i.split("\n")[0]
                ip_list.append(i)
        return ip_list
    except Exception:
        return None
