import json
import logging


def main(change):
    """
    Runs the Ansible-Runner for the task
    :param change: change data
    :return: result of task
    """
    logging.debug(json.dumps(change, indent=4))
    return True
