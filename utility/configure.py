import os
import json
import logging


class IntConfig():
    """
    Initialize object by passing in path to config file
    store configuration data in variable data
    """
    def __init__(self, path_to_config):
        """
        Construnctor for Interface configuration

        Parameters
        ----------
        path_to_config : path of config file
            Return the configuration object in the json format
        data : Dict
            Return the Dict object
        """
        self.path_to_config = path_to_config
        self.data = {}

    def load_config(self):
        logging.info(f"Loading config from: \
            {os.path.realpath(self.path_to_config)}")
        with open(self.path_to_config, "r") as read_file:
            data = json.load(read_file)
            self.data = data

            if 'urlScanUrl' in data:
                self.data['urlScanUrl'] = data['urlScanUrl']
            if 'urlscanApiKey' in data:
                self.data['urlscanApiKey'] = data['urlscanApiKey']
            if 'virustotalUrl' in data:
                self.data['virustotalUrl'] = data['virustotalUrl']
            if 'virustotalApiKey' in data:
                self.data['virustotalApiKey'] = data['virustotalApiKey']
            if 'scan_wait_time' in data:
                self.data['scan_wait_time'] = data['scan_wait_time']

            loggable_config_dict = {}
            for k, v in self.data.items():
                if "apikey" not in k.lower() or v == "":
                    loggable_config_dict[k] = v
                else:
                    loggable_config_dict[k] = "---HIDDEN---"
            logging.info(json.dumps(loggable_config_dict, indent=4))
