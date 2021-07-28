import os
import re
import json
import logging
import requests
from collections import Counter


class JsonFormating():
    """
    JSON string formatting Class
    Attributes
    ----------
    json_obj : Obj
        Takes json object and return pretty formated json

    Return
    ------
    dict object
    """
    def __init__(self, json_obj):
        self.obj = json_obj

    def __str__(self):
        logging.info("JsonFormating()")
        return json.dumps(
            self.obj, sort_keys=True, indent=4, separators=(",", ": "))


class VirusTotal:
    """VirusTotal Client
    
    Parameters
    ----------
    config (obj) : configuration object
    """
    def __init__(self, config):
        """
        Constructs to initilised class attributes 
        Attributes
        ----------
        config (obj) : Configuration object
        rooturl (str): Virustotal API root URL
        apikey (str) : API key 
        header (dict): Header details specific to Virustotal
        """
        self.config = config
        self.rooturl = config.data.get('virustotalUrl')
        self.apikey = config.data.get('virustotalApiKey')
        if self.apikey is None:
            self.apikey = os.getenv('virustotalApiKey')
        self.header = {'x-apikey': self.apikey,
                     'Accept': 'application/json'}

        assert len(self.rooturl) > 0, "API Root URL missing."
        assert len(self.apikey) > 0, "Valid API Key is missing from configuration."

    
    def get_data(self, arg, timeout=None):
        """
        Get generated data w.r.t IPv4 or Domain
        Attribute
        ---------
        arg (str) : IPv4 or domain name as argument
        timeout (int): Optional 
        Return
        ------
        dict object
        """ 
        logging.info("VirusTotal/get_data()")
        regex = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', arg)
        try:
            if list(arg.split()) == regex:
                url = f"{self.rooturl}/ip_addresses/{arg}"
            else:        
                url = f"{self.rooturl}/domains/{arg}"
            response = requests.get(
                url, headers = self.header, timeout=timeout)
            if response.status_code != 200:
                # raise_exception(response)
                return json.loads(response.text)
            return json.loads(response.text)
        except Exception:
            return "Exception: Require details"

    def get_summary(self, data):
        """
        Parsing Summary status from JSON object
        Attribute
        ---------
        data (dict): API Response return 
        Return
        ------
        dict --> On Successful response
        str  --> On Failed response
        """
        logging.info("VirusTotal/get_summary()")
        if data.get('error') is None: 
            summary = dict()
            category = [j['category'] for _, j in data.get('data').get('attributes').get('last_analysis_results').items()]
            summary['owner'] = data.get('data').get('attributes').get('as_owner')
            summary['id'] =  data.get('data').get('id')
            summary['votes'] = data.get('data').get('attributes').get('total_votes')
            summary['category'] = [ 
                    {"harmless": category.count('harmless')},
                    {"malicious": category.count('malicious')},
                    {"suspicious": category.count('suspicious')},
                    {"timeout": category.count('timeout')},
                    {"undetected": category.count('undetected')}
            ]
            summary['reputation'] = data.get('data').get('attributes').get('reputation')
            return summary
        else:
            return data.get('error')

    def virustotal_status(self, data):
        """
        Calculation of Malicious summary
        Attribute
        ---------
        data (dict): API Response return 
        Return
        ------
        dict --> On Successful response
        """
        logging.info("VirusTotal/virustotal_status()")
        if data.get('error') is None:
            category = [j['category'] for _, j in data.get('data').get('attributes').get('last_analysis_results').items()]
            suspicious = category.count('suspicious')
            malicious = category.count('malicious')
            category_check = {
                "harmless": category.count('harmless'),
                "malicious": malicious,
                "suspicious": suspicious,
                "timeout": category.count('timeout'),
                "undetected": category.count('undetected')
            }
            vote_check = data['data']['attributes']['total_votes']
            vote_malicious = vote_check.get('malicious')
            virusotal = dict(Counter(category_check) + Counter(vote_check))
            status = False
            if malicious > 2 or suspicious > 0:
                status = True
            if vote_malicious > 2:
                status = True
            return {'score' : virusotal, 'status': status , "data": "PROCESSED"}
        else:
            return {'score' : None, 'status': None , 'data': data.get('error') }


if __name__ == "__main__":
    from configure import IntConfig
    import os
    config = os.path.join(os.path.dirname(__file__),"..", "resources", "config.json")
    configure = IntConfig(config)
    configure.load_config()
    # a = URLScan(configure)
    domain = "hsbc1ererewr2321.com"
    # us = a.post_data(domain) 
    # urlscan = a.urlscan_status(us)
    b = VirusTotal(configure)
    vt = b.get_data(domain)
    # virustotal = b.virustotal_status(vt)
    # print("urlscan: ", urlscan )
    # print("virustotal: ", virustotal )

    # print(type(virustotal.get('status')))