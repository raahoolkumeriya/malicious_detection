import os
import json
import logging
import requests
from time import sleep


class URLScan:
    """URLScan Client

    Parameters
    ----------
    config (obj) : configuration object
    """
    def __init__(self, config: object):
        """
        Constructs to initilised class attributes
        Attributes
        ----------
        config (obj) : Configuration object
        rooturl (str): UrlScan API root URL
        apikey (str) : API key
        header (dict): Header details specific to UrlScan
        """
        logging.info('URLScan()')
        
        self.config = config
        self.rooturl = config.data.get('urlScanUrl')
        self.scan_time = config.data.get('scan_wait_time')
        self.apikey = config.data.get('urlscanApiKey')
        if self.apikey == "":
            self.apikey = os.getenv('urlscanApiKey')
        self.header = {
                    'API-Key': self.apikey,
                    'Content-Type': 'application/json'}
        assert len(self.rooturl) > 0, "Url must be defined"
        assert len(self.apikey) > 0, "API key is missing"

    def post_data(self, arg: str):
        """
        Scan data to URLScanl API w.r.t IPv4 or Domain
        Attribute
        ---------
        arg (str) : IPv4 or domain name as argument
        Return
        ------
        dict object
        """
        logging.info('URLScan()/post_data')
        try:
            data = {"url": arg, "visibility": "public"}
            resp = requests.post(
                f'{self.rooturl}/scan/', headers=self.header,
                data=json.dumps(data))
            if resp.status_code == 200:
                scanid = resp.json().get('uuid')
                sleep(self.scan_time)
                response = requests.get(
                            f"{self.rooturl}/result/{scanid}",
                            headers=self.header)
                return json.loads(response.text)
            else:
                return json.loads(resp.text)
        except Exception:
            return "Exception: Scan timeout"

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
        logging.info('URLScan()/get_summary')
        if data.get('message') != "Not Found":
            summary = dict()
            if data.get('stats').get('ipStats') != []:
                summary['main domain'] = data.get('stats')\
                    .get('ipStats')[1].get('domains')[0]
                summary['Ips address'] = \
                    [i['ips'][0] for i in data.get('stats').get('regDomainStats')]
                summary['Category'] = data.get('verdicts')\
                    .get('urlscan').get('categories')
                summary['HTTP transactions'] = \
                    len(data.get('data').get('requests'))
            else:
                summary['ERR_EMPTY_RESPONSE'] = \
                    "We could not scan this website!"
            return summary
        else:
            return data

    def urlscan_status(self, data):
        """
        Calculation of Malicious summary
        Attribute
        ---------
        data (dict): API Response return
        Return
        ------
        dict --> On Successful response
        """
        logging.info('URLScan()/urlscan_status()')
        if data.get('message') != "Not Found":
            score_overall = data.get('verdicts').get('overall').get('score')
            score_urlscan = data.get('verdicts').get('urlscan').get('score')
            score_engines = data.get('verdicts').get('engines').get('score')
            score_community = data.get('verdicts')\
                .get('community').get('score')
            score = {
                "overall": score_overall,
                "urlscan": score_urlscan,
                "engines": score_engines,
                "community": score_community
            }
            so = su = se = sc = False
            if score_overall > 5:
                so = True
            if score_urlscan > 5:
                su = True
            if score_engines > 5:
                se = True
            if score_community > 5:
                sc = True
            return {
                'score': score,
                'status': any([so, su, se, sc]),
                "data": "PROCESSED"}
        else:
            return {
                'score': None,
                'status': None,
                "data": data.get('message')}
