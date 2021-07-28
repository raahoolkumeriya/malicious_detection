from utility.virustotalClient import VirusTotal
from utility.urlscanClient import URLScan
from utility.configure import IntConfig
import requests
import os

# Configuration setup
config = os.path.join(os.path.abspath('.'), "resources", "config.json")
configure = IntConfig(config)
configure.load_config()


def test_api_key_avilable_for_connection_in_urlscan():
    us = URLScan(configure)
    apikey = us.config.data['urlscanApiKey']
    if apikey == "":
        apikey = os.getenv('urlscanApiKey')
    assert apikey != ""


def test_api_key_avilable_for_connection_in_virustotal():
    us = VirusTotal(configure)
    apikey = us.config.data['virustotalApiKey']
    if apikey == "":
        apikey = os.getenv('virustotalApiKey')
    assert apikey != ""


def test_connection_for_urlscan_api():
    test_endpoint = "https://urlscan.io/api/v1/search/?q=domain:urlscan.io"
    us = URLScan(configure)
    apikey = us.config.data['urlscanApiKey']
    if apikey is None:
        apikey = os.getenv('virustotalApiKey')
    response = requests.get(test_endpoint, headers={
                    'API-Key': apikey,
                    'Content-Type': 'application/json'})
    assert response.status_code == 200


def test_connection_for_virustotal_api():
    test_endpoint = "https://www.virustotal.com/api/v3/domains/abc.com"
    us = URLScan(configure)
    apikey = us.config.data['virustotalApiKey']
    if apikey is None:
        apikey = os.getenv('urlscanApiKey')
    response = requests.get(test_endpoint, headers={
                    'x-apikey': apikey,
                    'Accept': 'application/json'})
    assert response.status_code == 200
