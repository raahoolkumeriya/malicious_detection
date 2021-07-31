import os
import re
import json
import aiohttp
import logging
import socket
import uvicorn
import requests
import dns.resolver
from time import sleep
from typing import Optional
from collections import Counter
from utility.configure import IntConfig
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import FastAPI, Form, HTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException

# Variable
APP_NAME = "Malicious IPv4/Domain Detection"

# Configuration setup
config = os.path.join(os.path.dirname(__file__), "resources", "config.json")
configure = IntConfig(config)
configure.load_config()

# Creating an object
logger = logging.getLogger()

# Setting the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)

logging.info(f"Configration loaded for {APP_NAME}")

tags_metadata = [
    {
        "name": "path-parameter",
        "description": "Operations on endpoint with **path parameter**",
    },
    {
        "name": "query-parameter",
        "description": "Operations on endpoint with **query parameter**",
    },
    {
        "name": "malicious",
        "description": "Determination of Malicious result",
    },

]

app = FastAPI(
    title=APP_NAME,
    description="The service will accept IPv4 addresses and domains,\
        query external services and return appropriate responses.",
    version="1.0.0",
    servers=[
        {
            "url": "https://maliciousdetection.herokuapp.com",
            "description": "Live environment"
        },
        {
            "url": "http://127.0.0.1:8000",
            "description": "Development environment"}
    ],
    openapi_tags=tags_metadata,
    openapi_url="/api/v1/openapi.json"
    )

application_banner = {
    "Welcome": "Malicious Detection API",
    "How to use?":
    "You can hit respective Ipv4 and domain enpoints to get summary details",
    "Endpoints": [
        {"GET": [
            "/ip/{ip_address}",
            "/domain/{domain_name}",
            "ip?data={ip_address}",
            "domain?data={domain_name}"
        ]},
        {"POST": "/"}]
}


@app.exception_handler(StarletteHTTPException)
async def exception_callback(request: Request, exc: Exception):
    return JSONResponse({"detail": exc.__repr__()}, status_code=500)


def valid_domain_name(arg: str):
    """Domain Name Validation"""
    logging.info("space: --> valid_domain_name()")
    regex = re.compile(r'^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$')
    return regex.findall(arg)


def valid_ip_address(arg: str):
    """Ip address validation"""
    logging.info("space: --> valid_ip_address()")
    regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return regex.findall(arg)


async def get_resolve_ip(arg: str):
    try:
        logging.info('get_resolve_IP()')
        ip_address = socket.gethostbyname(arg)
        logging.info(f"Resolve IP return : {ip_address}")
        return ip_address
    except Exception as diag:
        raise HTTPException(status_code=500, detail=diag)


async def get_resolve_domain_name(domain: str):
    try:
        logging.info('get_resolve_domain_name()')
        # record_type 'A', 'AAAA', 'NS', MX
        rt = 'A'  # Record_type
        value = [i.to_text() for i in dns.resolver.query(domain, rt)]
        logging.info(f"Resolve Domain name return : {value}")
        return value
    except Exception as diag:
        raise HTTPException(status_code=500, detail=diag)


async def post_data_from_urlscan(arg: str):
    logging.info("space: --> post_data_from_urlscan()")
    try:
        data = {"url": arg, "visibility": "public"}
        header = {
                    'API-Key': os.getenv('urlscanApiKey'),
                    'Content-Type': 'application/json'}
        resp = requests.post(
            f'{configure.data["urlScanUrl"]}/scan/', headers=header,
            data=json.dumps(data))
        if resp.status_code == 200:
            scanid = resp.json().get('uuid')
            logging.info(f"post_data_from_urlscan() -> {scanid} ")
            return scanid
        else:
            logging.debug(resp.text)
            return json.loads(resp.text)
    except Exception:
        return "Exception: Scan timeout"


async def get_scanid_response(arg: str):
    logging.info("space: --> get_scanid_response()")
    async with aiohttp.ClientSession() as session:
        scanid = await post_data_from_urlscan(arg)
        logging.info(f"urlscan generated Scanid: {scanid} ")
        if len(scanid) == 36:
            sleep(configure.data['scan_wait_time'])
            header = {
                        'API-Key': os.getenv('urlscanApiKey'),
                        'Content-Type': 'application/json'}
            url = f"{configure.data['urlScanUrl']}/result/{scanid}"
            logging.info(f"Calling API: {url} ")
            async with session.get(url, headers=header) as resp:
                data = await resp.text()
                return json.loads(data)
        else:
            return scanid


# GET URLSCAN BREIF SUMMARY
async def get_urlscan_summary(arg: str):
    logging.info("space: --> get_urlscan_summary()")
    if valid_domain_name(arg) or valid_ip_address(arg):
        data = await get_scanid_response(arg)
        if data.get('verdicts'):
            summary = dict()
            if data.get('stats').get('ipStats') != []:
                summary['main domain'] =\
                    data.get('stats').get('ipStats')[1].get('domains')
                summary['malicious'] =\
                    data.get('stats').get('malicious')
                summary['HTTP transactions'] =\
                    len(data.get('data').get('requests'))
            else:
                summary['ERR_EMPTY_RESPONSE'] =\
                    "We could not scan this website!"
            logging.info(f"Summary : {summary}")
            return summary
        elif data.get('status'):
            return data
    raise HTTPException(
        status_code=404,
        detail="Provide Valid IPv4 address or Domain name.")


# GET STATUS FROM URLSCAN
async def get_urlscan_status(arg: str):
    logging.info("space: --> get_urlscan_status()")
    data = await get_scanid_response(arg)
    if data.get('message') is None:
        score_overall = data.get('verdicts').get('overall').get('score')
        score_urlscan = data.get('verdicts').get('urlscan').get('score')
        score_engines = data.get('verdicts').get('engines').get('score')
        score_community =\
            data.get('verdicts').get('community').get('score')
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
        return {'score': None, 'status': None, "data": data}


# GET VIRUSTOTAL DATA
async def get_data_from_virustotal(arg: str):
    logging.info("space: --> get_data_from_virustotal()")
    async with aiohttp.ClientSession() as session:
        header = {
                'x-apikey': os.getenv('virustotalApiKey'),
                'Accept': 'application/json'}
        if valid_ip_address(arg):
            url = f"{configure.data['virustotalUrl']}/ip_addresses/{arg}"
        else:
            url = f"{configure.data['virustotalUrl']}/domains/{arg}"
        async with session.get(url, headers=header) as resp:
            data = await resp.text()
            return json.loads(data)


# GET VIRUSTOTAL BRIEDF SUMMARY
async def get_virustotal_summary(value: str):
    logging.info("space: --> get_virustotal_summary()")
    response = await get_data_from_virustotal(value)
    if response.get('data'):
        summary = dict()
        fetch = response.get('data').get('attributes')\
            .get('last_analysis_results')
        category = [j['category'] for _, j in fetch.items()]
        summary['owner'] = response.get('data')\
            .get('attributes').get('as_owner')
        summary['id'] = response.get('data').get('id')
        summary['votes'] = response.get('data')\
            .get('attributes').get('total_votes')
        summary['category'] = [
                {"harmless": category.count('harmless')},
                {"malicious": category.count('malicious')},
                {"suspicious": category.count('suspicious')},
                {"timeout": category.count('timeout')},
                {"undetected": category.count('undetected')}
        ]
        summary['reputation'] = response.get('data')\
            .get('attributes').get('reputation')
        return summary
    else:
        return response.get('error')


# GET STATUS from Virustoatl
async def get_virustotal_status(value: str):
    logging.info("space: --> get_virustotal_status()")
    data = await get_data_from_virustotal(value)
    if data.get('data'):
        fetch = data.get('data').get('attributes')\
            .get('last_analysis_results')
        category = [j['category'] for _, j in fetch.items()]
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
        return {'score': virusotal, 'status': status, "data": "PROCESSED"}
    else:
        return {'score': None, 'status': None, 'data': data.get('error')}


@app.get("/ip/{ip}", tags=["path-parameter"])
async def get_summary_with_ip_as_path_parameter(ip: str):
    """
    **Get summary details from 'Virustotal' and
        'Urlscan' API's with IP address.**

    **Path Parameter**
    - `ip`: Argument expected to be **Ipv4 address**

    **Expected Response** :
    - VirusTotal response with Vote, Category, reputation
    - UrlScan response with Domain, Ip address, Https transactions
    - Resolve IP Addresses
    """
    logging.info("space: --> get_summary_with_ip_as_path_parameter()")
    if valid_ip_address(ip):
        urlscan = await get_urlscan_summary(ip)
        virsustotal = await get_virustotal_summary(ip)
        resolve_ip = await get_resolve_ip(ip)
        if urlscan and virsustotal:
            return {
                "virustotal": virsustotal,
                "urlscan":  urlscan,
                "resolve IP": resolve_ip
            }
    raise HTTPException(status_code=404, detail="Provide Valid IPv4 address.")


@app.get("/domain/{domain}", tags=["path-parameter"])
async def get_summary_with_domain_as_path_parameter(domain: str):
    """
    **Get summary details from 'Virustotal' and
    'Urlscan' API's with Domain name.**

    **Path Parameter**
    - `domain`: Argument expected to be **Domain name**

    **Expected Response** :
    - VirusTotal response with Vote, Category, reputation
    - UrlScan response with Domain, Ip address, Https transactions
    - Resolve Ip address
    """
    logging.info("space: --> get_summary_with_domain_as_path_parameter()")
    if valid_domain_name(domain):
        urlscan = await get_urlscan_summary(domain)
        virsustotal = await get_virustotal_summary(domain)
        resolve_domain = await get_resolve_domain_name(domain)
        if urlscan and virsustotal:
            return {
                "virustotal": virsustotal,
                "urlscan":  urlscan,
                "Resolve Domain": resolve_domain
            }
    raise HTTPException(status_code=404, detail="Provide Valid Domain name.")


# Handling Json response
def handle_bool(arg):
    if arg == 'false':
        return False
    elif arg == 'true':
        return True


@app.get("/", tags=["malicious"])
async def get_application_details():
    """
    **Application Details**
    """
    logging.info("space: --> get_application_banner()")
    return application_banner


@app.get("/{type}", tags=["query-parameter"])
async def get_summary_with_query_parameter(
        type: str,
        data: Optional[str] = None
        ):
    """
    **Get IPv4 or Domain summary details from Virustotal and Urlscan API's.**

    **Query Parameter**
    - `type`: type will be **ip** or **domain** e.g., ip or domain
    - `data`: value of ip address or domain
        name e.g., google.com, redhat.in etc

    **Expected Response** :
    - VirusTotal response with Vote, Category, reputation
    - UrlScan response with Domain, Ip address, Https transactions
    - Resolve Ip address or DNS Name
    """
    logging.info("space: --> get_summary_with_query_parameter()")
    if data:
        if valid_ip_address(data) or valid_domain_name(data):
            if valid_ip_address(data):
                resolve = await get_resolve_ip(data)
            if valid_domain_name(data):
                resolve = await get_resolve_domain_name(data)
            urlscan = await get_urlscan_summary(data)
            virsustotal = await get_virustotal_summary(data)
            if urlscan and virsustotal:
                return {
                    "virustotal": virsustotal,
                    "urlscan":  urlscan,
                    "resolve": resolve
                }
        raise HTTPException(
            status_code=404,
            detail="Provide Valid IPv4 address or Domain name.")
    return application_banner


@app.post("/", tags=["malicious"])
async def determnation_of_malicious_result(
        type: str = Form(...),
        data: str = Form(...)):
    """
    **Post IPv4 address or Domain name for scanning results.
    It will post data to Virustotal and Urlscan
      for determination of `Malicious result`.**

    - How it work?
    Base on score calculation it determine
    Malicious status **True** or **False**.

    **Message Body**
    - **type**: type will be `ip` or `domain` e.g., ip or domain
    - **data**: value of ip address or domain
        name e.g., google.com, redhat.in etc
    """
    logging.info("space: --> determnation_of_malicious_result()")
    if type:
        if valid_ip_address(data) or valid_domain_name(data):
            urlscan = await get_urlscan_status(data)
            virustotal = await get_virustotal_status(data)
            if urlscan and virustotal:
                if virustotal.get('data') == "PROCESSED"\
                        and urlscan.get('status') != "PROCESSED":
                    status = virustotal.get('status')
                elif virustotal.get('data') != "PROCESSED"\
                        and urlscan.get('status') == "PROCESSED":
                    status = urlscan.get('status')
                elif virustotal.get('data') != "PROCESSED"\
                        and urlscan.get('status') != "PROCESSED":
                    status = f"""
                    VIRUSTOTAL: {virustotal.get('status')}
                    URLSCAN: {urlscan.get('status')}"""
                else:
                    status = any[
                        handle_bool(virustotal.get('status')),
                        handle_bool(urlscan.get('status'))]
                # Urlscan Error website score
                if urlscan.get('score') is None:
                    urlscore = urlscan.get('data')
                else:
                    urlscore = urlscan.get('score')
                # Virustotal Error website score
                if virustotal.get('score') is None:
                    vtscore = virustotal.get('data')
                else:
                    vtscore = virustotal.get('score')
                return {
                        "virustotal": vtscore,
                        "urlscan": urlscore,
                        "malicious": status,
                    }
        raise HTTPException(
            status_code=404,
            detail="Provide Valid IPv4 address or Domain name.")
    else:
        return application_banner

if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
