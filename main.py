import os
import re
import json
import logging
from fastapi import FastAPI, Form, HTTPException,\
    Query
from utility import URLScan, IntConfig, VirusTotal,\
    getIP, get_a_record, valid_domain_name, valid_ip_address

# Not Implmented for this Task
# Authentication not NotImplemented

# Configuration setup
config = os.path.join(os.path.dirname(__file__), "resources", "config.json")
configure = IntConfig(config)
configure.load_config()

logging.info("Configration loaded")

# Initiating VirusTotal
vt = VirusTotal(configure)
us = URLScan(configure)


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
    title="Malicious IPv4/Domain Detection",
    description="The service will accept IPv4 addresses and domains,\
        query external services and return appropriate responses.",
    version="1.0.0",
    servers=[
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
        "/ip/{ip_address}",
        "/domain/{domain_name}",
        "?type=ip&data={ip_address}",
        "?type=domain&data={domain_name}"
    ]
}


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
    logging.info('path_parameter ip endpoint called')
    if valid_ip_address(ip):
        get_vt_data = vt.get_data(ip)
        get_vt_summary = vt.get_summary(get_vt_data)
        get_us_data = us.post_data(ip)
        get_us_summary = us.get_summary(get_us_data)
        resolve_ip = getIP(ip)
        logging.info("URLSCAN:", get_us_summary)
        logging.info("VIRUSTOTAL:", get_vt_summary)
        return {
            "virustotal": get_vt_summary,
            "urlscan": get_us_summary,
            "resolve_ip": resolve_ip
            }
    else:
        logging.debug('IPv4 address validation failed')
        raise HTTPException(
            status_code=404,
            detail="IPv4 address validation failed",
            headers={"X-Error": "Valid IPv4 is expected"},
        )


@app.get("/domain/{domain}", tags=["path-parameter"])
async def get_summary_with_domain_path_parameter(domain: str):
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
    logging.info('path_parameter endpoint called')
    if valid_domain_name(domain):
        get_vt_data = vt.get_data(domain)
        get_vt_summary = vt.get_summary(get_vt_data)
        get_us_data = us.post_data(domain)
        get_us_summary = us.get_summary(get_us_data)
        resolve_domain = get_a_record(domain)
        print("URLSCAN:", get_us_summary)
        print("VIRUSTOTAL:", get_vt_summary)
        return {
            "virustotal": get_vt_summary,
            "urlscan": get_us_summary,
            "resolve": resolve_domain
            }
    else:
        logging.debug('Domain name not found')
        raise HTTPException(
            status_code=404,
            detail="Domain name is not Valid Domain",
            headers={"X-Error": "Valid Domain name fails standards."},
        )


def json_from_s(s):
    """To get all Matching Categories"""
    match = re.findall(r'"category": (\"\w*\")', s)
    return json.loads(match[0]) if match else None


def find_matches(d, item):
    """To Find matches in Json data"""
    for k in d:
        if re.match(k, item):
            return d[k]


# Handling Json response
def handle_bool(arg):
    """JSON string value in python"""
    if arg == 'false':
        return False
    elif arg == 'true':
        return True


@app.get("/", tags=["query-parameter"])
async def get_summary_with_query_parameter(
    type: str = Query(
            None,
            title="Ip or domain",
            description="""
            Query type IPv4 or Domain for result e.g., `ip` or `domain`""",
            ),
    data: str = Query(
            None,
            title="ip address or domain name",
            description="""
            Query data value for summary result
            e.g., `10.10.10.10` or `abc.com`""",
            )
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
    if type:
        if valid_domain_name(data) or valid_ip_address(data):
            get_vt_data = vt.get_data(data)
            get_vt_summary = vt.get_summary(get_vt_data)
            get_us_data = us.post_data(data)
            get_us_summary = us.get_summary(get_us_data)
            resolveIp = getIP(data)
            resolveDN = get_a_record(data)
            return {
                "virustotal": get_vt_summary,
                "urlscan": get_us_summary,
                "resolve": [resolveIp, resolveDN]
                }
        raise HTTPException(
            status_code=404,
            detail="Valid IPv4 or Domain name failed",
            headers={
                "X-Error": """
                Valid Domain name or Valid Ip address
                does not meet with standards."""
                }
        )
    else:
        return application_banner


@app.post("/", tags=["malicious"])
async def determnation_of_malicious_result(
        type: str = Form(...),
        data: str = Form(...)
        ):
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
    if valid_domain_name(data) or valid_ip_address(data):
        get_vt_data = vt.get_data(data)
        get_us_data = us.post_data(data)
        virustotal = vt.virustotal_status(get_vt_data)
        urlscan = us.urlscan_status(get_us_data)
        vgd = virustotal.get('data')
        ugs = urlscan.get('status')
        if vgd == "PROCESSED" and ugs != "PROCESSED":
            status = virustotal.get('status')
        elif vgd != "PROCESSED" and ugs == "PROCESSED":
            status = ugs
        elif vgd != "PROCESSED" and ugs != "PROCESSED":
            status = f"""VIRUSTOTAL:
             {virustotal.get('status')} URLSCAN: {ugs}"""
        else:
            status = any[
                handle_bool(virustotal.get('status')),
                handle_bool(ugs)]
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
    else:
        raise HTTPException(
            status_code=404,
            detail="Valid IPv4 or Domain name failed",
            headers={
                "X-Error": """Valid Domain name or Valid Ip
                address does not meet with standards."""
            }
        )
