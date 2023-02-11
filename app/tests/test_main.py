import os
from fastapi.testclient import TestClient
import app.main
import logging
from app.utility.configure import IntConfig
import pytest
from httpx import AsyncClient

# TEST Variable
IP_ADDRESS = "209.132.183.105"
DOMAIN_NAME = "google.com"
SCAN_ID = "5fc71aba-8b60-4f3e-80d0-e8b14a3f7f1c"

# Configuration setup
config = os.path.join(os.path.abspath('.'), "resources", "config.json")
configure = IntConfig(config)
configure.load_config()

client = TestClient(main.app)


def test_conifguration_file_is_configured_and_loaded():
    logging.info("test_conifguration_file_is_configured_and_loaded")
    assert configure.data["urlScanUrl"] != ""
    assert configure.data["virustotalUrl"] != ""
    assert os.getenv('urlscanApiKey') != ""
    assert os.getenv('virustotalApiKey') != ""
    assert os.getenv('scan_wait_time') != ""


def test_application_response_for_200():
    logging.info('test_application_response_for_200')
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == main.application_banner


def test_domain_name_validation():
    logging.info('test_domain_name_validation')
    assert main.valid_domain_name(DOMAIN_NAME) ==\
        f"{DOMAIN_NAME.split('.')[0]}.".split()


def test_ip_address_validation():
    logging.info('test_ip_address_validation')
    assert main.valid_ip_address(IP_ADDRESS) ==\
        list(IP_ADDRESS.split())


@pytest.mark.asyncio
async def test_get_resolve_ip_address():
    async with AsyncClient(app=main.app, base_url="http://test"):
        response = await main.get_resolve_ip(IP_ADDRESS)
    assert response == IP_ADDRESS


@pytest.mark.asyncio
async def test_get_resolve_damain_name():
    logging.info('test_get_resolve_damain_name')
    async with AsyncClient(app=main.app, base_url="http://test"):
        response = await main.get_resolve_domain_name(DOMAIN_NAME)
    assert response != list(IP_ADDRESS.split())


@pytest.mark.asyncio
async def test_post_data_from_urlscan():
    logging.info('test_get_resolve_damain_name')
    async with AsyncClient(app=main.app, base_url="http://test"):
        response = await main.post_data_from_urlscan(DOMAIN_NAME)
    assert len(response) == 36


@pytest.mark.asyncio
async def test_get_summary_with_ip_as_path_parameter():
    """
    {
        "resolve IP": "192.192.10.1",
        "urlscan": {"ERR_EMPTY_RESPONSE": "We could not scan this website!"},
        "virustotal": {
            "category": [
                {"harmless": 85},
                {"malicious": 0},
                {"suspicious": 0},
                {"timeout": 0},
                {"undetected": 0}],
                "id": "192.192.10.1",
                "owner": "National Taiwan University",
                "reputation": 0,
                "votes": {"harmless": 0, "malicious": 0}}}
    """
    async with AsyncClient(app=main.app, base_url="http://test") as ac:
        response = await ac.get(f"/ip/{IP_ADDRESS}")
    assert response.status_code == 200
    assert response.json().get('resolve IP') == IP_ADDRESS


@pytest.mark.asyncio
async def test_get_summary_with_domain_name_as_path_parameter():
    logging.info("test_get_summary_with_domain_name_as_path_parameter")
    """
    {
                "virustotal": {
                    "owner": "null",
                    "id": "codelocked.com",
                    "votes": { "harmless": 0,"malicious": 0 },
                    "category": [
                    {"harmless": 85},
                    {"malicious": 0},
                    {"suspicious": 0},
                    {"timeout": 0},
                    {"undetected": 0}
                    ],
                    "reputation": 0
                },
                "urlscan": {
                    "main domain": "i1.cdn-image.com",
                    "Ips address": [
                    "2.16.186.106",
                    "209.99.64.70"
                    ],
                    "Category": [],
                    "HTTP transactions": 10
                },
                "Resolve Domain": [
                    "209.99.64.70"]}
    """
    async with AsyncClient(app=main.app, base_url="http://test") as ac:
        response = await ac.get(f"/domain/{DOMAIN_NAME}")
    assert response.status_code == 200
    assert response.json().get('id') != DOMAIN_NAME


@pytest.mark.asyncio
async def test_get_summary_with_ip_in_query_parameter():
    """
    {
        "virustotal": {
            "owner": "National Taiwan University",
            "id": "192.192.10.1",
            "votes": {
            "harmless": 0,
            "malicious": 0},
            "category": [
            {"harmless": 85},
            {"malicious": 0},
            {"suspicious": 0},
            {"timeout": 0},
            {"undetected": 0}
            ],
            "reputation": 0
        },
        "urlscan": {
            "ERR_EMPTY_RESPONSE": "We could not scan this website!"
        },
        "resolve": "192.192.10.1"
        }
    """
    async with AsyncClient(app=main.app, base_url="http://test") as ac:
        response = await ac.get(f"/ip?data={IP_ADDRESS}")
    assert response.status_code == 200
    assert response.json().get('resolve') == IP_ADDRESS


@pytest.mark.asyncio
async def test_get_summary_with_domain_in_query_parameter():
    """{
            "virustotal": {
                "owner": "null",
                "id": "codelocked.com",
                "votes": {
                "harmless": 0,
                "malicious": 0},
                "category": [
                {"harmless": 85},
                { "malicious": 0},
                {"suspicious": 0},
                {"timeout": 0},
                {"undetected": 0}
                ],
                "reputation": 0
            },
            "urlscan": {
                "main domain": "fonts.googleapis.com",
                "Ips address": [
                "2a00:1450:4001:813::2004",
                "185.53.178.30",
                "209.99.64.70",
                "2600:9000:2190:6600:1f:4100:9540:21",
                "13.224.96.33",
                "2a00:1450:4001:831::2003",
                "2a00:1450:4001:831::200a"
                ],
                "Category": [],
                "HTTP transactions": 25
            },
            "resolve": [
                "209.99.64.70"
            ]
            }
    """
    async with AsyncClient(app=main.app, base_url="http://test") as ac:
        response = await ac.get(f"/domain?data={DOMAIN_NAME}")
    assert response.status_code == 200
    assert response.json().get('resolve') != list(IP_ADDRESS.split())


@pytest.mark.asyncio
async def test_determnation_of_malicious_result():
    """
    {
        "malicious": False,
        "urlscan": {
            "community": 0,
            "engines": 0,
            "overall": 0,
            "urlscan": 0},
        "virustotal": {
            "harmless": 85}}
    """
    async with AsyncClient(app=main.app, base_url="http://test") as ac:
        data = {"type": "ip", "data": IP_ADDRESS}
        response = await ac.post("/", data=data)
    assert response.status_code == 200
    assert response.json().get('malicious') is False


@pytest.mark.asyncio
async def test_determnation_of_malicious_result_with_domain():
    """
    {
        "malicious": False,
        "urlscan": {
            "community": 0,
            "engines": 0,
            "overall": 0,
            "urlscan": 0},
        "virustotal": {
            "harmless": 85}}
    """
    async with AsyncClient(app=main.app, base_url="http://test") as ac:
        data = {"type": "domain", "data": DOMAIN_NAME}
        response = await ac.post("/", data=data)
    assert response.status_code == 200
    assert response.json().get('malicious') is not False


@pytest.mark.asyncio
async def test_determination_of_malicious_application_banner():
    async with AsyncClient(app=main.app, base_url="http://test") as ac:
        response = await ac.get("/")
    assert response.status_code == 200
    assert response.json() == main.application_banner
