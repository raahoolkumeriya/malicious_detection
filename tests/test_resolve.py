from utility import resolve
import logging

TEST_IP="10.10.10.10"
TEST_DOMAIN="abc.com"


def test_utility_resolve_get_ip():
    logging.info("test_utility_resolve_get_ip")
    assert resolve.getIP(TEST_IP) == {
        "result": ['10.10.10.10', []]
    } 

def test_utility_resolve_get_a_record():
    logging.info("test_utility_resolve_get_a_record")
    assert resolve.get_a_record(TEST_DOMAIN) != {
        'result': []}

def test_valid_domain_name():
    logging.info("test_valid_domain_name")
    assert resolve.valid_domain_name(TEST_DOMAIN) == ['abc.']

def test_valid_ip_address():
    logging.info("test_valid_ip_address")
    assert resolve.valid_ip_address(TEST_IP) == ["10.10.10.10"]