from fastapi.testclient import TestClient
import main

client = TestClient(main.app)


def test_get_summary_with_query_parameter():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == main.application_banner


def test_get_summary_with_ip_as_path_parameter_not_200():
    response = client.get("/ip/10.10.10.10.12")
    assert response.status_code == 404
    assert response.json() == {
        "detail": "IPv4 address validation failed"
        }


def test_get_summary_with_domain_path_parameter_not_200():
    response = client.get("/domain/readhat.-com")
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Domain name is not Valid Domain"}


# def test_get_summary_with_ip_as_path_parameter_200():
#     response = client.get("/ip/10.10.10.10")
#     assert response.status_code == 200
#     assert response.json() == {
#         "virustotal":{"owner":"null",
#             "id":"10.10.10.10",
#             "votes":{
#                 "harmless":1,
#                 "malicious":3},
#                 "category":[
#                     {"harmless":74},
#                     {"malicious":0},
#                     {"suspicious":0},
#                     {"timeout":0},
#                     {"undetected":11}],
#                     "reputation":-42},
#         "urlscan":{
#             "message":"Not Found","description":"We could not find this page","status":404},
#         "resolve_ip":{
#             "result":[
#                 "10.10.10.10",["10.10.10.10"],[]]}
#             }


# def test_get_summary_with_domain_path_parameter_200():
#     response = client.get("/domain/redhat.com")
#     assert response.status_code == 200
#     assert response.json() == {
#         "virustotal":{
#             "owner":"null",
#             "id":"hsbc.com",
#             "votes":{
#                 "harmless":0,
#                 "malicious":0},
#             "category":[
#                 {"harmless":75},
#                 {"malicious":0},
#                 {"suspicious":0},
#                 {"timeout":0},
#                 {"undetected":10}],
#             "reputation":0},
#         "urlscan":{
#             "main domain":"www.hsbc.com",
#             "Ips address":[
#                 "91.214.6.62","13.224.90.110",
#                 "2a04:4e42:600::539","23.37.56.41",
#                 "2a04:4e42:1b::539","2a04:4e42:3::729",
#                 "23.218.209.37"],
#             "Category":[],
#             "HTTP transactions":57},
#         "resolve":{
#             "result":["193.108.75.62","91.214.6.62"]}
#         }
