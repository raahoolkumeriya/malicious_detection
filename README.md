# malicious_detection
Malicious Detection for IPv4 or Domain 

## Update API Keys in config.json File
Get Api keys from Virustotal and Urlscan to setup connection.
`urlscanApiKey` and `virustotalApiKey` update in config file or 
set and export environment variables with the above names.

## Setting Virtual Environment
Create virtual environment and install required packages.
`pip install -r requirements.txt`

## Run FastAPI app
`python main.py`

## Run tests
Tests for this project are defined in the tests/ folder.

This project uses pytest to define tests because it allows you to use the assert keyword with good formatting for failed assertations.

To run all the tests of a project, simply run the pytest command:


    └─ $ ▶ pytest -p no:warnings tests -v --color=yes --exitfirst --showlocals --durations=5
    ========================================================================== test session starts ==========================================================================
    platform linux -- Python 3.9.5, pytest-6.2.4, py-1.10.0, pluggy-0.13.1 -- /home/raahool/anaconda3/envs/HSBC/bin/python
    cachedir: .pytest_cache
    rootdir: /application/coding_test/GITHUB/malicious_detection
    collected 11 items                                                                                                                                                      

    tests/test_client.py::test_api_key_avilable_for_connection_in_urlscan PASSED                                                                                      [  9%]
    tests/test_client.py::test_api_key_avilable_for_connection_in_virustotal PASSED                                                                                   [ 18%]
    tests/test_client.py::test_connection_for_urlscan_api PASSED                                                                                                      [ 27%]
    tests/test_client.py::test_connection_for_virustotal_api PASSED                                                                                                   [ 36%]
    tests/test_main.py::test_get_summary_with_query_parameter PASSED                                                                                                  [ 45%]
    tests/test_main.py::test_get_summary_with_ip_as_path_parameter_not_200 PASSED                                                                                     [ 54%]
    tests/test_main.py::test_get_summary_with_domain_path_parameter_not_200 PASSED                                                                                    [ 63%]
    tests/test_resolve.py::test_utility_resolve_get_ip PASSED                                                                                                         [ 72%]
    tests/test_resolve.py::test_utility_resolve_get_a_record PASSED                                                                                                   [ 81%]
    tests/test_resolve.py::test_valid_domain_name PASSED                                                                                                              [ 90%]
    tests/test_resolve.py::test_valid_ip_address PASSED                                                                                                               [100%]

    ========================================================================== slowest 5 durations ==========================================================================
    4.83s call     tests/test_client.py::test_connection_for_urlscan_api
    2.15s call     tests/test_client.py::test_connection_for_virustotal_api
    0.57s call     tests/test_resolve.py::test_utility_resolve_get_a_record

    (2 durations < 0.005s hidden.  Use -vv to show these durations.)
    ========================================================================== 11 passed in 7.84s ===========================================================================
