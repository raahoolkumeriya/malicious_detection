# Malicious IPv4 or Domain Detection 
[![Docker Image CI](https://github.com/raahoolkumeriya/malicious_detection/actions/workflows/docker-image.yml/badge.svg)](https://github.com/raahoolkumeriya/malicious_detection/actions/workflows/docker-image.yml)
[![GitHub issues](https://img.shields.io/github/issues/raahoolkumeriya/malicious_detection)](https://github.com/raahoolkumeriya/malicious_detection/issues)
[![GitHub stars](https://img.shields.io/github/stars/raahoolkumeriya/malicious_detection)](https://github.com/raahoolkumeriya/malicious_detection/stargazers)
[![GitHub license](https://img.shields.io/github/license/raahoolkumeriya/malicious_detection)](https://github.com/raahoolkumeriya/malicious_detection)
[![GitHub license](https://img.shields.io/website-up-down-green-red/http/monip.org.svg)](website:https://maliciousdetection.herokuapp.com/docs)

[![Twitter](https://img.shields.io/twitter/url?url=https%3A%2F%2Ftwitter.com%2FKumeriyaRahul)](https://twitter.com/intent/tweet?text=Wow:&url=https%3A%2F%2Fgithub.com%2Fraahoolkumeriya%2Fmalicious_detection)


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

    └─ $ ▶ pytest -p no:warnings tests -v --color=yes --exitfirst --showlocals --durations=5  -vv
    ========================================================================== test session starts ==========================================================================
    platform linux -- Python 3.9.5, pytest-6.2.4, py-1.10.0, pluggy-0.13.1 -- /home/raahool/anaconda3/envs/HSBC/bin/python
    cachedir: .pytest_cache
    rootdir: /application/coding_test/malicious_detection
    plugins: anyio-3.3.0, asyncio-0.15.1
    collected 14 items                                                                                                                                                      

    tests/test_main.py::test_conifguration_file_is_configured_and_loaded PASSED                                                                                       [  7%]
    tests/test_main.py::test_application_response_for_200 PASSED                                                                                                      [ 14%]
    tests/test_main.py::test_domain_name_validation PASSED                                                                                                            [ 21%]
    tests/test_main.py::test_ip_address_validation PASSED                                                                                                             [ 28%]
    tests/test_main.py::test_get_resolve_ip_address PASSED                                                                                                            [ 35%]
    tests/test_main.py::test_get_resolve_damain_name PASSED                                                                                                           [ 42%]
    tests/test_main.py::test_post_data_from_urlscan PASSED                                                                                                            [ 50%]
    tests/test_main.py::test_get_summary_with_ip_as_path_parameter PASSED                                                                                             [ 57%]
    tests/test_main.py::test_get_summary_with_domain_name_as_path_parameter PASSED                                                                                    [ 64%]
    tests/test_main.py::test_get_summary_with_ip_in_query_parameter PASSED                                                                                            [ 71%]
    tests/test_main.py::test_get_summary_with_domain_in_query_parameter PASSED                                                                                        [ 78%]
    tests/test_main.py::test_determnation_of_malicious_result PASSED                                                                                                  [ 85%]
    tests/test_main.py::test_determnation_of_malicious_result_with_domain PASSED                                                                                      [ 92%]
    tests/test_main.py::test_determination_of_malicious_application_banner PASSED                                                                                     [100%]

    ========================================================================== slowest 5 durations ==========================================================================
    38.67s call     tests/test_main.py::test_get_summary_with_ip_as_path_parameter
    37.46s call     tests/test_main.py::test_get_summary_with_domain_in_query_parameter
    36.53s call     tests/test_main.py::test_get_summary_with_ip_in_query_parameter
    35.98s call     tests/test_main.py::test_get_summary_with_domain_name_as_path_parameter
    34.86s call     tests/test_main.py::test_determnation_of_malicious_result
    ==================================================================== 14 passed in 219.63s (0:03:39) =====================================================================

# Dockerise version
### Build the Docker Image

Go to the project directory (in where your Dockerfile is, containing your app directory).
- Build your FastAPI image:

```docker build -t malicious .```

### Start the Docker Container
- Run a container based on your image:
```docker run -d --name malicious_detection -p 80:80 malicious```

#### Check it
You should be able to check it in your Docker container's URL, for example: http://192.168.99.100/ or http://127.0.0.1/ (or equivalent, using your Docker host).

#### Interactive API docs
Now you can go to http://192.168.99.100/docs or http://127.0.0.1/docs (or equivalent, using your Docker host).

#### Alternative API docs¶
And you can also go to http://192.168.99.100/redoc or http://127.0.0.1/redoc (or equivalent, using your Docker host).
