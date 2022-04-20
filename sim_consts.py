# File: sim_consts.py
#
# Copyright (c) 2017-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
SIM_CONFIG_URL = "url"
SIM_CONFIG_ENCLAVE_IDS = "config_enclave_ids"
SIM_CONFIG_CLIENT_ID = "client_id"
SIM_CONFIG_CLIENT_SECRET = "client_secret"  # pragma: allowlist secret
SIM_CONFIG_WAIT_TIME = "max_wait_time"
SIM_PAGE_SIZE = 100
SIM_PAGE_SIZE_API_2 = 999
SIM_PAGE_NUMBER = 0
SIM_DEFAULT_MAX_WAIT_TIME = 10
SIM_OBSERVABLE_TYPES = [
    "BITCOIN_ADDRESS",
    "CIDR_BLOCK",
    "EMAIL_ADDRESS",
    "IP4",
    "IP6",
    "MD5",
    "PHONE_NUMBER",
    "REGISTRY_KEY",
    "SHA1",
    "SHA256",
    "SOFTWARE",
    "URL",
    "X_ID",
    "DOMAIN",
]
SIM_REST_RESP_SUCCESS = 200
SIM_REST_RESP_BAD_REQUEST = 400
SIM_REST_RESP_BAD_REQUEST_MSG = "Bad Request"
SIM_REST_RESP_UNAUTHORIZED = 401
SIM_REST_RESP_UNAUTHORIZED_MSG = "Unauthorized"
SIM_REST_RESP_RESOURCE_NOT_FOUND = 404
SIM_REST_RESP_RESOURCE_NOT_FOUND_MSG = "Not Found"
SIM_REST_RESP_TOO_LONG = 413
SIM_REST_RESP_TOO_LONG_MSG = "Request body too large"
SIM_REST_RESP_INTERNAL_SERVER_ERROR = 500
SIM_REST_RESP_INTERNAL_SERVER_ERROR_MSG = "Internal Server Error"
SIM_REST_RESP_GATEWAY_TIMEOUT = 504
SIM_REST_RESP_GATEWAY_TIMEOUT_MSG = "Gateway Timeout"
SIM_REST_TOO_MANY_REQUESTS = 429
SIM_REST_TOO_MANY_REQUESTS_MSG = "Request limit exceeded for the current time period"
SIM_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
SIM_EXCEPTION_OCCURRED = "Exception occurred"
SIM_ERR_SERVER_CONNECTION = "Connection failed"
SIM_ERR_JSON_PARSE = "Unable to parse the response into a dictionary.\nResponse text - {raw_text}"
SIM_ERR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: {detail}"
SIM_ERR_MISSING_FIELD = "Could not find '{field}' in REST response"
SIM_REST_RESP_OTHER_ERROR_MSG = "Error returned"
SIM_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
SIM_ERR_TIME_FORMAT = "Timestamp format incorrect"
SIM_ERR_TIME_PARSE = "Could not parse given time: {value_error}"
SIM_ERR_PRIORITY_EVENT_SCORES = "Not all given priority event scores are valid. Valid options are: -1, 0, 1, 2, 3"
SIM_STATUSES = ["CONFIRMED", "IGNORED", "UNRESOLVED"]
SIM_ERR_STATUSES = "Not all given statuses are valid. Valid options are: 'CONFIRMED', 'IGNORED', 'UNRESOLVED'"
SIM_ERR_MISSING_ENCLAVE_ID = "Mandatory parameter enclave_ids is missing or no enclave_ids are yet configured"
SIM_UNKNOWN_ENCLAVE_ID = "Only configured enclave ID(s) should be provided"
SIM_CONNECTION_TEST_MSG = "Querying endpoint to verify the credentials provided"
SIM_TEST_CONNECTIVITY_FAIL = "Test connectivity failed"
SIM_TEST_CONNECTIVITY_PASS = "Test connectivity passed"
SIM_UNEXPECTED_RESPONSE = "Expected response not found: {response}"
SIM_BAD_REPORT_ID = "Server did not return a proper UUID: {response}"
SIM_VALID_INT_MSG = "Please provide a valid integer value in the '{param}' parameter"
SIM_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in '{param}' parameter"
SIM_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the '{param}' parameter"
SIM_GENERATE_TOKEN_ENDPOINT = "/oauth/token"
SIM_TOKEN_GENERATION_ERR = "Error while generating token"
SIM_JSON_REPORT_ID = "report_id"
SIM_JSON_REPORT_ID_TYPE = "id_type"
SIM_JSON_REPORT_TITLE = "report_title"
SIM_JSON_REPORT_BODY = "report_body"
SIM_JSON_DISTRIBUTION_TYPE = "distribution_type"
SIM_JSON_ENCLAVE_IDS = "enclave_ids"
SIM_JSON_TIME_DISCOVERED = "time_discovered"
SIM_JSON_TRACKING_ID = "external_tracking_id"
SIM_JSON_EXTERNAL_URL = "external_url"
SIM_JSON_DEST_ENCLAVE = "destination_enclave"
SIM_OAUTH_TOKEN_STRING = "token"
SIM_OAUTH_ACCESS_TOKEN_STRING = "access_token"
SIM_AUTHORIZATION_HEADER = "Bearer {token}"
SIM_LATEST_IOC_ENDPOINT = "/api/1.3/indicators/latest"
SIM_GET_REPORT_ENDPOINT = "/api/1.3/reports/{report_id}"
SIM_COPY_REPORT_ENDPOINT = "/api/1.3/reports/copy/{report_id}"
SIM_MOVE_REPORT_ENDPOINT = "/api/1.3/reports/move/{report_id}"
SIM_SUBMIT_REPORT_ENDPOINT = "/api/1.3/reports"
SIM_UPDATE_REPORT_ENDPOINT = "/api/1.3/reports/{report_id}"
SIM_HUNT_ACTIONS_ENDPOINT = "/api/1.3/reports/correlate"
SIM_WHITELIST_ENDPOINT = "/api/1.3/whitelist"
SIM_ENCLAVES_ENDPOINT = "/api/1.3/enclaves"
SIM_PHISHING_SUBMISSIONS_ENDPOINT = "/api/1.3/triage/submissions"
SIM_PHISHING_INDICATORS_ENDPOINT = "/api/1.3/triage/indicators"
SIM_INDICATORS_METADATA_ENDPOINT = "/api/1.3/indicators/metadata"
SIM_INDICATORS_SUMMARY_ENDPOINT = "/api/1.3/indicators/summaries"
SIM_PARSE_ENTITIES_ENDPOINT = "/api/2.0/entities/parse"
SIM_ENRICH_INDICATOR_ENDPOINT = "/api/2.0/indicators/search"
SIM_TRIAGE_SUBMISSION_ENDPOINT = "/api/1.3/triage/submissions/{submission_id}/status"
SIM_HUNT_IOC_PARAM = "ioc"
SIM_IOC_TYPE_PARAM = "ioc_type"
SIM_HUNT_IP_PARAM = "ip"
SIM_HUNT_URL_PARAM = "url"
SIM_HUNT_FILE_PARAM = "file"
SIM_HUNT_EMAIL_PARAM = "email"
SIM_HUNT_CVE_PARAM = "cve_number"
SIM_HUNT_MALWARE_PARAM = "malware"
SIM_HUNT_REGISTRY_KEY_PARAM = "registry_key"
SIM_HUNT_BITCOIN_ADDRESS_PARAM = "bitcoin_address"
SIM_IP_VALIDATION_FAILED = "Parameter 'ip' failed validation"
SIM_INGESTION_REQUEST_TIME_ERROR = "Invalid request time encountered"
SIM_LESS_INDICATOR_TYPE = "Please provide indicator type for every value."
SIM_LESS_VALUE = "Please provide value for every indicator type."
SIM_INVALID_LIST_MSG = "Please enter the value of {param} parameter in form of list"
SIM_REASON_FOR_REPORT_UNAVAILABILITY = (
    "No correlated reports available. There might be no correlated reports in"
    " Splunk Intelligence Management for the specified IOC or"
    " the specified IOC value might be less than 4 characters."
)
SIM_INVALID_TOKEN_MESSAGES = ("Expired oauth2 access token", "Invalid oauth2 access token")
SIM_DEFAULT_TIMEOUT = 30
