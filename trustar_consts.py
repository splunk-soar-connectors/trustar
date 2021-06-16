# File: trustar_consts.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

TRUSTAR_CONFIG_URL = "url"
TRUSTAR_CONFIG_ENCLAVE_IDS = "config_enclave_ids"
TRUSTAR_CONFIG_CLIENT_ID = "client_id"
TRUSTAR_CONFIG_CLIENT_SECRET = "client_secret"
TRUSTAR_REST_RESP_SUCCESS = 200
TRUSTAR_REST_RESP_BAD_REQUEST = 400
TRUSTAR_REST_RESP_BAD_REQUEST_MSG = "Bad Request"
TRUSTAR_REST_RESP_UNAUTHORIZED = 401
TRUSTAR_REST_RESP_UNAUTHORIZED_MSG = "Unauthorized"
TRUSTAR_REST_RESP_RESOURCE_NOT_FOUND = 404
TRUSTAR_REST_RESP_RESOURCE_NOT_FOUND_MSG = "Not Found"
TRUSTAR_REST_RESP_TOO_LONG = 413
TRUSTAR_REST_RESP_TOO_LONG_MSG = "Request body too large"
TRUSTAR_REST_RESP_INTERNAL_SERVER_ERROR = 500
TRUSTAR_REST_RESP_INTERNAL_SERVER_ERROR_MSG = "Internal Server Error"
TRUSTAR_REST_RESP_GATEWAY_TIMEOUT = 504
TRUSTAR_REST_RESP_GATEWAY_TIMEOUT_MSG = "Gateway Timeout"
TRUSTAR_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
TRUSTAR_EXCEPTION_OCCURRED = "Exception occurred"
TRUSTAR_ERR_SERVER_CONNECTION = "Connection failed"
TRUSTAR_ERR_JSON_PARSE = "Unable to parse the response into a dictionary.\nResponse text - {raw_text}"
TRUSTAR_ERR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: {detail}"
TRUSTAR_ERR_MISSING_FIELD = "Could not find '{field}' in REST response"
TRUSTAR_REST_RESP_OTHER_ERROR_MSG = "Error returned"
TRUSTAR_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
TRUSTAR_ERR_TIME_FORMAT = "Timestamp format incorrect"
TRUSTAR_ERR_TIME_PARSE = "Could not parse given time: {value_error}"
TRUSTAR_PRIROITY_EVENT_SCORES = [-1, 0, 1, 2, 3]
TRUSTAR_ERR_PRIROITY_EVENT_SCORES = "Not all given priority event scores are valid. Valid options are: -1, 0, 1, 2, 3"
TRUSTAR_STATUSES = ['CONFIRMED', 'IGNORED', 'UNRESOLVED']
TRUSTAR_ERR_STATUSES = "Not all given statuses are valid. Valid options are: 'CONFIRMED', 'IGNORED', 'UNRESOLVED'"
TRUSTAR_ERR_MISSING_ENCLAVE_ID = "Mandatory parameter enclave_ids is missing or no enclave_ids are yet configured"
TRUSTAR_UNKNOWN_ENCLAVE_ID = "Only configured enclave ID(s) should be provided"
TRUSTAR_CONNECTION_TEST_MSG = "Querying endpoint to verify the credentials provided"
TRUSTAR_TEST_CONNECTIVITY_FAIL = "Connectivity test failed"
TRUSTAR_TEST_CONNECTIVITY_PASS = "Connectivity test succeeded"
TRUSTAR_UNEXPECTED_RESPONSE = "Expected response not found: {response}"
TRUSTAR_BAD_REPORT_ID = "Server did not return a proper UUID: {response}"
TRUSTAR_GENERATE_TOKEN_ENDPOINT = "/oauth/token"
TRUSTAR_TOKEN_GENERATION_ERR = "Error while generating token"
TRUSTAR_JSON_REPORT_ID = "report_id"
TRUSTAR_JSON_REPORT_ID_TYPE = "id_type"
TRUSTAR_JSON_REPORT_TITLE = "report_title"
TRUSTAR_JSON_REPORT_BODY = "report_body"
TRUSTAR_JSON_DISTRIBUTION_TYPE = "distribution_type"
TRUSTAR_JSON_ENCLAVE_IDS = "enclave_ids"
TRUSTAR_JSON_TIME_DISCOVERED = "time_discovered"
TRUSTAR_JSON_TRACKING_ID = "external_tracking_id"
TRUSTAR_JSON_EXTERNAL_URL = "external_url"
TRUSTAR_JSON_DEST_ENCLAVE = "destination_enclave"
TRUSTAR_LATEST_IOC_ENDPOINT = "/api/1.3/indicators/latest"
TRUSTAR_GET_REPORT_ENDPOINT = "/api/1.3/reports/{report_id}"
TRUSTAR_COPY_REPORT_ENDPOINT = "/api/1.3/reports/copy/{report_id}"
TRUSTAR_MOVE_REPORT_ENDPOINT = "/api/1.3/reports/move/{report_id}"
TRUSTAR_SUBMIT_REPORT_ENDPOINT = "/api/1.3/reports"
TRUSTAR_UPDATE_REPORT_ENDPOINT = "/api/1.3/reports/{report_id}"
TRUSTAR_HUNT_ACTIONS_ENDPOINT = "/api/1.3/reports/correlate"
TRUSTAR_WHITELIST_ENDPOINT = "/api/1.3/whitelist"
TRUSTAR_ENCLAVES_ENDPOINT = "/api/1.3/enclaves"
TRUSTAR_PHISHING_SUBMISSIONS_ENDPOINT = "/api/1.3/triage/submissions"
TRUSTAR_PHISHING_INDICATORS_ENDPOINT = "/api/1.3/triage/indicators"
TRUSTAR_TRIAGE_SUBMISSION_ENDPOINT = "/api/1.3/triage/submissions/{submission_id}/status"
TRUSTAR_HUNT_IOC_PARAM = "ioc"
TRUSTAR_IOC_TYPE_PARAM = "ioc_type"
TRUSTAR_HUNT_IP_PARAM = "ip"
TRUSTAR_HUNT_URL_PARAM = "url"
TRUSTAR_HUNT_FILE_PARAM = "file"
TRUSTAR_HUNT_EMAIL_PARAM = "email"
TRUSTAR_HUNT_CVE_PARAM = "cve_number"
TRUSTAR_HUNT_MALWARE_PARAM = "malware"
TRUSTAR_HUNT_REGISTRY_KEY_PARAM = "registry_key"
TRUSTAR_HUNT_BITCOIN_ADDRESS_PARAM = "bitcoin_address"
TRUSTAR_IP_VALIDATION_FAILED = "Parameter 'ip' failed validation"
TRUSTAR_INGESTION_REQUEST_TIME_ERROR = "Invalid request time encountered"
TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY = "No correlated reports available. There might be no correlated reports in" \
                                           " TruSTAR for the specified IOC or" \
                                           " the specified IOC value might be less than 4 characters."
