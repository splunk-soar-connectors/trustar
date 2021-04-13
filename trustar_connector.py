# File: trustar_connector.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Standard library imports
from dateutil import parser, tz
import requests
import datetime
import socket
import json

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
import trustar_consts as consts

# Dictionary containing details of possible HTTP error codes in API Response
ERROR_RESPONSE_DICT = {
    consts.TRUSTAR_REST_RESP_BAD_REQUEST: consts.TRUSTAR_REST_RESP_BAD_REQUEST_MSG,
    consts.TRUSTAR_REST_RESP_UNAUTHORIZED: consts.TRUSTAR_REST_RESP_UNAUTHORIZED_MSG,
    consts.TRUSTAR_REST_RESP_RESOURCE_NOT_FOUND: consts.TRUSTAR_REST_RESP_RESOURCE_NOT_FOUND_MSG,
    consts.TRUSTAR_REST_RESP_TOO_LONG: consts.TRUSTAR_REST_RESP_TOO_LONG_MSG,
    consts.TRUSTAR_REST_RESP_INTERNAL_SERVER_ERROR: consts.TRUSTAR_REST_RESP_INTERNAL_SERVER_ERROR_MSG,
    consts.TRUSTAR_REST_RESP_GATEWAY_TIMEOUT: consts.TRUSTAR_REST_RESP_GATEWAY_TIMEOUT_MSG
}


def _break_ip_address(cidr_ip_address):
    """ Function divides the input parameter into IP address and network mask.

    :param cidr_ip_address: IP address in format of IP/prefix_size
    :return: IP, prefix_size
    """

    if "/" in cidr_ip_address:
        ip_address, prefix_size = cidr_ip_address.split("/")
    else:
        ip_address = cidr_ip_address
        prefix_size = 0

    return ip_address, int(prefix_size)


def _is_ipv6(ip_address):
    """ Function that checks given address and return True if address is IPv6 address.

    :param ip_address: input parameter IP address
    :return: status (success/failure)
    """

    try:
        # Validating IPv6 address
        socket.inet_pton(socket.AF_INET6, ip_address)
    except socket.error:
        return False

    return True


class TrustarConnector(BaseConnector):
    """ This is an AppConnector class that inherits the BaseConnector class. It implements various actions supported by
    TruSTAR and helper methods required to run the actions.
    """

    def __init__(self):

        # Calling the BaseConnector's init function
        super(TrustarConnector, self).__init__()
        self._url = None
        self._config_enclave_ids = None
        self._client_id = None
        self._client_secret = None
        self._access_token = None
        self._app_state = dict()

        return

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        # Get configuration dictionary
        config = self.get_config()
        self._url = config[consts.TRUSTAR_CONFIG_URL].strip('/')
        self._config_enclave_ids = config.get(consts.TRUSTAR_CONFIG_ENCLAVE_IDS)
        self._client_id = config[consts.TRUSTAR_CONFIG_CLIENT_ID]
        self._client_secret = config[consts.TRUSTAR_CONFIG_CLIENT_SECRET]
        # Load the state of app stored in JSON file
        self._app_state = self.load_state()
        # Custom validation for IP address
        self.set_validator(consts.TRUSTAR_HUNT_IP_PARAM, self._is_ip)

        return phantom.APP_SUCCESS

    def _is_ip(self, cidr_ip_address):
        """ Function that checks given address and return True if address is valid IPv4/IPv6 address.

        :param cidr_ip_address: IP/CIDR
        :return: status (success/failure)
        """

        try:
            ip_address, net_mask = _break_ip_address(cidr_ip_address)
        except Exception as e:
            self.debug_print(consts.TRUSTAR_IP_VALIDATION_FAILED, e)
            return False

        # Validate IP address
        if not (phantom.is_ip(ip_address) or _is_ipv6(ip_address)):
            self.debug_print(consts.TRUSTAR_IP_VALIDATION_FAILED)
            return False

        # Check if net mask is out of range
        if (":" in ip_address and net_mask not in range(0, 129)) or ("." in ip_address and net_mask not in range(0, 33)):
            self.debug_print(consts.TRUSTAR_IP_VALIDATION_FAILED)
            return False

        return True

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get",
                        timeout=None, auth=None):
        """ Function that makes the REST call to the device. It is a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters if method is get
        :param data: request body
        :param method: get/post/put/delete ( Default method will be 'get' )
        :param timeout: request timeout
        :param auth: client credentials
        :return: status success/failure(along with appropriate message), response obtained by making an API call
        """

        response_data = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            self.debug_print(consts.TRUSTAR_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(
                phantom.APP_ERROR, consts.TRUSTAR_ERR_API_UNSUPPORTED_METHOD, method=method
            ), response_data
        except Exception as e:
            self.debug_print(consts.TRUSTAR_EXCEPTION_OCCURRED, e)
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_EXCEPTION_OCCURRED, e), response_data

        try:
            # For all actions
            if auth is None:
                auth_headers = {"Authorization": "Bearer {token}".format(token=self._access_token)}
                # Update headers
                if headers:
                    auth_headers.update(headers)
                response = request_func("{base_url}{endpoint}".format(base_url=self._url, endpoint=endpoint),
                                        params=params, headers=auth_headers, data=data, verify=False,
                                        timeout=timeout)
            # For generating API token
            else:
                response = request_func("{base_url}{endpoint}".format(base_url=self._url, endpoint=endpoint),
                                        auth=auth, data=data, verify=False, timeout=timeout)
        except Exception as e:
            self.debug_print(consts.TRUSTAR_ERR_SERVER_CONNECTION, e)
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_ERR_SERVER_CONNECTION, e), response_data

        # Store response status_code, text and headers in debug data, it will get dumped in the logs
        if hasattr(action_result, 'add_debug_data'):
            if response is not None:
                action_result.add_debug_data({'r_status_code': response.status_code})
                action_result.add_debug_data({'r_text': response.text})
                action_result.add_debug_data({'r_headers': response.headers})
            else:
                action_result.add_debug_data({'r_text': 'r is None'})

        # Try parsing the json
        try:
            content_type = response.headers.get("content-type")
            if content_type and content_type.find("json") != -1:
                response_data = response.json()
            else:
                response_data = response.text

        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = consts.TRUSTAR_ERR_JSON_PARSE.format(raw_text=response.text)
            self.debug_print(msg_string, e)
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, msg_string, e), response_data

        if response.status_code in ERROR_RESPONSE_DICT:
            message = ERROR_RESPONSE_DICT[response.status_code]

            # Overriding message if available in response
            if isinstance(response_data, dict):
                message = response_data.get("message", message)

            self.debug_print(consts.TRUSTAR_ERR_FROM_SERVER.format(status=response.status_code, detail=message))
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_ERR_FROM_SERVER,
                                            status=response.status_code, detail=message), response_data

        # In case of success scenario
        if response.status_code == consts.TRUSTAR_REST_RESP_SUCCESS:
            if isinstance(response_data, dict) or isinstance(response_data, list):
                return phantom.APP_SUCCESS, response_data

            # If response obtained is not in the desired format
            self.debug_print(consts.TRUSTAR_UNEXPECTED_RESPONSE.format(response=response_data))
            return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_UNEXPECTED_RESPONSE.format(
                response=response_data
            )), response_data

        # If response code is unknown
        message = consts.TRUSTAR_REST_RESP_OTHER_ERROR_MSG

        if isinstance(response_data, dict):
            message = response_data.get("message", message)

        self.debug_print(consts.TRUSTAR_ERR_FROM_SERVER.format(status=response.status_code, detail=message))

        # All other response codes from REST call
        # Set the action_result status to error, the handler function will most probably return as is
        return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_ERR_FROM_SERVER,
                                        status=response.status_code,
                                        detail=message), response_data

    def _generate_api_token(self, action_result):
        """ This function is used to generate token.

        :param action_result: object of ActionResult class
        :return: status success/failure
        """

        data = {'grant_type': 'client_credentials'}

        timeout = 30 if self.get_action_identifier() == "test_asset_connectivity" else None

        # Querying endpoint to generate token
        status, response = self._make_rest_call(consts.TRUSTAR_GENERATE_TOKEN_ENDPOINT, action_result, method="post",
                                                data=data, timeout=timeout, auth=(self._client_id, self._client_secret))

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        # Get access token
        self._access_token = response.get("access_token")

        # Validate access token
        if not self._access_token:
            self.debug_print(consts.TRUSTAR_TOKEN_GENERATION_ERR)
            return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_TOKEN_GENERATION_ERR)

        return phantom.APP_SUCCESS

    def _test_asset_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = ActionResult()
        self.save_progress(consts.TRUSTAR_CONNECTION_TEST_MSG)
        self.save_progress("Configured URL: {url}".format(url=self._url))

        # Generate token
        token_generation_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(token_generation_status):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, consts.TRUSTAR_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, consts.TRUSTAR_TEST_CONNECTIVITY_PASS)
        return action_result.get_status()

    def _hunt_correlated_reports(self, action_result, ioc_to_hunt):
        """ This action gets the list of correlated reports for the IOC provided.

        :param action_result: object of ActionResult class
        :param ioc_to_hunt: IOC to query
        :return: request status and response of the request
        """

        # Generate token
        token_generation_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(token_generation_status):
            return action_result.get_status(), None

        # Prepare request params
        params = {'q': ioc_to_hunt}

        # Make REST call
        return self._make_rest_call(consts.TRUSTAR_HUNT_ACTIONS_ENDPOINT, action_result, params=params)

    def _hunt_ip(self, param):
        """ Get list of all TruSTAR incident report IDs that correlate with the provided IP.

        :param param: dictionary on input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        ip = param[consts.TRUSTAR_HUNT_IP_PARAM]

        # Get correlated reports
        resp_status, response = self._hunt_correlated_reports(action_result, ip)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, consts.TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY)

        # Update summary data
        summary_data["total_correlated_reports"] = len(response)

        for report_id in response:
            action_result.add_data({"report_id": report_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_url(self, param):
        """ Get list of all TruSTAR incident report IDs that correlate with the provided URL.

        :param param: dictionary on input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        url = param[consts.TRUSTAR_HUNT_URL_PARAM]

        # Get correlated reports
        resp_status, response = self._hunt_correlated_reports(action_result, url)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, consts.TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY)

        # Update summary data
        summary_data["total_correlated_reports"] = len(response)

        for report_id in response:
            action_result.add_data({"report_id": report_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_file(self, param):
        """ Get list of all TruSTAR incident report IDs that correlate with the provided hash.

        :param param: dictionary on input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        file_param = param[consts.TRUSTAR_HUNT_FILE_PARAM]

        # Get correlated reports
        resp_status, response = self._hunt_correlated_reports(action_result, file_param)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, consts.TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY)

        # Update summary data
        summary_data["total_correlated_reports"] = len(response)

        for report_id in response:
            action_result.add_data({"report_id": report_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_email(self, param):
        """ Get list of all TruSTAR incident report IDs that correlate with the provided email.

        :param param: dictionary on input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        email = param[consts.TRUSTAR_HUNT_EMAIL_PARAM]

        # Get correlated reports
        resp_status, response = self._hunt_correlated_reports(action_result, email)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, consts.TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY)

        # Update summary data
        summary_data["total_correlated_reports"] = len(response)

        for report_id in response:
            action_result.add_data({"report_id": report_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_cve(self, param):
        """ Get list of all TruSTAR incident report IDs that correlate with the provided
         CVE(Common Vulnerability and Exposure) number.

        :param param: dictionary on input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        cve_number = param[consts.TRUSTAR_HUNT_CVE_PARAM]

        # Get correlated reports
        resp_status, response = self._hunt_correlated_reports(action_result, cve_number)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, consts.TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY)

        # Update summary data
        summary_data["total_correlated_reports"] = len(response)

        for report_id in response:
            action_result.add_data({"report_id": report_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_malware(self, param):
        """ Get list of all TruSTAR incident report IDs that correlate with the provided
         Malware.

        :param param: dictionary on input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        malware = param[consts.TRUSTAR_HUNT_MALWARE_PARAM]

        # Get correlated reports
        resp_status, response = self._hunt_correlated_reports(action_result, malware)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, consts.TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY)

        # Update summary data
        summary_data["total_correlated_reports"] = len(response)

        for report_id in response:
            action_result.add_data({"report_id": report_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_registry_key(self, param):
        """ Get list of all TruSTAR incident report IDs that correlate with the provided
         Registry Key.

        :param param: dictionary on input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        registry_key = param[consts.TRUSTAR_HUNT_REGISTRY_KEY_PARAM]

        # Get correlated reports
        resp_status, response = self._hunt_correlated_reports(action_result, registry_key)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, consts.TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY)

        # Update summary data
        summary_data["total_correlated_reports"] = len(response)

        for report_id in response:
            action_result.add_data({"report_id": report_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_bitcoin_address(self, param):
        """ Get list of all TruSTAR incident report IDs that correlate with the provided
         Bitcoin Address.

        :param param: dictionary on input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        bitcoin_address = param[consts.TRUSTAR_HUNT_BITCOIN_ADDRESS_PARAM]

        # Get correlated reports
        resp_status, response = self._hunt_correlated_reports(action_result, bitcoin_address)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, consts.TRUSTAR_REASON_FOR_REPORT_UNAVAILABILITY)

        # Update summary data
        summary_data["total_correlated_reports"] = len(response)

        for report_id in response:
            action_result.add_data({"report_id": report_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_report(self, param):
        """ Return the raw report data, extracted indicators and other metadata for a TruSTAR report
         given its report id.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Mandatory parameters
        report_id = param[consts.TRUSTAR_JSON_REPORT_ID]

        # Optional parameters
        id_type = param.get(consts.TRUSTAR_JSON_REPORT_ID_TYPE, 'internal')

        # Request parameters
        query_param = {'idType': id_type}

        # Generate token
        token_generation_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(token_generation_status):
            return action_result.get_status()

        # Make REST call
        resp_status, response = self._make_rest_call(consts.TRUSTAR_GET_REPORT_ENDPOINT.format(report_id=report_id),
                                                     action_result, params=query_param, method="get")

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        # Overriding response
        for indicator in response.get('indicators', []):
            indicator[indicator['indicatorType']] = indicator['value']
            del indicator['indicatorType']
            del indicator['value']

        # Adding REST response to action_result.data
        action_result.add_data(response)

        summary_data['extracted_indicators_count'] = len(response.get('indicators', []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _normalize_timestamp(self, date_time):
        """ Attempt to convert a string timestamp in to a TruSTAR compatible format for submission.

        :param date_time: string/datetime object containing date, time, and ideally timezone
        examples of supported timestamp formats: "2017-02-23T23:01:54", "2017-02-23T23:01:54+0000"
        :return: datetime in ISO 8601 format
        """

        datetime_dt = datetime.datetime.now()

        try:
            if isinstance(date_time, str):
                datetime_dt = parser.parse(date_time)
            elif isinstance(date_time, datetime.datetime):
                datetime_dt = date_time

        except Exception as e:
            self.debug_print(consts.TRUSTAR_EXCEPTION_OCCURRED, e)
            return None

        # If timestamp is timezone naive, add timezone
        if not datetime_dt.tzinfo:
            # Add system timezone
            timezone = tz.tzlocal()
            datetime_dt.replace(tzinfo=timezone)
            # Convert to UTC
            datetime_dt = datetime_dt.astimezone(tz.tzutc())

        # Converts datetime to ISO8601
        return datetime_dt.isoformat()

    def _submit_report(self, param):
        """ Submit a report to community or enclaves and returns its TruSTAR report ID and
         extracted indicators from the report.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Mandatory parameters
        report_title = param[consts.TRUSTAR_JSON_REPORT_TITLE]
        report_body = param[consts.TRUSTAR_JSON_REPORT_BODY]
        distribution_type = param[consts.TRUSTAR_JSON_DISTRIBUTION_TYPE]

        # Optional parameters
        enclave_ids = param.get(consts.TRUSTAR_JSON_ENCLAVE_IDS)
        time_discovered = param.get(consts.TRUSTAR_JSON_TIME_DISCOVERED)
        external_tracking_id = param.get(consts.TRUSTAR_JSON_TRACKING_ID)

        # Normalize timestamp
        report_time_began = self._normalize_timestamp(time_discovered)
        if not report_time_began:
            return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_ERR_TIME_FORMAT)

        # Prepare request data
        submit_report_payload = {
            "incidentReport": {
                "title": report_title,
                "reportBody": report_body,
                "distributionType": distribution_type,
                "timeDiscovered": report_time_began
            }
        }

        # Update request data only if enclave_ids are provided
        if distribution_type == 'ENCLAVE':

            # If there are no given enclave IDs
            if not (enclave_ids or self._config_enclave_ids):
                return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_ERR_MISSING_ENCLAVE_ID)

            enclave_id_list = []

            if enclave_ids:
                # Strip out any commas
                enclave_ids = enclave_ids.strip(',')
                # Strip out white spaces from enclave_ids provided in action parameters
                enclave_id_list = enclave_ids.split(',')
                enclave_id_list = list(filter(lambda x: x.strip(), [enclave_id.strip() for enclave_id in enclave_id_list]))

            config_enclave_id_list = []

            if self._config_enclave_ids:
                # Strip out any commas
                self._config_enclave_ids = self._config_enclave_ids.strip(',')
                # Strip out white spaces from enclave_ids provided in asset configuration
                config_enclave_id_list = self._config_enclave_ids.split(',')
                config_enclave_id_list = list(filter(lambda x: x.strip(), [config_enclave_id.strip() for config_enclave_id in config_enclave_id_list]))

            # Return error if any of the enclave_id provided in action parameters is not configured in asset
            if set(enclave_id_list) - set(config_enclave_id_list):
                return action_result.set_status(phantom.APP_ERROR, consts.TRUSTAR_UNKNOWN_ENCLAVE_ID)

            if not enclave_id_list:
                enclave_id_list = config_enclave_id_list

            # Update request data
            submit_report_payload["enclaveIds"] = enclave_id_list

        if external_tracking_id:
            submit_report_payload["incidentReport"]["externalTrackingId"] = external_tracking_id

        # Generate token
        token_generation_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(token_generation_status):
            return action_result.get_status()

        # Make REST call
        resp_status, response = self._make_rest_call(consts.TRUSTAR_SUBMIT_REPORT_ENDPOINT, action_result, data=json.dumps(submit_report_payload),
                                                     method="post", headers={'Content-Type': 'application/json'})

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        action_result.add_data(response)

        # Calculate indicators from response
        indicators_count = 0
        for indicator in response.get('reportIndicators', {}):
            indicators_count += len(response['reportIndicators'][indicator])

        # Update summary data
        summary_data['report_id'] = response['reportId']
        summary_data['total_extracted_indicators'] = indicators_count

        return action_result.set_status(phantom.APP_SUCCESS)

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        """

        # Save current state of the app
        self.save_state(self._app_state)

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_asset_connectivity': self._test_asset_connectivity,
            'hunt_ip': self._hunt_ip,
            'hunt_url': self._hunt_url,
            'hunt_email': self._hunt_email,
            'hunt_file': self._hunt_file,
            'hunt_cve': self._hunt_cve,
            'hunt_malware': self._hunt_malware,
            'hunt_registry_key': self._hunt_registry_key,
            'hunt_bitcoin_address': self._hunt_bitcoin_address,
            'get_report': self._get_report,
            'submit_report': self._submit_report
        }

        action = self.get_action_identifier()

        try:
            run_action = action_mapping[action]
        except Exception:
            raise ValueError("action {action} is not supported".format(action=action))

        return run_action(param)


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = TrustarConnector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(return_value), indent=4))
    exit(0)
