# File: trustar_view.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Local imports
import time


def _parse_data(data):

    # Modify time format
    data['created'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['created'] / 1000))
    data['timeBegan'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['timeBegan'] / 1000))

    # Parse data so as to create dictionary that includes ioc_name as key and list of ioc_value as its value
    indicators = data.get("indicators")
    ioc_details = dict()
    if indicators:
        for indicator in indicators:
            for key in indicator:
                if key not in ['IP', 'CIDR_BLOCK', 'URL', 'SOFTWARE', 'MD5', 'SHA256', 'EMAIL_ADDRESS', 'MALWARE',
                               'REGISTRY_KEY', 'CVE', 'SHA1', 'BITCOIN_ADDRESS']:
                    continue
                indicator_type = str(key)
                if indicator_type not in ioc_details.keys():
                    ioc_details[indicator_type] = list()
                    ioc_details[indicator_type].append(indicator[indicator_type])
                else:
                    ioc_details[indicator_type].append(indicator[indicator_type])

    # Overriding "indicators" key in response
    data["indicators"] = ioc_details
    return data


def _get_ctx_result(result, provides):

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["param"] = param

    if summary:
        ctx_result["summary"] = summary

    if not data:
        ctx_result["data"] = dict()
        return ctx_result

    if provides == "get report":
        data = _parse_data(data[0])

    if provides == "submit report":
        data = data[0]

    ctx_result["data"] = data

    return ctx_result


# Function to provide custom view for all actions
def display_action_details(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    # If action is get report
    if provides == "get report":
        return_page = "trustar_display_report_details.html"
    # If action is submit report
    elif provides == "submit report":
        return_page = "trustar_submitted_report_details.html"
    # If action is any of the hunt actions
    else:
        return_page = "trustar_display_report_ids.html"

    return return_page
