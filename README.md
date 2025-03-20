# TruSTAR

Publisher: Splunk \
Connector Version: 3.2.0 \
Product Vendor: TruSTAR Technology \
Product Name: TruSTAR \
Minimum Product Version: 6.1.0

This App integrates with TruSTAR to provide various hunting and reporting actions

**Note:** Input to all hunt actions must be greater than 3 characters.

All the hunt actions' endpoints will be deprecated in the next major release of the TruSTAR and the
corresponding actions will be removed from the integration.

### Configuration variables

This table lists the configuration variables required to operate TruSTAR. These variables are specified when configuring a TruSTAR asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** | required | string | URL (eg: https://api.trustar.co) |
**config_enclave_ids** | optional | string | (,) separated TruSTAR-generated enclave IDs |
**client_id** | required | string | OAuth client ID |
**client_secret** | required | password | OAuth client secret key |
**max_wait_time** | optional | numeric | Maximum time to wait after too many requests error (in seconds) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity \
[hunt ioc](#action-hunt-ioc) - Get report IDs associated with an IOC \
[hunt ip](#action-hunt-ip) - Get report IDs associated with an IP/CIDR \
[hunt url](#action-hunt-url) - Get report IDs associated with a URL \
[hunt file](#action-hunt-file) - Get report IDs associated with a file \
[hunt email](#action-hunt-email) - Get report IDs associated with an email address \
[hunt cve](#action-hunt-cve) - Get report IDs associated with a CVE (Common Vulnerability and Exposure) number \
[hunt malware](#action-hunt-malware) - Get report IDs associated with a malware indicator \
[hunt registry key](#action-hunt-registry-key) - Get report IDs associated with a registry key \
[hunt bitcoin address](#action-hunt-bitcoin-address) - Get report IDs associated with a bitcoin address \
[get report](#action-get-report) - Get report details \
[copy report](#action-copy-report) - Copy a report to another enclave \
[move report](#action-move-report) - Move a report to another enclave \
[delete report](#action-delete-report) - Delete a report \
[submit report](#action-submit-report) - Submit report to TruSTAR \
[update report](#action-update-report) - Update a TruSTAR report \
[safelist ioc](#action-safelist-ioc) - Add IOCs to the whitelist \
[unsafelist ioc](#action-unsafelist-ioc) - Remove IOC from the whitelist \
[list enclaves](#action-list-enclaves) - List all the accessible enclaves in TruSTAR \
[list emails](#action-list-emails) - Get a list of emails submitted to Phishing Triage \
[list indicators](#action-list-indicators) - Get a list of indictors found in phishing submissions \
[indicator reputation](#action-indicator-reputation) - Get enriched information of the indictor \
[get indicator summary](#action-get-indicator-summary) - Get the structured summaries about indicators \
[get indicator metadata](#action-get-indicator-metadata) - Get the metadata associated with the indicator \
[triage email](#action-triage-email) - Change the status of an email submission \
[parse entities](#action-parse-entities) - Find all of the entity terms that can be found from applying extraction rules on a chunk of text \
[list observable types](#action-list-observable-types) - Get all valid observable types

## action: 'test connectivity'

Validate credentials provided for connectivity

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'hunt ioc'

Get report IDs associated with an IOC

Type: **investigate** \
Read only: **True**

Input to <b>ioc</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | IOC to hunt | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ioc | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` | 2.3.5.1 |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | 100 |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt ip'

Get report IDs associated with an IP/CIDR

Type: **investigate** \
Read only: **True**

Input to <b>ip</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP/CIDR to hunt | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` | 5.33.33.33 |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt url'

Get report IDs associated with a URL

Type: **investigate** \
Read only: **True**

Input to <b>url</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to hunt | string | `url` `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.url | string | `url` `domain` | http://test.abc.xyz |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt file'

Get report IDs associated with a file

Type: **investigate** \
Read only: **True**

Input to <b>file</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file** | required | File to hunt | string | `hash` `file name` `md5` `sha1` `sha256` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.file | string | `hash` `file name` `md5` `sha1` `sha256` | 9f86d08188cc5d659a2feaa0c55ad015d3bf4f1d5a0b822cd15d6c15b0f00a08 |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt email'

Get report IDs associated with an email address

Type: **investigate** \
Read only: **True**

Input to <b>email</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** | required | Email address to hunt | string | `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.email | string | `email` | test@abc.xyz |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt cve'

Get report IDs associated with a CVE (Common Vulnerability and Exposure) number

Type: **investigate** \
Read only: **True**

Input to <b>cve_number</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve_number** | required | CVE (Common Vulnerability and Exposure) number to hunt | string | `trustar cve number` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.cve_number | string | `trustar cve number` | CVE-2013-5760 |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt malware'

Get report IDs associated with a malware indicator

Type: **investigate** \
Read only: **True**

Input to <b>malware</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**malware** | required | Malware to hunt | string | `trustar malware` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.malware | string | `trustar malware` | rig |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt registry key'

Get report IDs associated with a registry key

Type: **investigate** \
Read only: **True**

Input to <b>registry_key</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**registry_key** | required | Registry key to hunt | string | `trustar registry key` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.registry_key | string | `trustar registry key` | HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{824634b0-a93b-4db6-9214-722d56a79c97} |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt bitcoin address'

Get report IDs associated with a bitcoin address

Type: **investigate** \
Read only: **True**

Input to <b>bitcoin_address</b> parameter must be greater than 3 characters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**bitcoin_address** | required | Bitcoin address to hunt | string | `trustar bitcoin address` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.bitcoin_address | string | `trustar bitcoin address` | 1QAb9S6EmycqjzdWDc1yqWzr6jJLC8sLi |
action_result.data.\*.report_id | string | `trustar report id` | a9cd779a-75fc-4118-91d4-a428a63ffa23 |
action_result.summary.total_correlated_reports | numeric | | |
action_result.message | string | | Total correlated reports: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Get report details

Type: **investigate** \
Read only: **True**

The <b>id_type</b> parameter can be one of the following values:<ul><li>internal</li><li>external</li></ul>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | Report ID | string | `trustar report id` `trustar tracking id` |
**id_type** | optional | ID type (Default: internal) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id_type | string | | internal |
action_result.parameter.report_id | string | `trustar report id` `trustar tracking id` | 74e38d07-aec4-4dc5-8a07-c71a6c2b1046 |
action_result.data.\*.correlationCount | numeric | | 28 |
action_result.data.\*.created | numeric | | 1494777610386 |
action_result.data.\*.distributionType | string | | COMMUNITY |
action_result.data.\*.enclaves.\*.id | string | | |
action_result.data.\*.enclaves.\*.name | string | | |
action_result.data.\*.externalTrackingId | string | `trustar tracking id` | |
action_result.data.\*.externalUrl | string | | http://abc.test.xyz |
action_result.data.\*.id | string | `trustar report id` | 74e38d07-aec4-4dc5-8a07-c71a6c2b1046 |
action_result.data.\*.indicators.\*.BITCOIN_ADDRESS | string | `trustar bitcoin address` | 13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94 |
action_result.data.\*.indicators.\*.CIDR_BLOCK | string | `ip` | |
action_result.data.\*.indicators.\*.CVE | string | `trustar cve number` | cve-2017-0147 |
action_result.data.\*.indicators.\*.EMAIL_ADDRESS | string | `email` | |
action_result.data.\*.indicators.\*.IP | string | `ip` | |
action_result.data.\*.indicators.\*.MALWARE | string | `trustar malware` | |
action_result.data.\*.indicators.\*.MD5 | string | `md5` | 8dd63adb68ef053e044a5a2f46e0d2cd |
action_result.data.\*.indicators.\*.REGISTRY_KEY | string | `trustar registry key` | |
action_result.data.\*.indicators.\*.SHA1 | string | `sha1` | |
action_result.data.\*.indicators.\*.SHA256 | string | `sha256` | |
action_result.data.\*.indicators.\*.SOFTWARE | string | `file name` | |
action_result.data.\*.indicators.\*.URL | string | `url` | cwwnhwhlz52maqm7.onion |
action_result.data.\*.indicatorsCount | numeric | | 26 |
action_result.data.\*.mimeType | string | | application/text |
action_result.data.\*.reportBody | string | | |
action_result.data.\*.sector.label | string | | Information Technology |
action_result.data.\*.sector.name | string | | information-technology |
action_result.data.\*.submissionStatus | string | | PROCESSED |
action_result.data.\*.submitSource | string | | STATION |
action_result.data.\*.timeBegan | numeric | | 1494763210352 |
action_result.data.\*.title | string | | WannaCry ransomware used in widespread attacks |
action_result.data.\*.updated | numeric | | 1494777610386 |
action_result.summary.extracted_indicators_count | numeric | | 26 |
action_result.message | string | | Extracted indicators count: 26 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'copy report'

Copy a report to another enclave

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | Report ID | string | `trustar report id` `trustar tracking id` |
**destination_enclave** | required | ID of destination enclave | string | `trustar enclave id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.destination_enclave | string | `trustar enclave id` | e8369a18-3e93-49b7-a485-847c8f38b577 |
action_result.parameter.report_id | string | `trustar report id` `trustar tracking id` | 3b312275-e32a-41a2-886c-28966a726274 |
action_result.data.\*.id | string | | c272142e-9824-4ea7-afcf-8824a6dfe3a3 |
action_result.data.\*.submissionVersion | numeric | | 1 |
action_result.summary.new_report_id | string | `trustar report id` `trustar tracking id` | c272142e-9824-4ea7-afcf-8824a6dfe3a3 |
action_result.message | string | | New report id: c272142e-9824-4ea7-afcf-8824a6dfe3a3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'move report'

Move a report to another enclave

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | Report ID | string | `trustar report id` `trustar tracking id` |
**destination_enclave** | required | ID of destination enclave | string | `trustar enclave id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.destination_enclave | string | `trustar enclave id` | a8764f8c-7a0a-456b-8d08-dbc614b56ae3 |
action_result.parameter.report_id | string | `trustar report id` `trustar tracking id` | 3b312275-e32a-41a2-886c-28966a726274 |
action_result.data.\*.id | string | | 3b312275-e32a-41a2-886c-28966a726274 |
action_result.data.\*.submissionVersion | numeric | | 3 |
action_result.summary.new_report_id | string | `trustar report id` `trustar tracking id` | 3b312275-e32a-41a2-886c-28966a726274 |
action_result.message | string | | New report id: 3b312275-e32a-41a2-886c-28966a726274 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete report'

Delete a report

Type: **correct** \
Read only: **False**

The <b>id_type</b> parameter can be one of the following values:<ul><li>internal</li><li>external</li></ul>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | Report ID | string | `trustar report id` `trustar tracking id` |
**id_type** | optional | ID type (Default: internal) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id_type | string | | internal |
action_result.parameter.report_id | string | `trustar report id` `trustar tracking id` | f2a976e9-0e1a-4657-8de0-c8ad6b1fefd9 |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Successfully deleted report |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'submit report'

Submit report to TruSTAR

Type: **generic** \
Read only: **False**

If <b>distribution_type</b> selected is <b>ENCLAVE</b>, <b>enclave_ids</b> must be provided from the ones configured in the asset. If <b>time_discovered</b> is not provided, the action will consider current system time.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_title** | required | Report title | string | |
**report_body** | required | Text content of report | string | |
**distribution_type** | required | Distribution type | string | |
**enclave_ids** | optional | (,) separated TruSTAR-generated enclave IDs | string | `trustar enclave id` |
**time_discovered** | optional | ISO-8601 formatted incident time with timezone (e.g. "2016-09-22T11:38:35+00:00") | string | |
**external_tracking_id** | optional | External tracking ID (possibly a JIRA ticket number) | string | `trustar tracking id` |
**external_url** | optional | External URL (possibly a link to a JIRA ticket) | string | `url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.distribution_type | string | | ENCLAVE |
action_result.parameter.enclave_ids | string | `trustar enclave id` | 3e9d0a3c-c8cc-47ef-af92-a4c6908b3c9c |
action_result.parameter.external_tracking_id | string | `trustar tracking id` | c272142e-9824-4ea7-afcf-8824a6dfe3a3 |
action_result.parameter.external_url | string | `url` | http://test.abc.xyz |
action_result.parameter.report_body | string | | Test Body |
action_result.parameter.report_title | string | | Uploaded Title |
action_result.parameter.time_discovered | string | | 2016-05-12T12:05:20+00:00 |
action_result.data.\*.reportId | string | `trustar report id` | |
action_result.data.\*.reportIndicators.BITCOIN_ADDRESS | string | `trustar bitcoin address` | |
action_result.data.\*.reportIndicators.CIDR_BLOCK | string | `ip` | |
action_result.data.\*.reportIndicators.CVE | string | `trustar cve number` | |
action_result.data.\*.reportIndicators.EMAIL_ADDRESS | string | `email` | |
action_result.data.\*.reportIndicators.IP | string | `ip` | |
action_result.data.\*.reportIndicators.MALWARE | string | `trustar malware` | |
action_result.data.\*.reportIndicators.MD5 | string | `md5` | |
action_result.data.\*.reportIndicators.REGISTRY_KEY | string | `trustar registry key` | |
action_result.data.\*.reportIndicators.SHA1 | string | `sha1` | |
action_result.data.\*.reportIndicators.SHA256 | string | `sha256` | |
action_result.data.\*.reportIndicators.SOFTWARE | string | `file name` | |
action_result.data.\*.reportIndicators.URL | string | `url` | |
action_result.summary.new_report_id | string | `trustar report id` `trustar tracking id` | c272142e-9824-4ea7-afcf-8824a6dfe3a3 |
action_result.message | string | | New report id: 3b312275-e32a-41a2-886c-28966a726274 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update report'

Update a TruSTAR report

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | Report ID | string | `trustar report id` `trustar tracking id` |
**id_type** | optional | ID type (Default: internal) | string | |
**report_title** | optional | Report title | string | |
**report_body** | optional | Text content of report | string | |
**enclave_ids** | optional | (,) separated TruSTAR-generated enclave IDs | string | `trustar enclave id` |
**time_discovered** | optional | ISO-8601 formatted incident time with timezone (e.g. "2016-09-22T11:38:35+00:00") | string | |
**external_tracking_id** | optional | External tracking ID (possibly a JIRA ticket number) | string | `trustar tracking id` |
**external_url** | optional | External URL (possibly a link to a JIRA ticket) | string | `url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.enclave_ids | string | `trustar enclave id` | 3e9d0a3c-c8cc-47ef-af92-a4c6908b3c9c |
action_result.parameter.external_tracking_id | string | `trustar tracking id` | c272142e-9824-4ea7-afcf-8824a6dfe3a3 |
action_result.parameter.external_url | string | `url` | http://test.abc.xyz |
action_result.parameter.id_type | string | | internal |
action_result.parameter.report_body | string | | Test Body |
action_result.parameter.report_id | string | `trustar report id` `trustar tracking id` | cd6dcce9-8d72-4288-a139-ffb1d0795317 |
action_result.parameter.report_title | string | | Updated Title |
action_result.parameter.time_discovered | string | | 2016-05-12T12:05:20+00:00 |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Successfully updated report |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'safelist ioc'

Add IOCs to the whitelist

Type: **correct** \
Read only: **False**

Input to <b>ioc</b> parameter must be greater than 3 characters. The type of the IOC will be determined by TruSTAR.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | A comma-separated list of IOCs to add to the whitelist | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ioc | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` | 2.3.5.1 |
action_result.data.\*.guid | string | | IP|2.3.5.1 |
action_result.data.\*.indicatorType | string | | IP |
action_result.data.\*.value | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` | 2.3.5.1 |
action_result.summary.num_whitelisted_iocs | numeric | | 1 |
action_result.message | string | | Num whitelisted iocs: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unsafelist ioc'

Remove IOC from the whitelist

Type: **contain** \
Read only: **False**

Input to <b>ioc</b> parameter must be greater than 3 characters. The type of the IOC will be determined by TruSTAR.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | IOC to remove from the whitelist | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` |
**ioc_type** | required | The type of the given IOC | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ioc | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` | 2.3.5.1 |
action_result.parameter.ioc_type | string | | IP |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | IOC successfully remove from whitelist |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list enclaves'

List all the accessible enclaves in TruSTAR

Type: **investigate** \
Read only: **True**

This action will only list the enclaves that the user has access to.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.create | boolean | | False |
action_result.data.\*.id | string | `trustar enclave id` | e7f4907a-2909-48e8-9c2d-74ffc4b22e8c |
action_result.data.\*.name | string | | EU-CERT |
action_result.data.\*.read | boolean | | True |
action_result.data.\*.templateName | string | | Open Source |
action_result.data.\*.type | string | | OPEN |
action_result.data.\*.update | boolean | | False |
action_result.data.\*.workflowSupported | boolean | | False |
action_result.summary.num_enclaves | numeric | | 16 |
action_result.message | string | | Num enclaves: 16 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list emails'

Get a list of emails submitted to Phishing Triage

Type: **investigate** \
Read only: **True**

If the parameters <b>start_time</b> and <b>end_time</b> are not provided, then last 24 hours data will be fetched. The <b>start_time</b> of the time window must be within 1 month from the current time.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | ISO-8601 formatted start time with timezone (e.g. "2021-06-01T11:38:35+00:00") within the last month | string | |
**end_time** | optional | ISO-8601 formatted end time with timezone (e.g. "2021-06-23T17:24:42+00:00") | string | |
**priority_event_score** | optional | A comma-separated list of priority scores to filter submissions by. Valid options: -1, 0, 1, 2, 3 | string | |
**status** | optional | A comma-separated list of statuses to filter submissions by. Valid options: CONFIRMED, IGNORED, UNRESOLVED | string | |
**enclave_ids** | optional | A comma-separated list of enclave IDs to filter submissions by | string | `trustar enclave id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.enclave_ids | string | `trustar enclave id` | 3e9d0a3c-c8cc-47ef-af92-a4c6908b3c9c |
action_result.parameter.end_time | string | | 2021-06-09T08:35:17+01:00 |
action_result.parameter.priority_event_score | string | | -1 |
action_result.parameter.start_time | string | | 2021-05-10T08:35:17+01:00 |
action_result.parameter.status | string | | CONFIRMED,IGNORED |
action_result.data.\*.context.\*.indicatorType | string | | IP |
action_result.data.\*.context.\*.indicatorValue | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` | 167.248.133.82 |
action_result.data.\*.context.\*.normalizedIndicatorScore | numeric | | 3 |
action_result.data.\*.context.\*.originalIndicatorScore.name | string | | Malicious Score |
action_result.data.\*.context.\*.originalIndicatorScore.value | string | | HIGH |
action_result.data.\*.context.\*.sourceKey | string | | Test Source |
action_result.data.\*.priorityEventScore | numeric | | -1 |
action_result.data.\*.status | string | | phishing/confirmed |
action_result.data.\*.submissionId | string | | 1a491fb4-1565-4a81-821d-1c6bfad3710c |
action_result.data.\*.title | string | | [SPAM] Testing Phishing Triage |
action_result.summary.emails_found | numeric | | 3 |
action_result.message | string | | Emails found: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list indicators'

Get a list of indictors found in phishing submissions

Type: **investigate** \
Read only: **True**

If the parameters <b>start_time</b> and <b>end_time</b> are not provided, then last 24 hours data will be fetched. The <b>start_time</b> of the time window must be within 1 month from the current time.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start time in UTC (YYYY-MM-DD HH:MM:SS) | string | |
**end_time** | optional | End time in UTC (YYYY-MM-DD HH:MM:SS) | string | |
**indicator_score** | optional | A comma-separated list of indicator scores to filter indicators by | string | |
**priority_event_score** | optional | A comma-separated list of priority scores to filter indicators by | string | |
**status** | optional | A comma-separated list of statuses to filter indicators by | string | |
**enclave_ids** | optional | A comma-separated list of enclave IDs to filter indicators by | string | `trustar enclave id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.enclave_ids | string | `trustar enclave id` | 3e9d0a3c-c8cc-47ef-af92-a4c6908b3c9c |
action_result.parameter.end_time | string | | 2021-06-09T08:35:17+01:00 |
action_result.parameter.indicator_score | string | | 2 |
action_result.parameter.priority_event_score | string | | -1 |
action_result.parameter.start_time | string | | 2021-05-09T08:35:17+01:00 |
action_result.parameter.start_time | string | | 2021-05-10T08:35:17+01:00 |
action_result.parameter.status | string | | CONFIRMED,IGNORED |
action_result.data.\*.indicatorType | string | | URL |
action_result.data.\*.normalizedIndicatorScore | numeric | | 2 |
action_result.data.\*.originalIndicatorScore.name | string | | VirusTotal AV Percent |
action_result.data.\*.originalIndicatorScore.value | string | | 55.74 |
action_result.data.\*.sourceKey | string | | url_haus |
action_result.data.\*.value | string | `url` | http://115.49.30.239:39787/i |
action_result.summary.indicators_found | numeric | | 1 |
action_result.message | string | | Indicators found: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'indicator reputation'

Get enriched information of the indictor

Type: **investigate** \
Read only: **True**

If the value of the action parameter <b>enclave ids</b> is kept empty, then the value will be considered the same as a configuration parameter's value. If the configuration parameter is also kept empty, nothing will be passed in <b>enclave ids</b> parameter, and data from all the enclaves for which the user has READ access will be fetched.<br/>This action will fetch the data for the past one year.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_value** | required | The indicator value to search for | string | |
**indicator_types** | optional | A comma-separated list of indicator types to filter indicators by | string | |
**enclave_ids** | optional | A comma-separated list of enclave IDs to filter indicators by | string | `trustar enclave id` |
**limit** | optional | Specify the number of indicators to return (default value = 10000) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.enclave_ids | string | `trustar enclave id` | 5285b7ec-3582-4d4a-a967-82d3d4f98bb4 |
action_result.parameter.indicator_types | string | | URL |
action_result.parameter.indicator_value | string | | 5.3 |
action_result.parameter.limit | numeric | | 222 |
action_result.data.\*.attributes.\*.type | string | | THREAT_ACTOR MALWARE |
action_result.data.\*.attributes.\*.value | string | | SOMENAME_2 MYDOOM |
action_result.data.\*.created | numeric | | 1634119674000 1639175447562 |
action_result.data.\*.enclaveGuid | string | `trustar enclave id` | 5285b7ec-3582-4d4a-a967-82d3d4f98bb4 ebf45cf7-b029-45cb-a21a-661aa3a8e501 |
action_result.data.\*.guid | string | | d9d0b3df-b15e-307e-b8f1-9780b79c505f 009aeb62-73b6-33ba-8c10-2dda659e1c74 |
action_result.data.\*.observable.type | string | | IP4 URL |
action_result.data.\*.observable.value | string | `ip` `url` | 5.39.39.39 |
action_result.data.\*.priorityScore | string | | BENIGN HIGH |
action_result.data.\*.processedAt | numeric | | 1634195463512 1646951151171 |
action_result.data.\*.safelisted | boolean | | False |
action_result.data.\*.scoreContexts.\*.enclaveGuid | string | `trustar enclave id` | d1b45847-28c0-4426-98eb-dcabde9c044f ca97e725-7e0e-4866-950c-7dbaf0bea6aa |
action_result.data.\*.scoreContexts.\*.enclaveName | string | | BOTS 2021 Intel Feed (Stxd Indicators) Netlab 360 DGA |
action_result.data.\*.scoreContexts.\*.normalizedScore | numeric | | 0 3 |
action_result.data.\*.scoreContexts.\*.sourceName | string | | BOTS 2021 Intel Feed (Stxd Indicators) Netlab 360 DGA |
action_result.data.\*.scoreContexts.\*.weight | numeric | | 1 |
action_result.data.\*.submissionTags.\* | string | | ph_tag_3 |
action_result.data.\*.updated | numeric | | 1634119674000 1646950945820 |
action_result.data.\*.userTags.\* | string | | |
action_result.data.\*.validFrom | numeric | | 1635724800000 0 |
action_result.data.\*.validUntil | numeric | | 1635811199000 1893456000000 |
action_result.data.\*.workflowGuid | string | | a9cbe8c6-85fb-4a57-b78f-77a29f3d4fe3 1dd26bf5-ecb7-4c8d-8961-7c75c5f866ad |
action_result.summary.indicators_found | numeric | | 3 222 |
action_result.message | string | | Indicators found: 3 Indicators found: 222 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get indicator summary'

Get the structured summaries about indicators

Type: **investigate** \
Read only: **True**

If the value of the action parameter <b>enclave ids</b> is kept empty, then the value will be considered the same as a configuration parameter's value. If the configuration parameter is also kept empty, nothing will be passed in <b>enclave ids</b> parameter, and data from all the enclaves for which the user has READ access will be fetched.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_values** | required | A comma-separated list of indicator values to query | string | |
**enclave_ids** | optional | A comma-separated list of enclave IDs to filter indicators by | string | `trustar enclave id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.enclave_ids | string | `trustar enclave id` | d1b45847-28c0-4426-98eb-dcabde9c044f |
action_result.parameter.indicator_values | string | | 5.33.33.33, 5.35.35.35 |
action_result.data.\*.attributes.\*.name | string | | THREAT_ACTOR |
action_result.data.\*.attributes.\*.value | string | | Test |
action_result.data.\*.description | string | | IP4 |
action_result.data.\*.enclaveId | string | `trustar enclave id` | d1b45847-28c0-4426-98eb-dcabde9c044f |
action_result.data.\*.reportId | string | `trustar report id` | 9b13f51c-0a14-4fca-b290-14464c1eff31 |
action_result.data.\*.score.name | string | | Malicious Score |
action_result.data.\*.score.value | string | | BENIGN |
action_result.data.\*.severityLevel | numeric | | 0 |
action_result.data.\*.source.key | string | | BOTS 2021 Intel Feed (Stxd Indicators) |
action_result.data.\*.source.name | string | | BOTS 2021 Intel Feed (Stxd Indicators) |
action_result.data.\*.type | string | | IP |
action_result.data.\*.value | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` | 5.33.33.33 |
action_result.summary.indicator_summaries | numeric | | 3 |
action_result.message | string | | Indicator summaries: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get indicator metadata'

Get the metadata associated with the indicator

Type: **investigate** \
Read only: **True**

<p>If the <b>indicator types</b> field is used, it must be present for all entries in the <b>indicator values</b> parameter. i.e. The length of <b>indicator types</b> and <b>indicator values</b> parameters should be the same.</p><p>If the value of the action parameter <b>enclave ids</b> is kept empty, then the value will be considered the same as a configuration parameter's value. If the configuration parameter is also kept empty, nothing will be passed in <b>enclave ids</b> parameter, and data from all the enclaves for which the user has READ access will be fetched.</p>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_types** | optional | A comma-separated list of indicator types | string | |
**indicator_values** | required | A comma-separated list of indicator values to query | string | |
**enclave_ids** | optional | A comma-separated list of enclave IDs to filter indicators by | string | `trustar enclave id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.enclave_ids | string | `trustar enclave id` | d1b45847-28c0-4426-98eb-dcabde9c044f |
action_result.parameter.indicator_types | string | | IP4 |
action_result.parameter.indicator_values | string | | 5.35.35.35 |
action_result.data.\*.correlationCount | numeric | | 0 |
action_result.data.\*.enclaveIds.\* | string | `trustar enclave id` | d1b45847-28c0-4426-98eb-dcabde9c044f |
action_result.data.\*.firstSeen | numeric | | 1633952402250 |
action_result.data.\*.guid | string | | IP|5.35.35.35 |
action_result.data.\*.indicatorType | string | | IP |
action_result.data.\*.lastSeen | numeric | | 1633952402250 |
action_result.data.\*.noteCount | numeric | | 0 |
action_result.data.\*.priorityLevel | string | | NOT_FOUND |
action_result.data.\*.sightings | numeric | | 1 |
action_result.data.\*.source | string | | |
action_result.data.\*.tags.\*.enclaveId | string | `trustar enclave id` | d1b45847-28c0-4426-98eb-dcabde9c044f |
action_result.data.\*.tags.\*.guid | string | | 5285b7ec-3582-4d4a-a967-82d3d4f98bb4 |
action_result.data.\*.tags.\*.name | string | | test_phishing |
action_result.data.\*.value | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` | 5.35.35.35 |
action_result.summary.indicator_count | numeric | | 1 |
action_result.message | string | | Indicator count: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'triage email'

Change the status of an email submission

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**submission_id** | required | ID of email submission to triage | string | `trustar email submission id` |
**status** | required | Status to set the email submission to | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.status | string | | CONFIRMED |
action_result.parameter.submission_id | string | `trustar email submission id` | 1a491fb4-1565-4a81-821d-1c6bfad3710c |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Email successfully triaged |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'parse entities'

Find all of the entity terms that can be found from applying extraction rules on a chunk of text

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**payload** | required | Text using which all the entities will be extracted | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.payload | string | | Address: 5.33.55.65, Name: hello.in, Visit: www.hello.com |
action_result.data.\*.entity | string | `ip` `url` `md5` `hash` `sha1` `email` `domain` `sha256` `file name` `trustar malware` `trustar cve number` `trustar registry key` `trustar bitcoin address` | hello.com |
action_result.data.\*.type | string | | DOMAIN |
action_result.summary.entity_count | numeric | | 4 |
action_result.message | string | | Entity count: 4 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list observable types'

Get all valid observable types

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.observable_type | string | | BITCOIN_ADDRESS |
action_result.summary.observable_type_count | numeric | | 14 |
action_result.message | string | | Observable type count: 14 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
