[comment]: # "Auto-generated SOAR connector documentation"
# TruSTAR

Publisher: Splunk  
Connector Version: 3\.1\.7  
Product Vendor: TruSTAR Technology  
Product Name: TruSTAR  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This App integrates with TruSTAR to provide various hunting and reporting actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2017-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
**Note:** Input to all hunt actions must be greater than 3 characters.

All the hunt actions' endpoints will be deprecated in the next major release of the TruSTAR and the
corresponding actions will be removed from the integration.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a TruSTAR asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | URL \(eg\: https\://api\.trustar\.co\)
**config\_enclave\_ids** |  optional  | string | \(,\) separated TruSTAR\-generated enclave IDs
**client\_id** |  required  | string | OAuth client ID
**client\_secret** |  required  | password | OAuth client secret key
**max\_wait\_time** |  optional  | numeric | Maximum time to wait after too many requests error \(in seconds\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity  
[hunt ioc](#action-hunt-ioc) - Get report IDs associated with an IOC  
[hunt ip](#action-hunt-ip) - Get report IDs associated with an IP/CIDR  
[hunt url](#action-hunt-url) - Get report IDs associated with a URL  
[hunt file](#action-hunt-file) - Get report IDs associated with a file  
[hunt email](#action-hunt-email) - Get report IDs associated with an email address  
[hunt cve](#action-hunt-cve) - Get report IDs associated with a CVE \(Common Vulnerability and Exposure\) number  
[hunt malware](#action-hunt-malware) - Get report IDs associated with a malware indicator  
[hunt registry key](#action-hunt-registry-key) - Get report IDs associated with a registry key  
[hunt bitcoin address](#action-hunt-bitcoin-address) - Get report IDs associated with a bitcoin address  
[get report](#action-get-report) - Get report details  
[copy report](#action-copy-report) - Copy a report to another enclave  
[move report](#action-move-report) - Move a report to another enclave  
[delete report](#action-delete-report) - Delete a report  
[submit report](#action-submit-report) - Submit report to TruSTAR  
[update report](#action-update-report) - Update a TruSTAR report   
[safelist ioc](#action-safelist-ioc) - Add IOCs to the whitelist  
[unsafelist ioc](#action-unsafelist-ioc) - Remove IOC from the whitelist  
[list enclaves](#action-list-enclaves) - List all the accessible enclaves in TruSTAR  
[list emails](#action-list-emails) - Get a list of emails submitted to Phishing Triage  
[list indicators](#action-list-indicators) - Get a list of indictors found in phishing submissions  
[indicator reputation](#action-indicator-reputation) - Get enriched information of the indictor  
[get indicator summary](#action-get-indicator-summary) - Get the structured summaries about indicators  
[get indicator metadata](#action-get-indicator-metadata) - Get the metadata associated with the indicator  
[triage email](#action-triage-email) - Change the status of an email submission  
[parse entities](#action-parse-entities) - Find all of the entity terms that can be found from applying extraction rules on a chunk of text  
[list observable types](#action-list-observable-types) - Get all valid observable types  

## action: 'test connectivity'
Validate credentials provided for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'hunt ioc'
Get report IDs associated with an IOC

Type: **investigate**  
Read only: **True**

Input to <b>ioc</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | IOC to hunt | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ioc | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt ip'
Get report IDs associated with an IP/CIDR

Type: **investigate**  
Read only: **True**

Input to <b>ip</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP/CIDR to hunt | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt url'
Get report IDs associated with a URL

Type: **investigate**  
Read only: **True**

Input to <b>url</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to hunt | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt file'
Get report IDs associated with a file

Type: **investigate**  
Read only: **True**

Input to <b>file</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file** |  required  | File to hunt | string |  `hash`  `file name`  `md5`  `sha1`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file | string |  `hash`  `file name`  `md5`  `sha1`  `sha256` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt email'
Get report IDs associated with an email address

Type: **investigate**  
Read only: **True**

Input to <b>email</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email address to hunt | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt cve'
Get report IDs associated with a CVE \(Common Vulnerability and Exposure\) number

Type: **investigate**  
Read only: **True**

Input to <b>cve\_number</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve\_number** |  required  | CVE \(Common Vulnerability and Exposure\) number to hunt | string |  `trustar cve number` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cve\_number | string |  `trustar cve number` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt malware'
Get report IDs associated with a malware indicator

Type: **investigate**  
Read only: **True**

Input to <b>malware</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**malware** |  required  | Malware to hunt | string |  `trustar malware` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.malware | string |  `trustar malware` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt registry key'
Get report IDs associated with a registry key

Type: **investigate**  
Read only: **True**

Input to <b>registry\_key</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**registry\_key** |  required  | Registry key to hunt | string |  `trustar registry key` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.registry\_key | string |  `trustar registry key` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt bitcoin address'
Get report IDs associated with a bitcoin address

Type: **investigate**  
Read only: **True**

Input to <b>bitcoin\_address</b> parameter must be greater than 3 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**bitcoin\_address** |  required  | Bitcoin address to hunt | string |  `trustar bitcoin address` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.bitcoin\_address | string |  `trustar bitcoin address` 
action\_result\.data\.\*\.report\_id | string |  `trustar report id` 
action\_result\.summary\.total\_correlated\_reports | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Get report details

Type: **investigate**  
Read only: **True**

The <b>id\_type</b> parameter can be one of the following values\:<ul><li>internal</li><li>external</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_id** |  required  | Report ID | string |  `trustar report id`  `trustar tracking id` 
**id\_type** |  optional  | ID type \(Default\: internal\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id\_type | string | 
action\_result\.parameter\.report\_id | string |  `trustar report id`  `trustar tracking id` 
action\_result\.data\.\*\.correlationCount | numeric | 
action\_result\.data\.\*\.created | numeric | 
action\_result\.data\.\*\.distributionType | string | 
action\_result\.data\.\*\.enclaves\.\*\.id | string | 
action\_result\.data\.\*\.enclaves\.\*\.name | string | 
action\_result\.data\.\*\.externalTrackingId | string |  `trustar tracking id` 
action\_result\.data\.\*\.externalUrl | string | 
action\_result\.data\.\*\.id | string |  `trustar report id` 
action\_result\.data\.\*\.indicators\.\*\.BITCOIN\_ADDRESS | string |  `trustar bitcoin address` 
action\_result\.data\.\*\.indicators\.\*\.CIDR\_BLOCK | string |  `ip` 
action\_result\.data\.\*\.indicators\.\*\.CVE | string |  `trustar cve number` 
action\_result\.data\.\*\.indicators\.\*\.EMAIL\_ADDRESS | string |  `email` 
action\_result\.data\.\*\.indicators\.\*\.IP | string |  `ip` 
action\_result\.data\.\*\.indicators\.\*\.MALWARE | string |  `trustar malware` 
action\_result\.data\.\*\.indicators\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.indicators\.\*\.REGISTRY\_KEY | string |  `trustar registry key` 
action\_result\.data\.\*\.indicators\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.indicators\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.indicators\.\*\.SOFTWARE | string |  `file name` 
action\_result\.data\.\*\.indicators\.\*\.URL | string |  `url` 
action\_result\.data\.\*\.indicatorsCount | numeric | 
action\_result\.data\.\*\.mimeType | string | 
action\_result\.data\.\*\.reportBody | string | 
action\_result\.data\.\*\.sector\.label | string | 
action\_result\.data\.\*\.sector\.name | string | 
action\_result\.data\.\*\.submissionStatus | string | 
action\_result\.data\.\*\.submitSource | string | 
action\_result\.data\.\*\.timeBegan | numeric | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.updated | numeric | 
action\_result\.summary\.extracted\_indicators\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'copy report'
Copy a report to another enclave

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_id** |  required  | Report ID | string |  `trustar report id`  `trustar tracking id` 
**destination\_enclave** |  required  | ID of destination enclave | string |  `trustar enclave id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.destination\_enclave | string |  `trustar enclave id` 
action\_result\.parameter\.report\_id | string |  `trustar report id`  `trustar tracking id` 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.submissionVersion | numeric | 
action\_result\.summary\.new\_report\_id | string |  `trustar report id`  `trustar tracking id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'move report'
Move a report to another enclave

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_id** |  required  | Report ID | string |  `trustar report id`  `trustar tracking id` 
**destination\_enclave** |  required  | ID of destination enclave | string |  `trustar enclave id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.destination\_enclave | string |  `trustar enclave id` 
action\_result\.parameter\.report\_id | string |  `trustar report id`  `trustar tracking id` 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.submissionVersion | numeric | 
action\_result\.summary\.new\_report\_id | string |  `trustar report id`  `trustar tracking id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete report'
Delete a report

Type: **correct**  
Read only: **False**

The <b>id\_type</b> parameter can be one of the following values\:<ul><li>internal</li><li>external</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_id** |  required  | Report ID | string |  `trustar report id`  `trustar tracking id` 
**id\_type** |  optional  | ID type \(Default\: internal\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id\_type | string | 
action\_result\.parameter\.report\_id | string |  `trustar report id`  `trustar tracking id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'submit report'
Submit report to TruSTAR

Type: **generic**  
Read only: **False**

If <b>distribution\_type</b> selected is <b>ENCLAVE</b>, <b>enclave\_ids</b> must be provided from the ones configured in the asset\. If <b>time\_discovered</b> is not provided, the action will consider current system time\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_title** |  required  | Report title | string | 
**report\_body** |  required  | Text content of report | string | 
**distribution\_type** |  required  | Distribution type | string | 
**enclave\_ids** |  optional  | \(,\) separated TruSTAR\-generated enclave IDs | string |  `trustar enclave id` 
**time\_discovered** |  optional  | ISO\-8601 formatted incident time with timezone \(e\.g\. "2016\-09\-22T11\:38\:35\+00\:00"\) | string | 
**external\_tracking\_id** |  optional  | External tracking ID \(possibly a JIRA ticket number\) | string |  `trustar tracking id` 
**external\_url** |  optional  | External URL \(possibly a link to a JIRA ticket\) | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.distribution\_type | string | 
action\_result\.parameter\.enclave\_ids | string |  `trustar enclave id` 
action\_result\.parameter\.external\_tracking\_id | string |  `trustar tracking id` 
action\_result\.parameter\.external\_url | string |  `url` 
action\_result\.parameter\.report\_body | string | 
action\_result\.parameter\.report\_title | string | 
action\_result\.parameter\.time\_discovered | string | 
action\_result\.data\.\*\.reportId | string |  `trustar report id` 
action\_result\.data\.\*\.reportIndicators\.BITCOIN\_ADDRESS | string |  `trustar bitcoin address` 
action\_result\.data\.\*\.reportIndicators\.CIDR\_BLOCK | string |  `ip` 
action\_result\.data\.\*\.reportIndicators\.CVE | string |  `trustar cve number` 
action\_result\.data\.\*\.reportIndicators\.EMAIL\_ADDRESS | string |  `email` 
action\_result\.data\.\*\.reportIndicators\.IP | string |  `ip` 
action\_result\.data\.\*\.reportIndicators\.MALWARE | string |  `trustar malware` 
action\_result\.data\.\*\.reportIndicators\.MD5 | string |  `md5` 
action\_result\.data\.\*\.reportIndicators\.REGISTRY\_KEY | string |  `trustar registry key` 
action\_result\.data\.\*\.reportIndicators\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.reportIndicators\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.reportIndicators\.SOFTWARE | string |  `file name` 
action\_result\.data\.\*\.reportIndicators\.URL | string |  `url` 
action\_result\.summary\.new\_report\_id | string |  `trustar report id`  `trustar tracking id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update report'
Update a TruSTAR report 

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_id** |  required  | Report ID | string |  `trustar report id`  `trustar tracking id` 
**id\_type** |  optional  | ID type \(Default\: internal\) | string | 
**report\_title** |  optional  | Report title | string | 
**report\_body** |  optional  | Text content of report | string | 
**enclave\_ids** |  optional  | \(,\) separated TruSTAR\-generated enclave IDs | string |  `trustar enclave id` 
**time\_discovered** |  optional  | ISO\-8601 formatted incident time with timezone \(e\.g\. "2016\-09\-22T11\:38\:35\+00\:00"\) | string | 
**external\_tracking\_id** |  optional  | External tracking ID \(possibly a JIRA ticket number\) | string |  `trustar tracking id` 
**external\_url** |  optional  | External URL \(possibly a link to a JIRA ticket\) | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.enclave\_ids | string |  `trustar enclave id` 
action\_result\.parameter\.external\_tracking\_id | string |  `trustar tracking id` 
action\_result\.parameter\.external\_url | string |  `url` 
action\_result\.parameter\.id\_type | string | 
action\_result\.parameter\.report\_body | string | 
action\_result\.parameter\.report\_id | string |  `trustar report id`  `trustar tracking id` 
action\_result\.parameter\.report\_title | string | 
action\_result\.parameter\.time\_discovered | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'safelist ioc'
Add IOCs to the whitelist

Type: **correct**  
Read only: **False**

Input to <b>ioc</b> parameter must be greater than 3 characters\. The type of the IOC will be determined by TruSTAR\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | A comma\-separated list of IOCs to add to the whitelist | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ioc | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
action\_result\.data\.\*\.guid | string | 
action\_result\.data\.\*\.indicatorType | string | 
action\_result\.data\.\*\.value | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
action\_result\.summary\.num\_whitelisted\_iocs | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unsafelist ioc'
Remove IOC from the whitelist

Type: **contain**  
Read only: **False**

Input to <b>ioc</b> parameter must be greater than 3 characters\. The type of the IOC will be determined by TruSTAR\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | IOC to remove from the whitelist | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
**ioc\_type** |  required  | The type of the given IOC | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ioc | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
action\_result\.parameter\.ioc\_type | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list enclaves'
List all the accessible enclaves in TruSTAR

Type: **investigate**  
Read only: **True**

This action will only list the enclaves that the user has access to\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.create | boolean | 
action\_result\.data\.\*\.id | string |  `trustar enclave id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.read | boolean | 
action\_result\.data\.\*\.templateName | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update | boolean | 
action\_result\.data\.\*\.workflowSupported | boolean | 
action\_result\.summary\.num\_enclaves | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list emails'
Get a list of emails submitted to Phishing Triage

Type: **investigate**  
Read only: **True**

If the parameters <b>start\_time</b> and <b>end\_time</b> are not provided, then last 24 hours data will be fetched\. The <b>start\_time</b> of the time window must be within 1 month from the current time\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | ISO\-8601 formatted start time with timezone \(e\.g\. "2021\-06\-01T11\:38\:35\+00\:00"\) within the last month | string | 
**end\_time** |  optional  | ISO\-8601 formatted end time with timezone \(e\.g\. "2021\-06\-23T17\:24\:42\+00\:00"\) | string | 
**priority\_event\_score** |  optional  | A comma\-separated list of priority scores to filter submissions by\. Valid options\: \-1, 0, 1, 2, 3 | string | 
**status** |  optional  | A comma\-separated list of statuses to filter submissions by\. Valid options\: CONFIRMED, IGNORED, UNRESOLVED | string | 
**enclave\_ids** |  optional  | A comma\-separated list of enclave IDs to filter submissions by | string |  `trustar enclave id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.enclave\_ids | string |  `trustar enclave id` 
action\_result\.parameter\.end\_time | string | 
action\_result\.parameter\.priority\_event\_score | string | 
action\_result\.parameter\.start\_time | string | 
action\_result\.parameter\.status | string | 
action\_result\.data\.\*\.context\.\*\.indicatorType | string | 
action\_result\.data\.\*\.context\.\*\.indicatorValue | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
action\_result\.data\.\*\.context\.\*\.normalizedIndicatorScore | numeric | 
action\_result\.data\.\*\.context\.\*\.originalIndicatorScore\.name | string | 
action\_result\.data\.\*\.context\.\*\.originalIndicatorScore\.value | string | 
action\_result\.data\.\*\.context\.\*\.sourceKey | string | 
action\_result\.data\.\*\.priorityEventScore | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.submissionId | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.summary\.emails\_found | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list indicators'
Get a list of indictors found in phishing submissions

Type: **investigate**  
Read only: **True**

If the parameters <b>start\_time</b> and <b>end\_time</b> are not provided, then last 24 hours data will be fetched\. The <b>start\_time</b> of the time window must be within 1 month from the current time\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Start time in UTC \(YYYY\-MM\-DD HH\:MM\:SS\) | string | 
**end\_time** |  optional  | End time in UTC \(YYYY\-MM\-DD HH\:MM\:SS\) | string | 
**indicator\_score** |  optional  | A comma\-separated list of indicator scores to filter indicators by | string | 
**priority\_event\_score** |  optional  | A comma\-separated list of priority scores to filter indicators by | string | 
**status** |  optional  | A comma\-separated list of statuses to filter indicators by | string | 
**enclave\_ids** |  optional  | A comma\-separated list of enclave IDs to filter indicators by | string |  `trustar enclave id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.enclave\_ids | string |  `trustar enclave id` 
action\_result\.parameter\.end\_time | string | 
action\_result\.parameter\.indicator\_score | string | 
action\_result\.parameter\.priority\_event\_score | string | 
action\_result\.parameter\.start\_time | string | 
action\_result\.parameter\.start\_time | string | 
action\_result\.parameter\.status | string | 
action\_result\.data\.\*\.indicatorType | string | 
action\_result\.data\.\*\.normalizedIndicatorScore | numeric | 
action\_result\.data\.\*\.originalIndicatorScore\.name | string | 
action\_result\.data\.\*\.originalIndicatorScore\.value | string | 
action\_result\.data\.\*\.sourceKey | string | 
action\_result\.data\.\*\.value | string |  `url` 
action\_result\.summary\.indicators\_found | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'indicator reputation'
Get enriched information of the indictor

Type: **investigate**  
Read only: **True**

If the value of the action parameter <b>enclave ids</b> is kept empty, then the value will be considered the same as a configuration parameter's value\. If the configuration parameter is also kept empty, nothing will be passed in <b>enclave ids</b> parameter, and data from all the enclaves for which the user has READ access will be fetched\.<br/>This action will fetch the data for the past one year\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator\_value** |  required  | The indicator value to search for | string | 
**indicator\_types** |  optional  | A comma\-separated list of indicator types to filter indicators by | string | 
**enclave\_ids** |  optional  | A comma\-separated list of enclave IDs to filter indicators by | string |  `trustar enclave id` 
**limit** |  optional  | Specify the number of indicators to return \(default value = 10000\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.enclave\_ids | string |  `trustar enclave id` 
action\_result\.parameter\.indicator\_types | string | 
action\_result\.parameter\.indicator\_value | string | 
action\_result\.data\.\*\.attributes\.\*\.type | string | 
action\_result\.data\.\*\.attributes\.\*\.value | string | 
action\_result\.data\.\*\.created | numeric | 
action\_result\.data\.\*\.enclaveGuid | string |  `trustar enclave id` 
action\_result\.data\.\*\.guid | string | 
action\_result\.data\.\*\.observable\.type | string | 
action\_result\.data\.\*\.observable\.value | string |  `ip`  `url` 
action\_result\.data\.\*\.priorityScore | string | 
action\_result\.data\.\*\.processedAt | numeric | 
action\_result\.data\.\*\.safelisted | boolean | 
action\_result\.data\.\*\.scoreContexts\.\*\.enclaveGuid | string |  `trustar enclave id` 
action\_result\.data\.\*\.scoreContexts\.\*\.enclaveName | string | 
action\_result\.data\.\*\.scoreContexts\.\*\.normalizedScore | numeric | 
action\_result\.data\.\*\.scoreContexts\.\*\.sourceName | string | 
action\_result\.data\.\*\.scoreContexts\.\*\.weight | numeric | 
action\_result\.data\.\*\.submissionTags\.\* | string | 
action\_result\.data\.\*\.updated | numeric | 
action\_result\.data\.\*\.userTags\.\* | string | 
action\_result\.data\.\*\.validFrom | numeric | 
action\_result\.data\.\*\.validUntil | numeric | 
action\_result\.data\.\*\.workflowGuid | string | 
action\_result\.summary\.indicators\_found | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.parameter\.limit | numeric |   

## action: 'get indicator summary'
Get the structured summaries about indicators

Type: **investigate**  
Read only: **True**

If the value of the action parameter <b>enclave ids</b> is kept empty, then the value will be considered the same as a configuration parameter's value\. If the configuration parameter is also kept empty, nothing will be passed in <b>enclave ids</b> parameter, and data from all the enclaves for which the user has READ access will be fetched\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator\_values** |  required  | A comma\-separated list of indicator values to query | string | 
**enclave\_ids** |  optional  | A comma\-separated list of enclave IDs to filter indicators by | string |  `trustar enclave id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.enclave\_ids | string |  `trustar enclave id` 
action\_result\.parameter\.indicator\_values | string | 
action\_result\.data\.\*\.attributes\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.\*\.value | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.enclaveId | string |  `trustar enclave id` 
action\_result\.data\.\*\.reportId | string |  `trustar report id` 
action\_result\.data\.\*\.score\.name | string | 
action\_result\.data\.\*\.score\.value | string | 
action\_result\.data\.\*\.severityLevel | numeric | 
action\_result\.data\.\*\.source\.key | string | 
action\_result\.data\.\*\.source\.name | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.value | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
action\_result\.summary\.indicator\_summaries | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get indicator metadata'
Get the metadata associated with the indicator

Type: **investigate**  
Read only: **True**

<p>If the <b>indicator types</b> field is used, it must be present for all entries in the <b>indicator values</b> parameter\. i\.e\. The length of <b>indicator types</b> and <b>indicator values</b> parameters should be the same\.</p><p>If the value of the action parameter <b>enclave ids</b> is kept empty, then the value will be considered the same as a configuration parameter's value\. If the configuration parameter is also kept empty, nothing will be passed in <b>enclave ids</b> parameter, and data from all the enclaves for which the user has READ access will be fetched\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator\_types** |  optional  | A comma\-separated list of indicator types | string | 
**indicator\_values** |  required  | A comma\-separated list of indicator values to query | string | 
**enclave\_ids** |  optional  | A comma\-separated list of enclave IDs to filter indicators by | string |  `trustar enclave id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.enclave\_ids | string |  `trustar enclave id` 
action\_result\.parameter\.indicator\_types | string | 
action\_result\.parameter\.indicator\_values | string | 
action\_result\.data\.\*\.correlationCount | numeric | 
action\_result\.data\.\*\.enclaveIds\.\* | string |  `trustar enclave id` 
action\_result\.data\.\*\.firstSeen | numeric | 
action\_result\.data\.\*\.guid | string | 
action\_result\.data\.\*\.indicatorType | string | 
action\_result\.data\.\*\.lastSeen | numeric | 
action\_result\.data\.\*\.noteCount | numeric | 
action\_result\.data\.\*\.priorityLevel | string | 
action\_result\.data\.\*\.sightings | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.tags\.\*\.enclaveId | string |  `trustar enclave id` 
action\_result\.data\.\*\.tags\.\*\.guid | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.value | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
action\_result\.summary\.indicator\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'triage email'
Change the status of an email submission

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**submission\_id** |  required  | ID of email submission to triage | string |  `trustar email submission id` 
**status** |  required  | Status to set the email submission to | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.status | string | 
action\_result\.parameter\.submission\_id | string |  `trustar email submission id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'parse entities'
Find all of the entity terms that can be found from applying extraction rules on a chunk of text

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**payload** |  required  | Text using which all the entities will be extracted | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.payload | string | 
action\_result\.data\.\*\.entity | string |  `ip`  `url`  `md5`  `hash`  `sha1`  `email`  `domain`  `sha256`  `file name`  `trustar malware`  `trustar cve number`  `trustar registry key`  `trustar bitcoin address` 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.entity\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list observable types'
Get all valid observable types

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.observable\_type | string | 
action\_result\.summary\.observable\_type\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 