# SOCRadar Incidents

Publisher: SOCRadar <br>
Connector Version: 1.0.0 <br>
Product Vendor: SOCRadar <br>
Product Name: SOCRadar Platform <br>
Minimum Product Version: 6.3.0

Ingest SOCRadar threat intelligence incidents (API v4) into Splunk SOAR with deduplication, rate-limit handling, and state-based polling.

### Configuration variables

This table lists the configuration variables required to operate SOCRadar Incidents. These variables are specified when configuring a SOCRadar Platform asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**socradar_company_id** | required | string | SOCRadar Company ID |
**socradar_api_key** | required | password | SOCRadar API Key |
**verify_server_cert** | optional | boolean | Verify server certificate |
**first_run_max_incidents** | optional | numeric | Maximum incidents to ingest on first run (last 10 hours) |
**max_incidents_per_poll** | optional | numeric | Maximum incidents per scheduled poll cycle |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied credentials <br>
[on poll](#action-on-poll) - Ingest SOCRadar incidents with deduplication and state management <br>
[get incident](#action-get-incident) - Retrieve a single SOCRadar incident by alarm ID <br>
[update status](#action-update-status) - Update the status of a SOCRadar alarm <br>
[change severity](#action-change-severity) - Change the severity of a SOCRadar alarm

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied credentials

Type: **test** <br>
Read only: **True**

Tests connectivity to the SOCRadar API v4 endpoint using the configured API key and company ID.

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Ingest SOCRadar incidents with deduplication and state management

Type: **ingest** <br>
Read only: **True**

Fetches incidents from SOCRadar API v4 with pagination, rate-limit handling, and state-based deduplication. Creates containers and artifacts for new or status-changed incidents. First run fetches the last 10 hours; subsequent runs resume from the last checkpoint.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_count** | optional | Maximum number of containers to create (used by Poll Now) | numeric | |
**start_time** | optional | Start time for ingestion (epoch) | numeric | |
**end_time** | optional | End time for ingestion (epoch) | numeric | |
**artifact_count** | optional | Maximum number of artifacts per container | numeric | |

#### Action Output

No Output

## action: 'get incident'

Retrieve a single SOCRadar incident by alarm ID

Type: **investigate** <br>
Read only: **True**

Fetches detailed information for a specific SOCRadar alarm using the incidents API v4.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** | required | SOCRadar Alarm ID to retrieve | string | `socradar incident id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.alarm_id | numeric | `socradar incident id` | |
action_result.data.\*.alarm_risk_level | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.alarm_main_type | string | | |
action_result.data.\*.alarm_sub_type | string | | |
action_result.data.\*.alarm_generic_title | string | | |
action_result.data.\*.date | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.alarm_id | numeric | `socradar incident id` | |
summary.status | string | | |
summary.alarm_risk_level | string | | |
action_result.parameter.incident_id | string | `socradar incident id` | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'update status'

Update the status of a SOCRadar alarm

Type: **generic** <br>
Read only: **False**

Changes the status of a SOCRadar alarm using the API v4 status change endpoint. Supports statuses: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE, ON_HOLD, PENDING_INFO, LEGAL_REVIEW, VENDOR_ASSESSMENT, DUPLICATE, PROCESSED_INTERNALLY, MITIGATED, NOT_APPLICABLE.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** | required | SOCRadar Alarm ID | string | `socradar incident id` |
**status** | required | New status for the alarm | string | |
**comment** | optional | Optional comment for the status change | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.message | string | | |
action_result.data.\*.alarm_id | string | `socradar incident id` | |
action_result.data.\*.new_status | string | | |
summary.status_changed | boolean | | |
action_result.parameter.incident_id | string | `socradar incident id` | |
action_result.parameter.status | string | | |
action_result.parameter.comment | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'change severity'

Change the severity of a SOCRadar alarm

Type: **generic** <br>
Read only: **False**

Changes the severity of a SOCRadar alarm using the API v4 severity change endpoint. Supported values: Low, Medium, High.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** | required | SOCRadar Alarm ID | string | `socradar incident id` |
**severity** | required | New severity for the alarm | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.message | string | | |
action_result.data.\*.alarm_id | string | `socradar incident id` | |
action_result.data.\*.new_severity | string | | |
summary.severity_changed | boolean | | |
action_result.parameter.incident_id | string | `socradar incident id` | |
action_result.parameter.severity | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
