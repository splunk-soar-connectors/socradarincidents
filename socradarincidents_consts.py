# File: socradarincidents_consts.py
#
# Copyright (c) 2025-2026 SOCRadar
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Constants for the SOCRadar Incidents Splunk SOAR connector.

All hardcoded values, API paths, mappings, and messages live here.
The connector imports from this module — no inline magic strings.
"""

# ──────────────────────────────────────────────────────────────────
#  App metadata
# ──────────────────────────────────────────────────────────────────
APP_VERSION = "1.0.0"
APP_NAME = "SOCRadar Incidents"

# ──────────────────────────────────────────────────────────────────
#  API configuration
# ──────────────────────────────────────────────────────────────────
SOCRADAR_API_BASE_URL = "https://platform.socradar.com/api"
API_HEADER_KEY = "API-Key"
API_CONTENT_TYPE = "application/json"
API_TIMEOUT_SECONDS = 60

# ──────────────────────────────────────────────────────────────────
#  Endpoint templates  (use .format(company_id=…) )
# ──────────────────────────────────────────────────────────────────
INCIDENTS_ENDPOINT = "/company/{company_id}/incidents/v4"
STATUS_CHANGE_ENDPOINT = "/company/{company_id}/alarms/status/change"
SEVERITY_CHANGE_ENDPOINT = "/company/{company_id}/alarm/severity"

# ──────────────────────────────────────────────────────────────────
#  Pagination & polling defaults
# ──────────────────────────────────────────────────────────────────
DEFAULT_PAGE_SIZE = 100
MAX_PAGES_PER_POLL = 50

FIRST_RUN_LOOKBACK_HOURS = 10
FIRST_RUN_MAX_INCIDENTS = 1000
DEFAULT_MAX_INCIDENTS_PER_POLL = 100

# ──────────────────────────────────────────────────────────────────
#  Rate-limit response headers
# ──────────────────────────────────────────────────────────────────
HEADER_RATELIMIT_LIMIT = "x-ratelimit-limit"
HEADER_RATELIMIT_REMAINING = "x-ratelimit-remaining"
HEADER_RATELIMIT_RESET = "x-ratelimit-reset"
HEADER_RETRY_AFTER = "retry-after"

DEFAULT_RATE_LIMIT_WAIT = 2  # seconds when retry-after header missing
PROACTIVE_THROTTLE_WAIT = 1  # seconds when remaining <= 1

# ──────────────────────────────────────────────────────────────────
#  Politeness
# ──────────────────────────────────────────────────────────────────
PAGE_DELAY_SECONDS = 2  # sleep between paginated requests
PERIODIC_STATE_SAVE_INTERVAL = 50  # save state every N new containers

# ──────────────────────────────────────────────────────────────────
#  State management keys
# ──────────────────────────────────────────────────────────────────
STATE_ALARM_STATUS = "alarm_status"
STATE_LAST_POLL_TIME = "last_poll_time"
STATE_LAST_UPDATED = "last_updated"
STATE_MAX_ALARMS = 10000

# ──────────────────────────────────────────────────────────────────
#  Field limits
# ──────────────────────────────────────────────────────────────────
MAX_TEXT_LENGTH = 5000

# ──────────────────────────────────────────────────────────────────
#  Severity mapping   (alarm_risk_level → SOAR severity)
#
#  API v4 returns  alarm_risk_level: "HIGH" | "MEDIUM" | "LOW" | "CRITICAL"
#  SOAR expects  "critical" | "high" | "medium" | "low"
# ──────────────────────────────────────────────────────────────────
SOCRADAR_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
}
DEFAULT_SEVERITY = "medium"

# ──────────────────────────────────────────────────────────────────
#  Status integer mapping  (for update-alarm-status endpoint)
#
#  API expects integer:  {"alarm_ids": [...], "status": 1}
#  API returns string:   "status": "INVESTIGATING"
# ──────────────────────────────────────────────────────────────────
SOCRADAR_STATUS_INT_MAP = {
    "OPEN": 0,
    "INVESTIGATING": 1,
    "RESOLVED": 2,
    "PENDING_INFO": 4,
    "LEGAL_REVIEW": 5,
    "VENDOR_ASSESSMENT": 6,
    "FALSE_POSITIVE": 9,
    "ON_HOLD": 10,
    "DUPLICATE": 10,
    "PROCESSED_INTERNALLY": 11,
    "MITIGATED": 12,
    "NOT_APPLICABLE": 13,
}

# ──────────────────────────────────────────────────────────────────
#  Severity values for change-severity endpoint (title case)
# ──────────────────────────────────────────────────────────────────
SEVERITY_API_VALUES = ["Low", "Medium", "High"]

# ──────────────────────────────────────────────────────────────────
#  IOC entity key types  (from alarm_related_entities)
#
#  Each entry: {"key": "<type>", "value": "<ioc_value>"}
# ──────────────────────────────────────────────────────────────────
IOC_KEY_IP = "ip"
IOC_KEY_URL = "url"
IOC_KEY_DOMAIN = "domain"
IOC_KEY_HASH = "hash"
IOC_KEY_EMAIL = "email"

IOC_ENTITY_KEYS = {IOC_KEY_IP, IOC_KEY_URL, IOC_KEY_DOMAIN, IOC_KEY_HASH, IOC_KEY_EMAIL}

# ──────────────────────────────────────────────────────────────────
#  CEF field mapping   (CEF field name → contains type list)
# ──────────────────────────────────────────────────────────────────
CEF_MAP_IP = ("sourceAddress", ["ip"])
CEF_MAP_URL = ("requestURL", ["url"])
CEF_MAP_DOMAIN = ("destinationDnsDomain", ["domain"])
CEF_MAP_HASH = ("fileHashSha256", ["hash", "sha256"])
CEF_MAP_EMAIL = ("emailAddress", ["email"])

# ──────────────────────────────────────────────────────────────────
#  Content fields that may contain IOCs  (from incident.content dict)
# ──────────────────────────────────────────────────────────────────
CONTENT_URL_FIELDS = ("source_link", "post_url", "permalink", "repository_url")
CONTENT_DOMAIN_FIELDS = ("domain", "domains")

# ──────────────────────────────────────────────────────────────────
#  SOCRadar platform deep-link template
# ──────────────────────────────────────────────────────────────────
SOCRADAR_PLATFORM_BASE = "https://platform.socradar.com"
SOCRADAR_ALARM_URL_TEMPLATE = "{base}/app/company/{company_id}/alarm-management?tab=approved&alarmId={alarm_id}"

# ──────────────────────────────────────────────────────────────────
#  Error messages
# ──────────────────────────────────────────────────────────────────
ERR_MISSING_CONFIG = "Missing company_id or api_key in asset configuration"
ERR_UNAUTHORIZED = "Unauthorized (401). Please check your API key and company ID."
ERR_RATE_LIMIT = "Rate limit exceeded (429). Retrying after {seconds}s."
ERR_CONNECTION = "Connection error: {error}"
ERR_TIMEOUT = "Request timed out after {timeout}s"
ERR_INVALID_JSON = "Invalid JSON in API response"
ERR_HTTP = "HTTP {status_code}: {detail}"
ERR_SAVE_CONTAINER = "Failed to save container: {message}"
ERR_SAVE_ARTIFACT = "Failed to save artifact: {message}"
ERR_ON_POLL = "Error during on_poll (page {page}): {error}"
ERR_GET_INCIDENT = "Error fetching incident {incident_id}: {error}"
ERR_CONNECTIVITY = "Connectivity test failed: {error}"
ERR_INVALID_STATUS = "Invalid status: {status}. Valid values: OPEN, INVESTIGATING, RESOLVED, PENDING_INFO, LEGAL_REVIEW, VENDOR_ASSESSMENT, FALSE_POSITIVE, ON_HOLD, DUPLICATE, PROCESSED_INTERNALLY, MITIGATED, NOT_APPLICABLE"
ERR_INVALID_SEVERITY = "Invalid severity: {severity}. Valid values: Low, Medium, High"
ERR_INVALID_INT = "Please provide a valid integer value for '{}'"
ERR_NON_POSITIVE_INT = "Please provide a non-zero positive integer value for '{}'"

# ──────────────────────────────────────────────────────────────────
#  Success messages
# ──────────────────────────────────────────────────────────────────
MSG_TEST_PASS = "Successfully connected to SOCRadar API"
MSG_TEST_FAIL = "Test Connectivity Failed"
MSG_INGESTION_COMPLETE = "Ingestion complete: {new} new/updated, {skipped} skipped"
MSG_STATUS_UPDATED = "Successfully updated alarm {alarm_id} status to {status}"
MSG_SEVERITY_UPDATED = "Successfully updated alarm {alarm_id} severity to {severity}"

# ──────────────────────────────────────────────────────────────────
#  Progress messages
# ──────────────────────────────────────────────────────────────────
MSG_INIT = "Connector initialized successfully"
MSG_TESTING = "Testing SOCRadar API connectivity..."
MSG_POLL_START = "Starting ingestion — time window {start} to {end}"
MSG_POLL_FIRST_RUN = "First run: fetching last {hours} hours (max {max} incidents)"
MSG_POLL_SCHEDULED = "Scheduled poll: from last checkpoint to now (max {max} incidents)"
MSG_POLL_NOW = "Poll Now: fetching up to {count} incidents"
MSG_FETCHING_PAGE = "Fetching page {current} — {count} incidents processed so far"
MSG_RATE_LIMIT_WAIT = "Rate limit hit. Waiting {seconds}s before retry."
MSG_PROACTIVE_THROTTLE = "Rate limit remaining: {remaining}. Throttling {seconds}s."
MSG_STATUS_CHANGE = "Status change for alarm {alarm_id}: {old} -> {new}"
MSG_LAST_PAGE = "Last page reached (received {count} < {page_size})."
MSG_PER_POLL_CAP = "Per-poll cap reached: {max} incidents"
MSG_STATE_TRIMMED = "State trimmed to {max} most recent alarms"
