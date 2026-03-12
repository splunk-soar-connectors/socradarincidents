# File: socradarincidents_connector.py
#
# Copyright (c) 2025-2026 SOCRadar
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
#
# ------------------------------------------------------------------
# SOCRadar Incidents v4 Connector for Splunk SOAR
# ------------------------------------------------------------------
#
# Pulls incidents from SOCRadar API v4 and creates Splunk SOAR
# containers + artifacts with proper severity, IOC extraction,
# and state-based deduplication.
#
# Actions:
#   test_connectivity  — validate credentials
#   on_poll            — ingest incidents (scheduled + Poll Now)
#   get_incident       — fetch a single incident by alarm_id
#   update_status      — change alarm status in SOCRadar
#   change_severity    — change alarm severity in SOCRadar
#
# Dedup:
#   Container SDI = alarm_id
#   Artifact  SDI = alarm_id-status
#   State tracks alarm_id -> last_seen_status
# ------------------------------------------------------------------

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from socradarincidents_consts import (
    API_CONTENT_TYPE,
    API_HEADER_KEY,
    API_TIMEOUT_SECONDS,
    CEF_MAP_DOMAIN,
    CEF_MAP_EMAIL,
    CEF_MAP_HASH,
    CEF_MAP_IP,
    CEF_MAP_URL,
    CONTENT_DOMAIN_FIELDS,
    CONTENT_URL_FIELDS,
    DEFAULT_MAX_INCIDENTS_PER_POLL,
    DEFAULT_PAGE_SIZE,
    DEFAULT_RATE_LIMIT_WAIT,
    DEFAULT_SEVERITY,
    ERR_CONNECTION,
    ERR_CONNECTIVITY,
    ERR_HTTP,
    ERR_INVALID_INT,
    ERR_INVALID_JSON,
    ERR_INVALID_SEVERITY,
    ERR_INVALID_STATUS,
    ERR_MISSING_CONFIG,
    ERR_NON_POSITIVE_INT,
    ERR_RATE_LIMIT,
    ERR_SAVE_CONTAINER,
    ERR_TIMEOUT,
    ERR_UNAUTHORIZED,
    FIRST_RUN_LOOKBACK_HOURS,
    FIRST_RUN_MAX_INCIDENTS,
    HEADER_RATELIMIT_REMAINING,
    HEADER_RETRY_AFTER,
    INCIDENTS_ENDPOINT,
    IOC_ENTITY_KEYS,
    IOC_KEY_DOMAIN,
    IOC_KEY_EMAIL,
    IOC_KEY_HASH,
    IOC_KEY_IP,
    IOC_KEY_URL,
    MAX_PAGES_PER_POLL,
    MAX_TEXT_LENGTH,
    MSG_FETCHING_PAGE,
    MSG_INGESTION_COMPLETE,
    MSG_INIT,
    MSG_LAST_PAGE,
    MSG_PER_POLL_CAP,
    MSG_POLL_FIRST_RUN,
    MSG_POLL_NOW,
    MSG_POLL_SCHEDULED,
    MSG_POLL_START,
    MSG_PROACTIVE_THROTTLE,
    MSG_RATE_LIMIT_WAIT,
    MSG_SEVERITY_UPDATED,
    MSG_STATE_TRIMMED,
    MSG_STATUS_CHANGE,
    MSG_STATUS_UPDATED,
    MSG_TEST_FAIL,
    MSG_TEST_PASS,
    MSG_TESTING,
    PAGE_DELAY_SECONDS,
    PERIODIC_STATE_SAVE_INTERVAL,
    PROACTIVE_THROTTLE_WAIT,
    SEVERITY_API_VALUES,
    SEVERITY_CHANGE_ENDPOINT,
    SOCRADAR_ALARM_URL_TEMPLATE,
    SOCRADAR_API_BASE_URL,
    SOCRADAR_PLATFORM_BASE,
    SOCRADAR_SEVERITY_MAP,
    SOCRADAR_STATUS_INT_MAP,
    STATE_ALARM_STATUS,
    STATE_LAST_POLL_TIME,
    STATE_LAST_UPDATED,
    STATE_MAX_ALARMS,
    STATUS_CHANGE_ENDPOINT,
)


class SocradarincidentsConnector(BaseConnector):
    """SOCRadar Incidents v4 connector for Splunk SOAR."""

    def __init__(self):
        super().__init__()

        self._base_url: str | None = None
        self._api_key: str | None = None
        self._company_id: str | None = None
        self._verify: bool = False
        self._state: dict[str, Any] = {}

        # Config values populated in initialize()
        self._first_run_max_incidents: int = FIRST_RUN_MAX_INCIDENTS
        self._max_incidents_per_poll: int = DEFAULT_MAX_INCIDENTS_PER_POLL
        self._container_label: str = "events"

    # ──────────────────────────────────────────────────────────────
    #  Validation helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _validate_integer(action_result, parameter, key, allow_zero=False):
        """Validate that a parameter is a valid integer."""
        try:
            parameter = int(parameter)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, ERR_INVALID_INT.format(key)), None
        if not allow_zero and parameter <= 0:
            return action_result.set_status(phantom.APP_ERROR, ERR_NON_POSITIVE_INT.format(key)), None
        return phantom.APP_SUCCESS, parameter

    # ──────────────────────────────────────────────────────────────
    #  Lifecycle
    # ──────────────────────────────────────────────────────────────

    def initialize(self):
        config = self.get_config()

        self._base_url = SOCRADAR_API_BASE_URL
        self._company_id = config.get("socradar_company_id")
        self._api_key = config.get("socradar_api_key")
        self._verify = config.get("verify_server_cert", False)

        # Validate numeric config parameters
        first_run_raw = config.get("first_run_max_incidents", FIRST_RUN_MAX_INCIDENTS) or FIRST_RUN_MAX_INCIDENTS
        try:
            self._first_run_max_incidents = int(first_run_raw)
            if self._first_run_max_incidents <= 0:
                self._first_run_max_incidents = FIRST_RUN_MAX_INCIDENTS
        except (ValueError, TypeError):
            self._first_run_max_incidents = FIRST_RUN_MAX_INCIDENTS

        per_poll_raw = config.get("max_incidents_per_poll", DEFAULT_MAX_INCIDENTS_PER_POLL) or DEFAULT_MAX_INCIDENTS_PER_POLL
        try:
            self._max_incidents_per_poll = int(per_poll_raw)
            if self._max_incidents_per_poll <= 0:
                self._max_incidents_per_poll = DEFAULT_MAX_INCIDENTS_PER_POLL
        except (ValueError, TypeError):
            self._max_incidents_per_poll = DEFAULT_MAX_INCIDENTS_PER_POLL

        self._container_label = config.get("ingest", {}).get("container_label", "events")

        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self._state = {}

        self.save_progress(MSG_INIT)
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        self.debug_print("action_id", action_id)

        action_map = {
            "test_connectivity": self._handle_test_connectivity,
            "on_poll": self._handle_on_poll,
            "get_incident": self._handle_get_incident,
            "update_status": self._handle_update_status,
            "change_severity": self._handle_change_severity,
        }

        handler = action_map.get(action_id)
        if handler:
            return handler(param)

        return self.set_status(phantom.APP_ERROR, f"Unsupported action: {action_id}")

    # ──────────────────────────────────────────────────────────────
    #  REST helper
    # ──────────────────────────────────────────────────────────────

    def _make_rest_call(
        self,
        endpoint: str,
        action_result: ActionResult,
        headers: dict | None = None,
        params: dict | None = None,
        data: dict | None = None,
        json_body: dict | None = None,
        method: str = "get",
    ) -> tuple[bool, dict | None, requests.Response | None]:
        """
        Central REST call helper.

        Returns:
            (status, response_data, raw_response)
            status: phantom.APP_SUCCESS or phantom.APP_ERROR
            response_data: parsed JSON dict (or None on error)
            raw_response: requests.Response object (for header inspection)
        """
        url = f"{self._base_url}{endpoint}"

        # Build default headers with API-Key auth
        req_headers = {
            API_HEADER_KEY: self._api_key,
            "Content-Type": API_CONTENT_TYPE,
        }
        if headers:
            req_headers.update(headers)

        self.debug_print(f"REST {method.upper()} {url}")

        try:
            request_func = getattr(requests, method.lower())

            response = request_func(
                url,
                headers=req_headers,
                params=params,
                data=data,
                json=json_body,
                verify=self._verify,
                timeout=API_TIMEOUT_SECONDS,
            )

            # Debug data for SOAR UI
            if hasattr(action_result, "add_debug_data"):
                action_result.add_debug_data({"r_status_code": response.status_code})
                action_result.add_debug_data({"r_text": response.text[:2000] if response.text else ""})
                action_result.add_debug_data({"r_headers": dict(response.headers)})

            # Parse JSON
            resp_data = None
            if response.text:
                try:
                    resp_data = response.json()
                except ValueError:
                    if 200 <= response.status_code < 300:
                        return phantom.APP_SUCCESS, {}, response
                    action_result.set_status(phantom.APP_ERROR, ERR_INVALID_JSON)
                    return phantom.APP_ERROR, None, response

            # Success range
            if 200 <= response.status_code < 300:
                return phantom.APP_SUCCESS, resp_data or {}, response

            # 401
            if response.status_code == 401:
                action_result.set_status(phantom.APP_ERROR, ERR_UNAUTHORIZED)
                return phantom.APP_ERROR, None, response

            # 429 rate limit
            if response.status_code == 429:
                retry_after = self._get_retry_wait(response)
                msg = ERR_RATE_LIMIT.format(seconds=retry_after)
                action_result.set_status(phantom.APP_ERROR, msg)
                return phantom.APP_ERROR, None, response

            # Other errors
            detail = ""
            if resp_data and isinstance(resp_data, dict):
                detail = resp_data.get("message", response.text[:300] if response.text else "")
            else:
                detail = response.text[:300] if response.text else ""
            action_result.set_status(phantom.APP_ERROR, ERR_HTTP.format(status_code=response.status_code, detail=detail))
            return phantom.APP_ERROR, None, response

        except requests.exceptions.Timeout:
            action_result.set_status(phantom.APP_ERROR, ERR_TIMEOUT.format(timeout=API_TIMEOUT_SECONDS))
            return phantom.APP_ERROR, None, None

        except requests.exceptions.ConnectionError as e:
            action_result.set_status(phantom.APP_ERROR, ERR_CONNECTION.format(error=str(e)))
            return phantom.APP_ERROR, None, None

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, ERR_CONNECTIVITY.format(error=str(e)))
            return phantom.APP_ERROR, None, None

    # ──────────────────────────────────────────────────────────────
    #  Rate-limit helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _get_retry_wait(response: requests.Response | None) -> int:
        """Read retry-after header, fall back to default."""
        if response is None:
            return DEFAULT_RATE_LIMIT_WAIT
        try:
            return int(response.headers.get(HEADER_RETRY_AFTER, DEFAULT_RATE_LIMIT_WAIT))
        except (ValueError, TypeError):
            return DEFAULT_RATE_LIMIT_WAIT

    @staticmethod
    def _should_throttle(response: requests.Response | None) -> bool:
        """Return True if ratelimit-remaining is dangerously low."""
        if response is None:
            return False
        try:
            remaining = int(response.headers.get(HEADER_RATELIMIT_REMAINING, 99))
            return remaining <= 1
        except (ValueError, TypeError):
            return False

    # ──────────────────────────────────────────────────────────────
    #  Response parsing helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_alarms_from_response(response_data: dict | None) -> tuple[list[dict], int | None]:
        """
        Handle dual response format:
          - Without include_total_records: data is a list
          - With include_total_records:    data is {"alarms": [...], "total_records": N}

        Returns:
            (alarms_list, total_records_or_None)
        """
        if not response_data:
            return [], None

        data = response_data.get("data")
        if data is None:
            return [], None

        if isinstance(data, list):
            return data, None

        if isinstance(data, dict):
            alarms = data.get("alarms", [])
            total = data.get("total_records")
            return alarms, total

        return [], None

    # ──────────────────────────────────────────────────────────────
    #  Severity mapping
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _map_severity(incident: dict[str, Any]) -> str:
        """
        Map API alarm_risk_level to SOAR severity.

        API returns: "HIGH", "MEDIUM", "LOW", "CRITICAL", "INFO"
        SOAR expects: "high", "medium", "low", "critical"
        """
        risk_level = (incident.get("alarm_risk_level") or "").lower()
        return SOCRADAR_SEVERITY_MAP.get(risk_level, DEFAULT_SEVERITY)

    # ──────────────────────────────────────────────────────────────
    #  IOC extraction
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_iocs(incident: dict[str, Any]) -> dict[str, list[str]]:
        """
        Extract IOCs from alarm_related_entities and content dict.

        alarm_related_entities: [{"key": "url", "value": "https://..."}]
        content: {"source_link": "...", "domains": "...", "repository_url": "..."}

        Returns dict with keys: ips, urls, domains, hashes, emails
        """
        iocs: dict[str, list[str]] = {
            "ips": [],
            "urls": [],
            "domains": [],
            "hashes": [],
            "emails": [],
        }

        key_to_list = {
            IOC_KEY_IP: "ips",
            IOC_KEY_URL: "urls",
            IOC_KEY_DOMAIN: "domains",
            IOC_KEY_HASH: "hashes",
            IOC_KEY_EMAIL: "emails",
        }

        # 1) alarm_related_entities
        entities = incident.get("alarm_related_entities") or []
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            key = (entity.get("key") or "").lower()
            value = entity.get("value")
            if key in IOC_ENTITY_KEYS and value:
                target = key_to_list.get(key)
                if target:
                    val_str = str(value).strip()
                    if val_str and val_str not in iocs[target]:
                        iocs[target].append(val_str)

        # 2) content dict
        content = incident.get("content") or {}
        if isinstance(content, dict):
            # URL fields
            for field in CONTENT_URL_FIELDS:
                val = content.get(field)
                if val and isinstance(val, str) and val.strip():
                    val = val.strip()
                    if val not in iocs["urls"]:
                        iocs["urls"].append(val)

            # Domain fields
            for field in CONTENT_DOMAIN_FIELDS:
                val = content.get(field)
                if val and isinstance(val, str) and val.strip():
                    val = val.strip()
                    if val not in iocs["domains"]:
                        iocs["domains"].append(val)

        return iocs

    # ──────────────────────────────────────────────────────────────
    #  Incident normalization
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_incident(incident: dict[str, Any]) -> dict[str, Any]:
        """Truncate large text fields, flatten alarm_type_details."""

        def _truncate(value, max_len=MAX_TEXT_LENGTH):
            text = "" if value is None else str(value)
            return text if len(text) <= max_len else (text[:max_len] + "...")

        if not isinstance(incident, dict):
            return incident

        # Truncate big text fields
        for field in ("alarm_text", "alarm_response"):
            if field in incident:
                incident[field] = _truncate(incident[field])

        # Flatten alarm_type_details
        details = incident.get("alarm_type_details") or {}
        if isinstance(details, dict):
            if "alarm_default_mitigation_plan" in details:
                details["alarm_default_mitigation_plan"] = _truncate(details["alarm_default_mitigation_plan"])
            incident["alarm_main_type"] = details.get("alarm_main_type", "N/A")
            incident["alarm_sub_type"] = details.get("alarm_sub_type", "N/A")
            incident["alarm_generic_title"] = details.get("alarm_generic_title", "")
        else:
            incident.setdefault("alarm_main_type", "N/A")
            incident.setdefault("alarm_sub_type", "N/A")
            incident.setdefault("alarm_generic_title", "")

        return incident

    # ──────────────────────────────────────────────────────────────
    #  Timestamp helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_incident_timestamp(incident: dict[str, Any]) -> int | None:
        """Parse incident 'date' field to epoch seconds."""
        date_str = incident.get("date")
        if date_str:
            try:
                return int(datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
            except (ValueError, TypeError):
                pass
        return None

    @staticmethod
    def _epoch_to_iso(epoch: int) -> str:
        """Convert epoch seconds to ISO 8601 UTC string."""
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ──────────────────────────────────────────────────────────────
    #  Deep link builder
    # ──────────────────────────────────────────────────────────────

    def _build_alarm_link(self, alarm_id) -> str:
        return SOCRADAR_ALARM_URL_TEMPLATE.format(
            base=SOCRADAR_PLATFORM_BASE,
            company_id=self._company_id,
            alarm_id=alarm_id,
        )

    # ──────────────────────────────────────────────────────────────
    #  Container + Artifact builders
    # ──────────────────────────────────────────────────────────────

    def _build_artifact(
        self,
        incident: dict[str, Any],
        alarm_id_str: str,
        current_status: str,
        event_epoch: int | None,
        run_automation: bool = True,
    ) -> dict[str, Any]:
        """Build artifact dict with IOC-rich CEF payload.  SDI = alarm_id-status."""
        alarm_id = incident.get("alarm_id")
        generic_title = incident.get("alarm_generic_title", "")
        iocs = self._extract_iocs(incident)

        # Build CEF — include all meaningful alarm fields
        type_details = incident.get("alarm_type_details") or {}
        cef: dict[str, Any] = {
            "alarm_id": alarm_id,
            "status": current_status,
            "alarm_risk_level": incident.get("alarm_risk_level", ""),
            "alarm_main_type": type_details.get("alarm_main_type") or incident.get("alarm_main_type", ""),
            "alarm_sub_type": type_details.get("alarm_sub_type") or incident.get("alarm_sub_type", ""),
            "alarm_generic_title": generic_title,
            "company_id": self._company_id,
            "alarm_link": self._build_alarm_link(alarm_id),
        }

        # Alarm text and response (rich description fields)
        if incident.get("alarm_text"):
            cef["alarm_text"] = incident["alarm_text"]
        if incident.get("alarm_response"):
            cef["alarm_response"] = incident["alarm_response"]

        # Date
        if incident.get("date"):
            cef["alarm_date"] = incident["date"]

        # Approval and notification
        if incident.get("approved_by"):
            cef["approved_by"] = incident["approved_by"]

        # Asset info
        if incident.get("alarm_asset"):
            cef["alarm_asset"] = incident["alarm_asset"]

        # Compliance list (flatten to names)
        compliance_list = type_details.get("alarm_compliance_list")
        if compliance_list and isinstance(compliance_list, list):
            cef["compliance_frameworks"] = ", ".join(c.get("name", "") for c in compliance_list if c.get("name"))

        # Mitigation plan
        if type_details.get("alarm_default_mitigation_plan"):
            cef["mitigation_plan"] = type_details["alarm_default_mitigation_plan"]

        # Detection and analysis
        if type_details.get("alarm_detection_and_analysis"):
            cef["detection_and_analysis"] = type_details["alarm_detection_and_analysis"]

        # Content enrichment — include all content fields
        content = incident.get("content") or {}
        if isinstance(content, dict):
            for content_key, content_val in content.items():
                if content_val and content_key != "tags":  # tags handled separately
                    if isinstance(content_val, dict):
                        cef[f"content_{content_key}"] = json.dumps(content_val)
                    elif isinstance(content_val, list):
                        cef[f"content_{content_key}"] = ", ".join(str(v) for v in content_val)
                    else:
                        cef[f"content_{content_key}"] = content_val

        # Tags
        tags = incident.get("tags")
        if tags and isinstance(tags, list):
            cef["tags"] = ", ".join(str(t) for t in tags)

        # Related assets (keywords etc.)
        related_assets = incident.get("alarm_related_assets")
        if related_assets and isinstance(related_assets, list):
            asset_parts = []
            for ra in related_assets:
                key = ra.get("key", "")
                val = ra.get("value", "")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                asset_parts.append(f"{key}: {val}")
            if asset_parts:
                cef["related_assets"] = "; ".join(asset_parts)

        # History (status/severity changes)
        history = incident.get("history")
        if history and isinstance(history, list):
            history_parts = []
            for h in history[:10]:  # max 10 entries
                action = h.get("action_type", "")
                desc = h.get("description", "")
                date = h.get("date", "")
                history_parts.append(f"[{date}] {action}: {desc}")
            if history_parts:
                cef["history"] = " | ".join(history_parts)

        # Extra fields (e.g. Safebin links)
        extra = incident.get("extra")
        if extra and isinstance(extra, list):
            for item in extra:
                fields = item.get("fields") or {}
                for ek, ev in fields.items():
                    safe_key = ek.lower().replace(" ", "_")
                    if ev:
                        cef[f"extra_{safe_key}"] = str(ev)[:500]

        # Map IOCs to standard CEF fields
        cef_types: dict[str, list[str]] = {}

        if iocs["ips"]:
            cef_field, contains = CEF_MAP_IP
            cef[cef_field] = iocs["ips"][0]
            cef_types[cef_field] = contains

        if iocs["urls"]:
            cef_field, contains = CEF_MAP_URL
            cef[cef_field] = iocs["urls"][0]
            cef_types[cef_field] = contains

        if iocs["domains"]:
            cef_field, contains = CEF_MAP_DOMAIN
            cef[cef_field] = iocs["domains"][0]
            cef_types[cef_field] = contains

        if iocs["hashes"]:
            cef_field, contains = CEF_MAP_HASH
            cef[cef_field] = iocs["hashes"][0]
            cef_types[cef_field] = contains

        if iocs["emails"]:
            cef_field, contains = CEF_MAP_EMAIL
            cef[cef_field] = iocs["emails"][0]
            cef_types[cef_field] = contains

        artifact_name = generic_title if generic_title else f"Alarm {alarm_id} artifact"

        artifact = {
            "name": artifact_name,
            "label": "event",
            "cef": cef,
            "cef_types": cef_types,
            "severity": self._map_severity(incident),
            "source_data_identifier": f"{alarm_id_str}-{current_status}",
            "run_automation": run_automation,
        }

        if event_epoch:
            artifact["start_time"] = self._epoch_to_iso(event_epoch)

        return artifact

    def _ingest_incident(
        self,
        incident: dict[str, Any],
        alarm_id_str: str,
        current_status: str,
        event_epoch: int | None,
    ) -> int | None:
        """Create container with embedded artifact in a single call.  SDI = alarm_id."""
        alarm_id = incident.get("alarm_id")
        generic_title = incident.get("alarm_generic_title", "")
        name = generic_title if generic_title else f"SOCRadar Alarm {alarm_id}"

        artifact = self._build_artifact(incident, alarm_id_str, current_status, event_epoch)

        container = {
            "name": name,
            "description": f"{incident.get('alarm_main_type', 'N/A')}/{incident.get('alarm_sub_type', 'N/A')}",
            "label": self._container_label,
            "severity": self._map_severity(incident),
            "source_data_identifier": alarm_id_str,
            "artifacts": [artifact],
        }

        ret_val, message, container_id = self.save_container(container)

        if phantom.is_fail(ret_val):
            self.debug_print(ERR_SAVE_CONTAINER.format(message=message))
            return None

        return container_id

    # ──────────────────────────────────────────────────────────────
    #  ACTION: test_connectivity
    # ──────────────────────────────────────────────────────────────

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not (self._company_id and self._api_key):
            self.save_progress(ERR_MISSING_CONFIG)
            return action_result.set_status(phantom.APP_ERROR, ERR_MISSING_CONFIG)

        self.save_progress(MSG_TESTING)

        endpoint = INCIDENTS_ENDPOINT.format(company_id=self._company_id)

        ret_val, _resp_data, _ = self._make_rest_call(
            endpoint,
            action_result,
            params={"limit": 1, "page": 1},
        )

        if phantom.is_fail(ret_val):
            self.save_progress(MSG_TEST_FAIL)
            return action_result.get_status()

        self.save_progress(MSG_TEST_PASS)
        return action_result.set_status(phantom.APP_SUCCESS, MSG_TEST_PASS)

    # ──────────────────────────────────────────────────────────────
    #  ACTION: on_poll
    # ──────────────────────────────────────────────────────────────

    def _handle_on_poll(self, param):
        """
        Ingest SOCRadar incidents into Splunk SOAR.

        - Scheduled poll: resume from state checkpoint, update state after
        - Poll Now: fetch recent items, do NOT update state
        - First run: fetch last N hours (configurable)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        action_result.set_status(phantom.APP_SUCCESS)

        if not (self._company_id and self._api_key):
            return action_result.set_status(phantom.APP_ERROR, ERR_MISSING_CONFIG)

        # ── Time window & limits ──
        now_utc = datetime.now(timezone.utc)
        end_epoch = int(now_utc.timestamp())
        is_poll_now = self.is_poll_now()
        last_poll_time = self._state.get(STATE_LAST_POLL_TIME)

        if is_poll_now:
            # Poll Now: use last checkpoint or last N hours; limited by container_count
            max_incidents = int(param.get("container_count", 5) or 5)
            if last_poll_time:
                start_epoch = int(last_poll_time)
            else:
                start_epoch = int((now_utc - timedelta(hours=FIRST_RUN_LOOKBACK_HOURS)).timestamp())
            self.save_progress(MSG_POLL_NOW.format(count=max_incidents))

        elif last_poll_time is None:
            # First scheduled run: last N hours
            start_epoch = int((now_utc - timedelta(hours=FIRST_RUN_LOOKBACK_HOURS)).timestamp())
            max_incidents = self._first_run_max_incidents
            self.save_progress(MSG_POLL_FIRST_RUN.format(hours=FIRST_RUN_LOOKBACK_HOURS, max=max_incidents))

        else:
            # Subsequent scheduled run: from checkpoint
            start_epoch = int(last_poll_time)
            max_incidents = self._max_incidents_per_poll
            self.save_progress(MSG_POLL_SCHEDULED.format(max=max_incidents))

        self.save_progress(
            MSG_POLL_START.format(
                start=self._epoch_to_iso(start_epoch),
                end=self._epoch_to_iso(end_epoch),
            )
        )

        # ── State setup ──
        alarm_status_map: dict[str, str] = self._state.get(STATE_ALARM_STATUS, {})

        endpoint = INCIDENTS_ENDPOINT.format(company_id=self._company_id)
        current_page = 1
        new_count = 0
        skipped_count = 0
        last_response: requests.Response | None = None

        # ── Pagination loop ──
        while current_page <= MAX_PAGES_PER_POLL and new_count < max_incidents:
            self.save_progress(MSG_FETCHING_PAGE.format(current=current_page, count=new_count))

            # Proactive throttle based on previous response
            if last_response is not None and self._should_throttle(last_response):
                remaining = last_response.headers.get(HEADER_RATELIMIT_REMAINING, "?")
                self.save_progress(MSG_PROACTIVE_THROTTLE.format(remaining=remaining, seconds=PROACTIVE_THROTTLE_WAIT))
                time.sleep(PROACTIVE_THROTTLE_WAIT)

            params: dict[str, Any] = {
                "limit": DEFAULT_PAGE_SIZE,
                "page": current_page,
                "start_date": start_epoch,
                "end_date": end_epoch,
            }

            # First page: request total_records for progress info
            if current_page == 1:
                params["include_total_records"] = "true"

            ret_val, resp_data, raw_response = self._make_rest_call(endpoint, action_result, params=params)
            last_response = raw_response

            # Handle rate limit inline (retry once)
            if raw_response is not None and raw_response.status_code == 429:
                wait = self._get_retry_wait(raw_response)
                self.save_progress(MSG_RATE_LIMIT_WAIT.format(seconds=wait))
                time.sleep(wait)
                # Reset action_result status for retry
                action_result.set_status(phantom.APP_SUCCESS)
                ret_val, resp_data, raw_response = self._make_rest_call(endpoint, action_result, params=params)
                last_response = raw_response

            if phantom.is_fail(ret_val):
                # Non-recoverable error — save progress so far and return
                break

            alarms, total_records = self._extract_alarms_from_response(resp_data)

            if total_records is not None and current_page == 1:
                self.debug_print(f"Total records available: {total_records}")

            if not alarms:
                if resp_data:
                    self.debug_print(
                        f"No alarms on page {current_page}. Response keys: {list(resp_data.keys()) if isinstance(resp_data, dict) else type(resp_data).__name__}"
                    )
                else:
                    self.debug_print(f"No alarms on page {current_page}")
                break

            # ── Process each alarm ──
            for incident in alarms:
                incident = self._normalize_incident(incident)

                alarm_id = incident.get("alarm_id")
                current_status = incident.get("status", "N/A")

                if not alarm_id:
                    continue

                alarm_id_str = str(alarm_id)

                # Dedup: skip unchanged
                previous_status = alarm_status_map.get(alarm_id_str)
                if previous_status is not None and previous_status == current_status:
                    skipped_count += 1
                    continue

                # Log status changes
                if previous_status is not None and previous_status != current_status:
                    self.debug_print(MSG_STATUS_CHANGE.format(alarm_id=alarm_id_str, old=previous_status, new=current_status))

                # Parse event timestamp
                event_epoch = self._parse_incident_timestamp(incident)

                # Create container with embedded artifact (single HTTP call)
                container_id = self._ingest_incident(incident, alarm_id_str, current_status, event_epoch)
                if not container_id:
                    continue

                # Update dedup map
                alarm_status_map[alarm_id_str] = current_status
                new_count += 1

                # Periodic state save to preserve progress
                if new_count % PERIODIC_STATE_SAVE_INTERVAL == 0:
                    self._state[STATE_ALARM_STATUS] = alarm_status_map
                    self.save_state(self._state)
                    self.debug_print(f"Periodic state save at {new_count} containers")

                if new_count >= max_incidents:
                    self.save_progress(MSG_PER_POLL_CAP.format(max=max_incidents))
                    break

            # End-of-page checks
            if new_count >= max_incidents:
                break

            if len(alarms) < DEFAULT_PAGE_SIZE:
                self.save_progress(MSG_LAST_PAGE.format(count=len(alarms), page_size=DEFAULT_PAGE_SIZE))
                break

            current_page += 1
            time.sleep(PAGE_DELAY_SECONDS)

        # ── State trim ──
        if len(alarm_status_map) > STATE_MAX_ALARMS:
            items = sorted(alarm_status_map.items(), key=lambda item: item[0])
            alarm_status_map = dict(items[-STATE_MAX_ALARMS:])
            self.debug_print(MSG_STATE_TRIMMED.format(max=STATE_MAX_ALARMS))

        # ── Save state (only for scheduled polling) ──
        self._state[STATE_ALARM_STATUS] = alarm_status_map
        self._state[STATE_LAST_UPDATED] = now_utc.isoformat()

        if not is_poll_now:
            self._state[STATE_LAST_POLL_TIME] = end_epoch

        # ── Summary ──
        action_result.update_summary(
            {
                "new_or_updated": new_count,
                "skipped_same_status": skipped_count,
                "pages_traversed": current_page,
                "total_tracked": len(alarm_status_map),
            }
        )

        self.save_progress(MSG_INGESTION_COMPLETE.format(new=new_count, skipped=skipped_count))

        if phantom.is_fail(action_result.get_status()):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    # ──────────────────────────────────────────────────────────────
    #  ACTION: get_incident
    # ──────────────────────────────────────────────────────────────

    def _handle_get_incident(self, param):
        """Fetch a single incident by alarm_id."""
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param.get("incident_id", "")
        if not incident_id:
            return action_result.set_status(phantom.APP_ERROR, "incident_id is required")

        endpoint = INCIDENTS_ENDPOINT.format(company_id=self._company_id)

        ret_val, resp_data, _ = self._make_rest_call(
            endpoint,
            action_result,
            params={"alarm_ids": incident_id, "limit": 1, "page": 1},
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        alarms, _ = self._extract_alarms_from_response(resp_data)

        if not alarms:
            return action_result.set_status(phantom.APP_ERROR, f"Incident {incident_id} not found")

        alarm = alarms[0]
        alarm = self._normalize_incident(alarm)

        action_result.add_data(alarm)
        action_result.update_summary(
            {
                "alarm_id": alarm.get("alarm_id"),
                "status": alarm.get("status"),
                "alarm_risk_level": alarm.get("alarm_risk_level"),
            }
        )

        return action_result.set_status(phantom.APP_SUCCESS)

    # ──────────────────────────────────────────────────────────────
    #  ACTION: update_status
    # ──────────────────────────────────────────────────────────────

    def _handle_update_status(self, param):
        """Change alarm status in SOCRadar."""
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param.get("incident_id", "").strip()
        new_status = param.get("status", "").strip()
        comment = param.get("comment", "")

        if not incident_id:
            return action_result.set_status(phantom.APP_ERROR, "incident_id is required")

        ret_val, incident_id_int = self._validate_integer(action_result, incident_id, "incident_id")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not new_status:
            return action_result.set_status(phantom.APP_ERROR, "status is required")

        status_int = SOCRADAR_STATUS_INT_MAP.get(new_status.upper())
        if status_int is None:
            return action_result.set_status(phantom.APP_ERROR, ERR_INVALID_STATUS.format(status=new_status))
        new_status = new_status.upper()

        endpoint = STATUS_CHANGE_ENDPOINT.format(company_id=self._company_id)
        body = {"alarm_ids": [incident_id_int], "status": status_int}
        if comment:
            body["comments"] = comment

        ret_val, resp_data, _ = self._make_rest_call(endpoint, action_result, method="post", json_body=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_data and not resp_data.get("is_success", False):
            return action_result.set_status(phantom.APP_ERROR, resp_data.get("message", "Status update failed"))

        action_result.add_data({"alarm_id": incident_id, "new_status": new_status, "api_response": resp_data})
        action_result.update_summary({"alarm_id": incident_id, "status_changed": True, "new_status": new_status})
        return action_result.set_status(phantom.APP_SUCCESS, MSG_STATUS_UPDATED.format(alarm_id=incident_id, status=new_status))

    # ──────────────────────────────────────────────────────────────
    #  ACTION: change_severity
    # ──────────────────────────────────────────────────────────────

    def _handle_change_severity(self, param):
        """Change alarm severity in SOCRadar."""
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param.get("incident_id", "").strip()
        severity = param.get("severity", "").strip()

        if not incident_id:
            return action_result.set_status(phantom.APP_ERROR, "incident_id is required")

        ret_val, incident_id_int = self._validate_integer(action_result, incident_id, "incident_id")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not severity:
            return action_result.set_status(phantom.APP_ERROR, "severity is required")

        severity = severity.title()
        if severity not in SEVERITY_API_VALUES:
            return action_result.set_status(phantom.APP_ERROR, ERR_INVALID_SEVERITY.format(severity=severity))

        endpoint = SEVERITY_CHANGE_ENDPOINT.format(company_id=self._company_id)
        body = {"alarm_ids": [incident_id_int], "severity": severity}

        ret_val, resp_data, _ = self._make_rest_call(endpoint, action_result, method="post", json_body=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_data and not resp_data.get("is_success", False):
            return action_result.set_status(phantom.APP_ERROR, resp_data.get("message", "Severity update failed"))

        action_result.add_data({"alarm_id": incident_id, "new_severity": severity, "api_response": resp_data})
        action_result.update_summary({"alarm_id": incident_id, "severity_changed": True, "new_severity": severity})
        return action_result.set_status(phantom.APP_SUCCESS, MSG_SEVERITY_UPDATED.format(alarm_id=incident_id, severity=severity))


# ──────────────────────────────────────────────────────────────────
#  Local testing
# ──────────────────────────────────────────────────────────────────


def main():
    import argparse
    import sys

    argparser = argparse.ArgumentParser()
    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    if args.username is not None and args.password is None:
        import getpass

        args.password = getpass.getpass("Password: ")

    if args.username and args.password:
        try:
            login_url = SocradarincidentsConnector._get_phantom_base_url() + "/login"
            print(f"Accessing the Login page at {login_url}")
            # Login handled by SOAR platform
            session_id = "local_test_session"
        except Exception as e:
            print(f"Unable to get session id: {e}")
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SocradarincidentsConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == "__main__":
    main()
