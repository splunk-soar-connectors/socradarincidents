**Unreleased**
* Initial release of SOCRadar Incidents connector (v1.0.0)
* Added 5 actions: test connectivity, on poll, get incident, update status, change severity
* SOCRadar API v4 integration with API-Key header authentication
* Automatic incident ingestion with state-based checkpointing and deduplication
* IOC extraction from alarm_related_entities and content fields into standard CEF format
* Severity mapping from alarm_risk_level (CRITICAL/HIGH/MEDIUM/LOW) to SOAR severity levels
* Rate limit handling with retry-after and x-ratelimit-remaining header support
* Rich artifact enrichment with all alarm fields (text, response, compliance, mitigation, history, etc.)
* Poll Now support without updating state checkpoint
* Configurable polling parameters (first_run_max_incidents, max_incidents_per_poll)
