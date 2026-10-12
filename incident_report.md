# SOC Incident Investigation Report

## 1. Incident Overview

* **Incident Name:** Repeated Failed Login Attempts
* **Category:** Authentication Monitoring
* **SIEM Tool:** Splunk
* **Log Source:** splunk_soc_sample_logs.txt
* **Sourcetype:** bruteforce
* **Windows Event ID:** 4625 — Failed Logon
* **Detection Threshold:** 5 or more events within a five-minute time bucket

## 2. Investigation Objective

The objective of this investigation was to analyze failed login events in Splunk and identify accounts with repeated authentication failures that may indicate suspicious activity.

## 3. Detection Results

| Account | Failed Login Attempts | Assessment        |
| ------- | --------------------: | ----------------- |
| admin   |                     5 | Threshold reached |
| smith   |                     2 | Below threshold   |

The admin account reached the configured threshold of five failed login attempts. The smith account had two failed login attempts.

## 4. Investigation Findings

The Splunk search identified repeated failed login events associated with the sample dataset.

The admin account requires further investigation because it reached the configured alert threshold. However, failed login attempts alone do not confirm a brute-force attack.

Additional investigation should include source IP addresses, event timestamps, authentication patterns, and any subsequent successful logins.

## 5. Severity Assessment

* **Initial Severity:** Medium
* **Reason:** The admin account reached the lab's configured threshold.
* **Status:** Further investigation required.

This severity is an initial lab assessment and not a confirmed incident classification.

## 6. Recommended Actions

1. Identify the source IP addresses associated with the failed logins.
2. Review timestamps to determine whether the attempts occurred within five minutes.
3. Check for successful logins following repeated failures.
4. Investigate whether the activity was expected or suspicious.
5. Escalate the incident if additional evidence indicates a potential attack.

## 7. Conclusion

Splunk was used to search Windows failed logon events and identify repeated authentication failures. The admin account reached the configured detection threshold, while the smith account remained below it.

Further investigation is necessary to determine whether the activity represents a genuine brute-force attempt.

## 8. Tools Used

* Splunk Enterprise or Splunk platform
* Splunk Processing Language (SPL)
* Windows Security Event Logs
* GitHub for project documentation
