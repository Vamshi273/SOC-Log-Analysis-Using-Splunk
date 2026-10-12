# Splunk Brute-Force Detection Lab

## Project Overview

This project demonstrates how Splunk can be used to analyze Windows failed logon events and identify repeated authentication failures that may indicate potential brute-force activity.

## Objectives

* Search and analyze failed login events.
* Identify accounts with repeated authentication failures.
* Create threshold-based detection queries using Splunk Processing Language (SPL).
* Document findings in a SOC incident report.

## Tools and Technologies

* Splunk
* Splunk Processing Language (SPL)
* Windows Security Event ID 4625
* Sample authentication logs
* GitHub

## Dataset

The lab uses sample authentication logs assigned the sourcetype `bruteforce`.

**Event ID 4625:** Windows Security auditing event indicating a failed logon.

## Detection Logic

The detection query searches for five or more matching failed-login events within a five-minute time bucket.

```spl
index=main sourcetype=bruteforce "4625"
| bin _time span=5m
| stats count by _time
| where count >= 5
| sort - count
```

## Sample Investigation Results

* **admin:** 5 failed logon attempts.
* **smith:** 2 failed logon attempts.
* **Detection threshold:** 5 or more matching events per five-minute bucket.
* **Initial assessment:** The admin account reached the configured threshold.

These results describe the lab findings and should be verified against the actual indexed dataset.

## Investigation Process

1. Search for failed logon events.
2. Review event timestamps and host information.
3. Count matching events within five-minute buckets.
4. Identify accounts that reach the detection threshold.
5. Investigate source IP addresses and subsequent successful logins.
6. Document findings and recommended next steps.

## Screenshots

Screenshots of the Splunk searches and detection results will be stored in the `screenshots/` directory.

## Project Files

* `splunk_queries.md` — SPL searches used in the lab.
* `incident_report.md` — Investigation findings and recommendations.
* `splunk_soc_sample_logs.txt` — Sample log dataset.
* `screenshots/` — Evidence of lab execution.

## Conclusion

This lab demonstrates basic SIEM log analysis and threshold-based detection using Splunk. Further investigation is required before classifying repeated failed logins as a confirmed brute-force attack.

## Disclaimer

This project is intended for educational purposes. Any sample logs included in this repository should be clearly identified as synthetic data and must not contain sensitive information.
