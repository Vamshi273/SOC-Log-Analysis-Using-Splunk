# Splunk Brute-Force Detection Queries

## 1. Search All Brute-Force Logs

```spl
index=main sourcetype=bruteforce
```

## 2. Search Failed Login Events

```spl
index=main sourcetype=bruteforce "4625"
```

Windows Security Event ID 4625 indicates a failed logon.

## 3. Count Events by Host

```spl
index=main sourcetype=bruteforce "4625"
| stats count by host
| sort - count
```

## 4. Detect Repeated Failed Logins

```spl
index=main sourcetype=bruteforce "4625"
| bin _time span=5m
| stats count by _time
| where count >= 5
| sort - count
```

This query identifies five or more matching events in a five-minute time bucket.

## 5. Detect Accounts with Repeated Failures

This query assumes account names can be extracted from the raw event text.

```spl
index=main sourcetype=bruteforce "4625"
| eval account=case(
    like(_raw,"%admin%"),"admin",
    like(_raw,"%smith%"),"smith",
    true(),"Unknown"
)
| stats count by account
| where count >= 5
| eval severity=if(count>=10,"High","Medium")
| table account count severity
```

Note: The account-matching query is specific to this sample dataset. A production detection should use correctly extracted account and source IP fields.
