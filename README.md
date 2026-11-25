# LogWatch

A Windows log analyzer that detects brute-force and suspicious login patterns.

## Detections
- Brute force (5+ failed logins in 5 minutes)
- Password spraying (4+ users from one source)
- Successful login after multiple failures
- Off-hours login (12 AM to 6 AM)
- Account lockout

## Requirements
Windows, Python 3.7+, Administrator rights (for log export)

## Usage
Test with sample data:

```
python logwatch.py sample_events.csv
```

Enable logon auditing (Administrator PowerShell):

```
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

Scan your logs from the last 24 hours (Administrator PowerShell):

```
powershell -ExecutionPolicy Bypass -File .\export_logs.ps1
python logwatch.py events.csv
```

## Note
For learning and defensive use. Never upload your real events.csv or report.csv.
