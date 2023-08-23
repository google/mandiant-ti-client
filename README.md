# Mandiant Advantage Threat Intel Client for Python

## Quickstart

### Initializing the client

#### From API Key and Secret Key (preferred)

```Python
import mandiant_threatintel

api_key = "API_KEY_GOES_HERE"
secret_key = "SECRET_KEY_GOES_HERE"

mati_client = mandiant_threatintel.ThreatIntelClient(api_key=api_key,
                                                    secret_key=secret_key)
```

#### With an existing Bearer Token

```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"

mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)
```

### Accessing Indicators

#### By UUID
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

indicator = mati_client.Indicators.get('INDICATOR--UUID')
```

#### By Value
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

indicator = mati_client.Indicators.get_from_value('INDICATOR_VALUE.com')
```

#### Get all matching Indicators
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

indicators_generator = mati_client.Indicators.get_list()
```

### Accessing Threat Actors

#### By Name or UUID
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

threatactor = mati_client.ThreatActors.get('NAME-OR-UUID')
```

#### Get all Threat Actors
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

threatactors_generator = mati_client.ThreatActors.get_list()
```

### Accessing Malware Families

#### By Name or UUID
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

malware = mati_client.Malware.get('NAME-OR-UUID')
```

#### Get all Malware Families
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

malware_generator = mati_client.Malware.get_list()
```

### Accessing Vulnerabilities

#### By CVE ID or UUID
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

vulnerability = mati_client.Vulnerabilities.get('CVE-ID-OR-UUID')
```

#### Get all matching Vulnerabilities
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

vulnerability_generator = mati_client.Vulnerabilities.get_list()
```

### Accessing Reports

#### By Report ID
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

report = mati_client.Reports.get('REPORT-ID')
```

#### Get all matching Reports
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

reports_generator = mati_client.Reports.get_list()
```

#### Save a Report PDF to a File
```Python
import mandiant_threatintel

bearer_token = "EXISTING_BEARER_TOKEN"
mati_client = mandiant_threatintel.ThreatIntelClient(bearer_token=bearer_token)

file_name = 'report.pdf'
report_id = 'SOME-REPORT-ID'

report = mati_client.Reports.get(report_id)
with open(file_name, 'wb') as f:
  f.write(report.pdf)
```

## Change Log

### 0.1.18 (2023-08-23)
* Add support for the new Threat Rating and Category fields on an indicator 

### 0.1.17 (2023-05-26)
* Allow passing of kwargs into `threat_intel_client.IndicatorClient.get_list()`

### 0.1.16 (2023-05-24)
* Handle 204 response from `threat_intel_client.IndicatorClient.get_from_value()`

### 0.1.14 (2023-04-04)
* Fix broken Aliases in Threat Actor because of MATI API change

### 0.1.12 (2023-03-03)
* Began using `include_reports=True` for Indicator queries to reduce API calls

### 0.1.11 (2023-01-31)
* Replaced usage of `|` with `dict.update()` to better support Python 3.7 and Python 3.8

### 0.1.10 (2023-01-31)
* Fixed an issue where `campaigns` were unavailable for indicators retrieved via `get_list`

### 0.1.9 (2023-01-31)

* Fixes an issue where a new bearer token is requested from the API before every API request
