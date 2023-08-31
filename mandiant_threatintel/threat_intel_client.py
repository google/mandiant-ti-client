# Copyright 2023 Google LLC
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

"""A Client Library for the Mandiant Advantage Threat Intelligence API.

This library provides a wrapper around the data available via the Mandiant
Advantage Threat Intelligence (MATI) API, allowing a user to access any of the
data in an appropriate format.

Typical usage examples:
  api_client = mandiant_threatintel.ThreatIntelClient(api_key=KEY,
                                                     secret_key=SECRET)
"""
from __future__ import annotations

import dataclasses
import datetime
import typing
import typing
from typing import Generator, Tuple, Union
import urllib.parse

import dateutil.parser as dateutil_parser
from mandiant_threatintel.data_types import *
import requests
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

API_BASE_URL = "https://api.intelligence.mandiant.com"
API_PREFIX = "/v4"
API_AUTHENTICATION_PATH = "/token"
API_THREATACTORS_ROOT = f"{API_PREFIX}/actor"
API_REPORTS_ROOT = f"{API_PREFIX}/report"
API_REPORTS_LIST_ROOT = f"{API_PREFIX}/reports"
API_MALWARE_ROOT = f"{API_PREFIX}/malware"
API_VULNERABILITY_ROOT = f"{API_PREFIX}/vulnerability"
API_INDICATOR_ROOT = f"{API_PREFIX}/indicator"
API_CAMPAIGN_ROOT = f"{API_PREFIX}/campaign"
DTM_API_PREFIX = f"{API_PREFIX}/dtm"
API_DTM_ALERTS_ROOT = f"{DTM_API_PREFIX}/alerts"
API_DTM_DOCS_ROOT = f"{DTM_API_PREFIX}/docs"
API_DTM_MONITORS_ROOT = f"{DTM_API_PREFIX}/monitors"
API_DTM_EMAIL_SETTINGS_ROOT = f"{DTM_API_PREFIX}/settings/email"


CLIENT_APP_NAME = "MA-TI-Python-Lib-v0.1"


def parse_mitre_attck_patterns(
    indicator_type: str, attack_pattern_response: dict
):
  attack_pattern_reference = {
      k: AttackPattern.from_api(v)
      for k, v in attack_pattern_response["attack-patterns"].items()
  }
  output = {}
  attack_pattern_map = attack_pattern_response[indicator_type][0][
      "attack-patterns"
  ]
  for pattern_type in attack_pattern_map:
    output[pattern_type] = []
    for base_pattern in attack_pattern_map.get(pattern_type):
      selected_pattern = attack_pattern_reference[base_pattern["id"]]
      selected_pattern.sub_techniques = [
          attack_pattern_reference[i["id"]]
          for i in base_pattern.get("sub_techniques", [])
      ]
      output[pattern_type].append(selected_pattern)

  return {"attack_patterns": output}


def parse_threatactor_attck_patterns(attack_pattern_response: dict):
  return parse_mitre_attck_patterns("threat-actors", attack_pattern_response)


def parse_malware_attck_patterns(attack_pattern_response: dict):
  return parse_mitre_attck_patterns("malware", attack_pattern_response)


def create_indicator(indicator_api_response: dict, client: ThreatIntelClient):
  indicator_type = indicator_api_response.get("type")

  if indicator_type is None:
    # Fallback - attempt to get type from ID
    uuid = indicator_api_response.get("id")
    indicator_type = uuid[0 : uuid.index("--")]

  INDICATOR_MAP = {
      "md5": MD5Indicator,
      "url": URLIndicator,
      "fqdn": FQDNIndicator,
      "ipv4": IPIndicator,
  }

  return INDICATOR_MAP[indicator_type].from_json_response(
      indicator_api_response, client
  )


def get_associated_hash(
    associated_hashes_list: typing.List[typing.Dict], hash_type: str = "md5"
) -> str:
  for assoc_hash in associated_hashes_list:
    if assoc_hash["type"] == hash_type:
      return assoc_hash["value"]

  return


def exception_is_retryable(exception: Exception) -> bool:
  if isinstance(exception, requests.exceptions.HTTPError):
    retryable_status_codes = [429, 500, 502, 503, 504]

    if exception.response.status_code in retryable_status_codes:
      return True

  return False


def get_field_from_response(
    api_response: dict[str, typing.Any], fields: typing.List[str]
):
  for field_name in fields:
    if field_name in api_response:
      return api_response.get(field_name)

  raise ValueError("No matching fields found in API response")


def create_attributed_association(
    attributed_association: dict, client: ThreatIntelClient
):
  if attributed_association["type"] == "threat-actor":
    return ThreatActor.from_identifier(attributed_association["id"], client)
  elif attributed_association["type"] == "malware":
    return Malware.from_identifier(attributed_association["id"], client)


class ThreatActorsClient:
  """A client for fetching information about Threat Actors from MATI.

  A client to fetch ThreatActor objects from the MATI API
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a ThreatActorsClient from a ThreatIntelClient.

    Initialize a new ThreatActorsClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get(self, identifier: str) -> ThreatActor:
    """Get a ThreatActor object from a given identifier.

    Get a single ThreatActor from the MATI API

    Args:
      identifier: The name or UUID of a Threat Actor

    Returns:
      A ThreatActor object
    """
    return ThreatActor.from_identifier(identifier, self._base_client)

  def get_list(
      self, page_size: int = 1000
  ) -> Generator[ThreatActor, None, None]:
    """Get all ThreatActor objects from MATI.

    Get a generator containing all ThreatActors from the MATI API

    Args:
      page_size: The number of Threat Actor objects per page to retrieve from
        MATI.  Does not limit the total number of results returned

    Yields:
      A ThreatActor object
    """
    params = {"limit": page_size, "offset": 0}

    while True:
      api_response = self._base_client.make_get_request(
          API_THREATACTORS_ROOT, params=params
      )

      if not api_response:
        break

      actors_from_api = api_response.get("threat-actors", [])

      for actor in actors_from_api:
        yield ThreatActor.from_json_response(actor, self._base_client)

      if len(actors_from_api) != page_size:
        break

      params = {"limit": page_size, "offset": params["offset"] + page_size}

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MATI ThreatActor endpoint.

    Make a GET request against a specific ThreatActor endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the Threat Actor to retrieve
      url_suffix: The specific endpoint to query (e.g. /reports)
      content_type: A str to be passed as the `Accept` header of the request

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes object
    """
    if not content_type:
      content_type = "application/json"

    endpoint = f"{API_THREATACTORS_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(endpoint, headers=headers)


class ReportsClient:
  """A client for fetching information about Reports from MATI.

  A client to fetch Report objects from the MATI API
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a ReportsClient from a ThreatIntelClient.

    Initialize a new ReportsClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get(self, identifier: str) -> Report:
    """Get a Report object from a given identifier.

    Get a single Report from the MATI API

    Args:Reports(
      identifier: The report ID of a report

    Returns:
      A Report object
    """
    return Report.from_identifier(identifier, self._base_client)

  def get_list(
      self,
      start_epoch: datetime.datetime,
      end_epoch: datetime.datetime = None,
      page_size: int = 1000,
  ) -> Generator[Report, None, None]:
    """Get all reports within a specified time range.

    Args:
      start_epoch: A datetime object representing the start of the time range
      end_epoch: An optional datetime object representing the end of the time
        range to retrieve.  Defaults to "now"
      page_size: The number of results to retrieve from MATI per page.  Does not
        limit the total number of results to retrieve

    Yields:
      A Report object
    """
    params = {"start_epoch": int(start_epoch.timestamp()), "limit": page_size}
    if end_epoch:
      params["end_epoch"] = int(end_epoch.timestamp())

    while True:
      api_response = self._base_client.make_get_request(
          API_REPORTS_LIST_ROOT, params=params
      )

      if not api_response:
        break

      reports_from_api = api_response.get("objects", [])

      for indicator in reports_from_api:
        yield Report.from_json_response(indicator, self._base_client)

      if len(reports_from_api) != page_size:
        break

      params = {"next": api_response.get("next")}

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
      params: dict = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MATI Reports endpoint.

    Make a GET request against a specific Reports endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the report to retrieve
      url_suffix: The specific endpoint to query (e.g. /indicators)
      content_type: A str to be passed as the `Accept` header of the request
      params: An optional dictionary containing request parameters

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes object
    """

    if not content_type:
      content_type = "application/json"

    if not params:
      params = {}

    endpoint = f"{API_REPORTS_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(
        endpoint, headers=headers, params=params
    )


class MalwareClient:
  """A client for fetching information about Malware Families from MATI.

  A client to fetch Malware objects from the MATI API
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a MalwareClient from a ThreatIntelClient.

    Initialize a new MalwareClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get(self, identifier: str) -> Malware:
    """Get a Malware object from a given identifier.

    Get a single Malware object from the MATI API

    Args:
      identifier: The UUID or name of a Malware Family

    Returns:
      A Malware object
    """
    return Malware.from_identifier(identifier, self._base_client)

  def get_list(self, page_size: int = 1000) -> Generator[Malware, None, None]:
    """Get all Malware Families from MATI.

    Args:
      page_size: The number of results to retrieve from MATI per page.  Does not
        limit the total number of results to retrieve

    Yields:
      A Malware object
    """
    params = {"limit": page_size, "offset": 0}

    while True:
      api_response = self._base_client.make_get_request(
          API_MALWARE_ROOT, params=params
      )

      if not api_response:
        break

      malware_from_api = api_response.get("malware", [])

      for malware in malware_from_api:
        yield Malware.from_json_response(malware, self._base_client)

      if len(malware_from_api) != page_size:
        break

      params = {"limit": page_size, "offset": params["offset"] + page_size}

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MATI Malware endpoint.

    Make a GET request against a specific Malware endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the Malware Family to retrieve
      url_suffix: The specific endpoint to query (e.g. /reports)
      content_type: A str to be passed as the `Accept` header of the request

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes object
    """
    if not content_type:
      content_type = "application/json"

    endpoint = f"{API_MALWARE_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(endpoint, headers=headers)


class VulnerabilityClient:
  """A client for fetching information about Vulnerabilities from MATI.

  A client to fetch Vulnerability objects from the MATI API
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a VulnerabilityClient from a ThreatIntelClient.

    Initialize a new VulnerabilityClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get(self, identifier: str) -> Vulnerability:
    """Get a Vulnerability object from a given identifier.

    Get a single Vulnerability object from the MATI API

    Args:
      identifier: The UUID or CVE ID of the Vulnerability to retrieve

    Returns:
      A Vulnerability object
    """

    return Vulnerability.from_identifier(identifier, self._base_client)

  def get_list(
      self,
      start_epoch: datetime.datetime,
      end_epoch: datetime.datetime = None,
      page_size: int = 1000,
  ) -> Generator[Vulnerability, None, None]:
    """Get all vulnerabilities within a specified time range.

    Args:
      start_epoch: A datetime object representing the start of the time range
      end_epoch: An optional datetime object representing the end of the time
        range to retrieve.  Defaults to "now"
      page_size: The number of results to retrieve from MATI per page.  Does not
        limit the total number of results to retrieve

    Yields:
      A Vulnerability object
    """
    params = {
        "start_epoch": int(start_epoch.timestamp()),
        "limit": page_size,
        "offset": 0,
    }
    if end_epoch:
      params["end_epoch"] = int(end_epoch.timestamp())

    while True:
      api_response = self._base_client.make_get_request(
          API_VULNERABILITY_ROOT, params=params
      )

      if not api_response:
        break

      vulnerabilities_from_api = api_response.get("vulnerability", [])

      for vulnerability in vulnerabilities_from_api:
        yield Vulnerability.from_json_response(vulnerability, self._base_client)

      if len(vulnerabilities_from_api) != page_size:
        break

      params = {"limit": page_size, "offset": params["offset"] + page_size}

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MATI Vulnerability endpoint.

    Make a GET request against a specific Vulnerability endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the vulnerability to retrieve
      url_suffix: The specific endpoint to query (e.g. /malware)
      content_type: A str to be passed as the `Accept` header of the request

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes object
    """
    if not content_type:
      content_type = "application/json"

    endpoint = f"{API_VULNERABILITY_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(endpoint, headers=headers)


class IndicatorsClient:
  """A client for fetching information about Indicators from MATI.

  A client to fetch Indicator objects from the MATI API
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize an IndicatorsClient from a ThreatIntelClient.

    Initialize a new IndicatorsClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get(
      self, identifier: str
  ) -> Union[FQDNIndicator, URLIndicator, IPIndicator, MD5Indicator]:
    """Get an Indicator object from a given identifier.

    Get a single Indicator object from the MATI API

    Args:
      identifier: The UUID of the Indicator to retrieve

    Returns:
      An Indicator object (FQDNIndicator, URLIndicator, IPIndicator, or
      MD5Indicator)
    """
    params = {
      "include_campaigns": True, 
      "include_reports": True, 
      "include_threat_rating": True,
      "include_misp": False,
      "include_category": True
    }
    indicator_api_response = self.get_raw(identifier, params=params)
    return create_indicator(indicator_api_response, self._base_client)

  def get_from_value(
      self, value: str
  ) -> Union[FQDNIndicator, URLIndicator, IPIndicator, MD5Indicator]:
    """Get an Indicator object from a given value.

    Get a single Indicator object from the MATI API based on the provided
    value

    Args:
      value: The value of the Indicator to retrieve

    Returns:
      An Indicator object (FQDNIndicator, URLIndicator, IPIndicator, or
      MD5Indicator)
    """
    request_body = {
        "requests": [{"values": [value]}],
        "include_campaigns": True,
        "include_reports": True,
        "include_threat_rating": True,
        "include_misp": False,
        "include_category": True
    }
    indicator_api_response = self._base_client.make_post_request(
        API_INDICATOR_ROOT, json=request_body
    )

    if indicator_api_response is None:
      return

    return create_indicator(
        indicator_api_response.get("indicators")[0], self._base_client
    )

  def get_list(
      self,
      minimum_mscore: int = 0,
      exclude_osint: bool = False,
      start_epoch: datetime.datetime = datetime.now(),
      end_epoch: datetime.datetime = None,
      page_size: int = 1000,
      **kwargs,
  ) -> Generator[
      Union[FQDNIndicator, URLIndicator, IPIndicator, MD5Indicator],
      None,
      None,
  ]:
    """Get all Indicators from MATI that meet the specified criteria.

    Args:
      minimum_mscore: A minimum 'mscore', or 'confidence'.
      exclude_osint: If True, then exclude Open Source Intelligence from results
      start_epoch: A datetime object representing the start of the time range
      end_epoch: An optional datetime object representing the end of the time
        range to retrieve.  Defaults to "now"
      page_size: The number of results to retrieve from MATI per page.  Does not
        limit the total number of results to retrieve

    Yields:
      An Indicator object (FQDNIndicator, URLIndicator, IPIndicator, or
      MD5Indicator)
    """
    params = {
        "gte_mscore": minimum_mscore,
        "exclude_osint": exclude_osint,
        "start_epoch": int(start_epoch.timestamp()),
        "limit": page_size,
        "include_campaigns": True,
        "include_reports": True,
        "include_threat_rating": True,
        "include_misp": False,
        "include_category": True
    }

    if end_epoch:
      params["end_epoch"] = int(end_epoch.timestamp())

    # Using 'dict.update()' for compatibility with Python 3.8
    params.update(kwargs)

    while True:
      api_response = self._base_client.make_get_request(
          API_INDICATOR_ROOT, params=params
      )

      if not api_response:
        break

      indicators_from_api = api_response.get("indicators", [])
      for indicator in indicators_from_api:
        yield create_indicator(indicator, self._base_client)

      if not api_response.get("next") or len(indicators_from_api) != page_size:
        break

      params = {"next": api_response.get("next"), "include_campaigns": True}

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
      params: typing.Optional[dict[str, str]] = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MATI Indicators endpoint.

    Make a GET request against a specific Indicators endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the indicator to retrieve
      url_suffix: The specific endpoint to query (e.g. /reports)
      content_type: A str to be passed as the `Accept` header of the request
      params: A dict containing optional URL Query Parameters

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes object
    """
    if not content_type:
      content_type = "application/json"

    if not params:
      params = {}

    endpoint = f"{API_INDICATOR_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(
        endpoint, headers=headers, params=params
    )


class CampaignsClient:
  """A client for fetching information about Campaigns from MATI.

  A client to fetch Campaign objects from the MATI API
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a CampignsClient from a ThreatIntelClient.

    Initialize a new CampignsClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get(self, identifier: str) -> Campaign:
    """Get an Campaign object from a given identifier.

    Get a single Campaign object from the MATI API

    Args:
      identifier: The ID or Short Name of the Campaign to retrieve

    Returns:
      A Campaign object
    """
    campaigns_api_response = self.get_raw(identifier)
    return Campaign.from_json_response(
        campaigns_api_response, self._base_client
    )

  def get_list(
      self,
      start_date: datetime.datetime = datetime.now(),
      end_date: datetime.datetime = None,
      page_size: int = 1000,
  ) -> Generator[Campaign, None, None]:
    """Get all Campaigns from MATI that meet the specified criteria.

    Args:
      start_date: A datetime object representing the start of the time range
      end_date: An optional datetime object representing the end of the time
        range to retrieve.  Defaults to "now"
      page_size: The number of results to retrieve from MATI per page.  Does not
        limit the total number of results to retrieve

    Yields:
      A Campaign object
    """
    params = {
        "start_date": start_date.date().isoformat(),
        "limit": page_size,
        "offset": 0,
    }
    if end_date:
      params["end_date"] = end_date.date().isoformat()

    while True:
      api_response = self._base_client.make_get_request(
          API_CAMPAIGN_ROOT, params=params
      )

      if not api_response:
        break

      campaigns_from_api = api_response.get("campaigns", [])
      for campaign in campaigns_from_api:
        yield Campaign.from_json_response(campaign, self._base_client)

      if len(campaigns_from_api) != page_size:
        break

      params["offset"] = params["offset"] + page_size

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MATI Campaign endpoint.

    Make a GET request against a specific Campaign endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the campaign to retrieve
      url_suffix: The specific endpoint to query (e.g. /reports)
      content_type: A str to be passed as the `Accept` header of the request

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes object
    """
    if not content_type:
      content_type = "application/json"

    endpoint = f"{API_CAMPAIGN_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(endpoint, headers=headers)


class DTMAlertsClient:
  """A client for retrieving and updating DTM Alerts in MATI.

  A client for retrieving and updating DTM Alerts in MATI
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a DTMAlertsClient from a ThreatIntelClient.

    Initialize a new DTMAlertsClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get_list(
      self,
      sort: str = "created_at",
      order: str = "desc",
      size: int = 10,
      monitor_id: Optional[typing.List[str]] = None,
      since: Optional[datetime.datetime] = None,
      until: Optional[datetime.datetime] = None,
      status: Optional[Union[str, typing.List[str]]] = None,
      search: Optional[str] = None,
      tags: Optional[Union[str, typing.List[str]]] = None,
      sanitize: bool = False,
      mscore_gte: int = 0,
  ) -> typing.Generator[DTMAlert, None, None]:
    """Get all DTM alerts meeting the specified criteria.

    Args:
      sort: The field name to sort alerts by.
      order: The order used to sort the response alert fields by.
      size: The number of alerts to retrieve per page.
      monitor_id: A list of monitor IDs to filter on.
      since: If specified, defines the starting date.
      until: If specified, defines the ending date.
      status: One or many statuses to filter by.
      search: A Lucene search query.
      tags: One or many tags to filter by.
      sanitize: If True, strips HTML content from the alert
      mscore_gte: Filter alerts by MScore
    """
    params = {
        "sort": sort,
        "order": order,
        "size": size,
        "monitor_id": monitor_id,
        "status": status,
        "search": search,
        "tags": tags,
        "sanitize": sanitize,
        "mscore_gte": mscore_gte,
    }

    if since:
      params["since"] = since.isoformat()

    if until:
      params["until"] = until.isoformat()

    endpoint = API_DTM_ALERTS_ROOT

    while True:
      api_response = self._base_client.make_get_request(
          endpoint, include_next=True, params=params
      )

      if not api_response:
        break

      alerts_from_api = api_response.get("alerts", [])

      for alert in alerts_from_api:
        yield DTMAlert.from_json_response(alert, self._base_client)

      if len(alerts_from_api) < size:
        break

      params = {}
      endpoint = api_response["page"]

  def get(self, alert_id: str) -> DTMAlert:
    """Retrieve a DTMAlert from DTM by ID.

    Args:
      alert_id: The ID of the alert to retrieve from DTM.

    Returns: A DTMAlert object
    """
    api_response = self.get_raw(alert_id)
    return DTMAlert.from_json_response(api_response, self._base_client)

  def update_alert(
      self,
      alert: DTMAlert,
      status: Optional[DTMAlertStatusEnum] = None,
      tags: Optional[typing.List[str]] = None,
  ) -> DTMAlert:
    """Update the status or tags of a DTMAlert.

    Args:
      alert: The DTMAlert to update
      status: A DTMAlertStatusEnum representing the new status
      tags: A list of strings representing new tags

    Returns: An updated DTMAlert object
    """
    endpoint = f"{API_DTM_ALERTS_ROOT}/{alert.id}"
    payload = dict()

    if status:
      payload["status"] = status.value

    if tags:
      payload["tags"] = tags

    if payload:
      api_response = self._base_client.make_patch_request(
          endpoint, json=payload
      )
      return DTMAlert.from_json_response(api_response, self._base_client)

    return alert

  def bulk_update_alerts(
      self, params_list: typing.List[tuple[DTMAlert, typing.Dict]]
  ):
    """Update the tags or status of multiple DTMAlerts at one time.

    Args:
      params_list: A list of tuples, in the form (DTMAlert, dict).  The dict
        should contain 'tags', 'status', or both.
    """
    payload = {"patch": []}
    for alert, params in params_list:
      alert_payload = {"id": alert.id}
      field_updated = False

      if params.get("status"):
        status_value = params.get("status")
        if isinstance(status_value, DTMAlertStatusEnum):
          status_value = status_value.value
        alert_payload["status"] = status_value
        field_updated = True
      if params.get("tags"):
        alert_payload["tags"] = params.get("tags")
        field_updated = True

      if field_updated:
        payload["patch"].append(alert_payload)

    self._base_client.make_post_request(
        f"{API_DTM_ALERTS_ROOT}/bulk", json=payload
    )

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MATI DTM Alerts endpoint.

    Make a GET request against a specific DTM Alert endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the alert to retrieve
      url_suffix: The specific endpoint to query (e.g. /reports)
      content_type: A str to be passed as the `Accept` header of the request

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes
    """
    if not content_type:
      content_type = "application/json"

    endpoint = f"{API_DTM_ALERTS_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(endpoint, headers=headers)


class DTMDocsClient:
  """A client for fetching information about DTM Documents from MATI.

  A client to fetch DTM Document objects from the MATI API
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a DTMDocsClient from a ThreatIntelClient.

    Initialize a new DTMDocsClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get(self, doc_type: DTMDocumentTypeEnum, doc_id: str) -> DTMDocument:
    """Retrive a single document from MDTM.

    Args:
        doc_type: The document type to retrieve
        doc_id: The ID of the document to retrieve

    Returns:
        A DTMDocument representing the requested document
    """
    api_response = self.get_raw(f"{doc_type.value}/{doc_id}")

    dtm_document = api_response["doc"]
    dtm_document["labels"] = api_response["labels"]
    dtm_document["topics"] = api_response["topics"]

    return DTMDocument.from_json_response(dtm_document, self._base_client)

  def search(
      self,
      query: str,
      size: typing.Optional[int] = None,
      since: typing.Optional[datetime.datetime] = None,
      until: typing.Optional[datetime.datetime] = None,
      doc_type: typing.Optional[
          typing.Union[typing.List[DTMDocumentTypeEnum], DTMDocumentTypeEnum]
      ] = None,
      sanitize: bool = False,
      threat_type: typing.Optional[typing.Union[typing.List[str], str]] = None,
  ) -> typing.Generator[DTMDocument, None, None]:
    """Search MDTM for matching Documents.

    Args:
        query: A search query in Lucene syntax
        size: Page size
        since: Search for documents since this time
        until: Search for documents before this time
        doc_type: One or more types of documents to search for
        sanitize: Whether to sanitize the results
        threat_type: One or more threat types to filter by

    Returns:
        A generator of DTMDocuments.
    """
    size = size or 25
    params = {"size": size, "sanitize": bool(sanitize)}

    if since:
      params["since"] = since.isoformat()
    if until:
      params["until"] = until.isoformat()
    if doc_type:
      params["doc_type"] = doc_type
    if threat_type:
      params["threat_type"] = threat_type

    body = {"query": query}

    output = []

    endpoint = f"{API_DTM_DOCS_ROOT}/search"
    while True:
      api_response = self._base_client.make_post_request(
          endpoint, params=params, json=body, include_next=True
      )

      output.extend(api_response["docs"])
      for doc in api_response["docs"]:
        yield DTMDocument.from_json_response(doc, self._base_client)

      if len(api_response["docs"]) < size:
        break
      else:
        params = {}
        endpoint = api_response["page"]

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MDTM Docs endpoint.

    Make a GET request against a specific MDTM Docs endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the campaign to retrieve
      url_suffix: The specific endpoint to query (e.g. /reports)
      content_type: A str to be passed as the `Accept` header of the request

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes
    """
    if not content_type:
      content_type = "application/json"

    endpoint = f"{API_DTM_DOCS_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(endpoint, headers=headers)


class DTMMonitorsClient:
  """A client for fetching information about DTM Monitors from MATI.

  A client to fetch DTM Monitor objects from the MATI API
  """

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a DTMMonitorsClient from a ThreatIntelClient.

    Initialize a new DTMMonitorsClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get_list(
      self,
      sort: str = "created_at",
      order: str = "desc",
      size: int = 10,
      since: typing.Optional[datetime] = None,
      until: typing.Optional[datetime] = None,
  ) -> typing.Generator[DTMMonitor, None, None]:
    """Retrieve all DTMMonitors meeting the specified conditions.

    Args:
        sort: Field name to sort monitors by
        order: Direction to sort selected field by
        size: Number of monitors to return per page
        since: Only show monitors since this date
        until: Only show monitors before this date
    """
    params = {
        "sort": sort,
        "order": order,
        "size": size,
    }

    if since:
      params["since"] = since.isoformat()
    if until:
      params["until"] = until.isoformat()

    endpoint = API_DTM_MONITORS_ROOT
    while True:
      api_response = self._base_client.make_get_request(
          endpoint, params=params, include_next=True
      )

      if not api_response:
        break

      monitors_from_api = api_response.get("monitors", [])
      for monitor in monitors_from_api:
        yield DTMMonitor(**monitor)

      if len(monitors_from_api) != size:
        break

      params = {}
      endpoint = api_response["page"]

  def get(self, monitor_id: str) -> DTMMonitor:
    """Retrieve and return a single monitor by ID.

    Args:
        monitor_id: ID of the monitor to return
    """
    return DTMMonitor(**self.get_raw(monitor_id))

  def delete(self, monitor: DTMMonitor):
    """Delete a specified DTMMonitor.

    Args:
        monitor: The DTMMonitor to delete
    """
    self._base_client.make_delete_request(
        f"{API_DTM_MONITORS_ROOT}/{monitor.id}"
    )

  def patch(self, monitor_id: str, update: typing.Dict) -> DTMMonitor:
    """Update one or more fields in a monitor.

    Args:
        monitor_id: The ID of the monitor to update
        update: A dictionary containing fields to update

    Returns:
        An updated DTMMonitor object
    """
    endpoint = f"{API_DTM_MONITORS_ROOT}/{monitor_id}"
    updated_monitor = self._base_client.make_patch_request(endpoint, update)

    return DTMMonitor(**updated_monitor)

  def update(self, monitor: DTMMonitor) -> DTMMonitor:
    """Update a DTMMonitor object.

    Args:
        monitor: The updated monitor

    Returns:
        An updated DTMMonitor object
    """
    _updatable_fields = [
        "description",
        "doc_condition",
        "email_notify_enabled",
        "email_notify_immediate",
        "enabled",
        "name",
    ]

    update_body = {
        k: v
        for k, v in dataclasses.asdict(monitor).items()
        if k in _updatable_fields
    }

    update_body["doc_condition"] = update_body["doc_condition"].json()

    endpoint = f"{API_DTM_MONITORS_ROOT}/{monitor.id}"

    headers = self._base_client.headers
    headers["accept"] = "application/json"

    response = self._base_client.make_put_request(
        endpoint, json=update_body, headers=headers
    )

    return DTMMonitor(**response)

  def create(
      self,
      description: typing.Optional[str],
      doc_condition: DTMMonitorCondition,
      email_notify_enabled: bool,
      email_notify_immediate: bool,
      enabled: bool,
      name: str,
  ) -> DTMMonitor:
    """Create a new DTMMonitor.

    Args:
        description: The optional description
        doc_condition: A DTMMonitorCondition
        email_notify_enabled: If e-mail notifications are enabled
        email_notify_immediate: If immediate e-mail notifications are enabled
        enabled: If the monitor is enabled
        name: The name of the monitor

    Returns:
        A new DTMMonitor
    """
    api_response = self._base_client.make_post_request(
        API_DTM_MONITORS_ROOT,
        json={
            "description": description,
            "doc_condition": doc_condition.json(),
            "email_notify_enabled": email_notify_enabled,
            "email_notify_immediate": email_notify_immediate,
            "enabled": enabled,
            "name": name,
        },
    )

    return DTMMonitor(**api_response)

  def get_raw(
      self,
      identifier: str,
      url_suffix: str = "",
      content_type: typing.Optional[str] = None,
  ) -> Union[dict[str, typing.Any], str, bytes]:
    """Make a raw GET request against the MDTM Monitors endpoint.

    Make a GET request against a specific MDTM Monitors endpoint, and retrieve
    the response as an object

    Args:
      identifier: The unique identifier of the monitor to retrieve
      url_suffix: The specific endpoint to query (e.g. /reports)
      content_type: A str to be passed as the `Accept` header of the request

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str,
      dict, or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of
      the HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a
      bytes
    """
    if not content_type:
      content_type = "application/json"

    endpoint = f"{API_DTM_MONITORS_ROOT}/{identifier}{url_suffix}"

    headers = self._base_client.headers

    headers["Accept"] = content_type

    return self._base_client.make_get_request(endpoint, headers=headers)


class DTMEmailSettingsClient:

  def __init__(self, base_client: ThreatIntelClient):
    """Initialize a DTMEmailSettingsClient from a ThreatIntelClient.

    Initialize a new DTMEmailSettingsClient using a provided ThreatIntelClient

    Args:
      base_client: A ThreatIntelClient instance
    """
    self._base_client: ThreatIntelClient = base_client
    return

  def get_settings(self) -> DTMEmailSettings:
    """Returns a DTMEmailSettings object representing the current e-mail configuration."""
    api_response = self._base_client.make_get_request(
        API_DTM_EMAIL_SETTINGS_ROOT
    )
    settings = api_response["email_settings"][0]

    return DTMEmailSettings(**settings)

  def get(self, settings_id: typing.Optional[str] = None) -> DTMEmailSettings:
    """Returns a DTMEmailSettings object representing the e-mail configuration specified by the ID.

    Args:
        settings_id: The ID of the e-mail settings to retrieve
    """
    if not settings_id:
      return self.get_settings()

    endpoint = f"{API_DTM_EMAIL_SETTINGS_ROOT}/{settings_id}"

    api_response = self._base_client.make_get_request(endpoint)

    return DTMEmailSettings(**api_response)

  def delete(self, settings_id: str):
    """Delete a DTMEmailSettings configuration from DTM.

    Args:
        settings_id: The ID of e-mail settings to delete
    """
    endpoint = f"{API_DTM_EMAIL_SETTINGS_ROOT}/{settings_id}"

    self._base_client.make_delete_request(endpoint)

  def update(self, settings: DTMEmailSettings) -> DTMEmailSettings:
    """Update DTMEmailSettings.

    Args:
        settings: The updated DTMEmailSettings

    Returns:
        An updated DTMEmailSettings object.
    """
    endpoint = f"{API_DTM_EMAIL_SETTINGS_ROOT}/{settings.id}"

    api_response = self._base_client.make_patch_request(
        endpoint, json=settings.json()
    )

    return DTMEmailSettings(**api_response)

  def reverify(
      self, settings_id: str, recipients: typing.Union[str, typing.List[str]]
  ) -> DTMEmailSettings:
    """Force one or more users to re-verify their e-mail addresses.

    Args:
        settings_id: The ID of the settings to update
        recipients: The recipient e-mails to re-verify

    Returns:
        An updated DTMEmailSettings object
    """
    if isinstance(recipients, str):
      recipients = [recipients]

    endpoint = f"{API_DTM_EMAIL_SETTINGS_ROOT}/{settings_id}"
    post_body = {"recipients": recipients}

    api_response = self._base_client.make_patch_request(
        endpoint, json=post_body
    )

    return DTMEmailSettings(**api_response)


class ThreatIntelClient:
  """The base API client class for Mandiant Advantage Threat Intelligence.

  Base API client class for MATI.  Provides functionality for getting and
  refreshing API Bearer Tokens, as well as for making GET and POST requests.

  Attributes:
    token: A string containing a Bearer Token for the MATI API
    headers: A dictionary containing the default headers for MATI API requests
    ThreatActors: A mandiant_threatintel.ThreatIntelClient.ThreatActorsClient
      client, using the API information contained within the parent
      ThreatIntelClient object
    Reports: A mandiant_threatintel.ThreatIntelClient.ReportsClient client,
      using the API information contained within the parent ThreatIntelClient
      object
    Malware: A mandiant_threatintel.ThreatIntelClient.MalwareClient client,
      using the API information contained within the parent ThreatIntelClient
      object
    Vulnerabilities: A
      mandiant_threatintel.ThreatIntelClient.VulnerabilityClient client, using
      the API information contained within the parent ThreatIntelClient object
      Indicators A mandiant_threatintel.ThreatIntelClient.IndicatorsClient
      client, using the API information contained within the parent
      ThreatIntelClient object
  """

  def __init__(
      self,
      api_key: str = None,
      secret_key: str = None,
      bearer_token: str = None,
      api_base_url: str = API_BASE_URL,
      client_name: str = CLIENT_APP_NAME,
      request_timeout: int = 5,
      proxy_config: dict = None,
  ):
    """Initialize a ThreatIntelClient with either an API and Secret Key or Bearer Token.

    Initialize a new ThreatIntelClient using either an API and Secret Key pair,
    or a user-provided bearer token.

    Args:
      api_key: A str containing the API Key for MATI. Optional if `bearer_token`
        is provided
      secret_key: A str containing the matching Secret Key for the provided
        `api_key`. Optional if `bearer_token` is provided
      bearer_token: A str containing a pre-retrieved Bearer Token. Optional if
        both `api_key` and `secret_key` are provided
      api_base_url: A str containing the API Base URL
      client_name: A str containing the value to be passed as the X-App-Name
        header
      request_timeout: An integer representation of the number of seconds to
        wait before timing out
      proxy_config: A dictionary containing the python-requests proxy
        configuration
    """

    self._api_base: str = api_base_url
    self._client_app_name: str = client_name
    self._request_timeout: int = request_timeout
    self._request_session: requests.Session = requests.Session()

    if proxy_config:
      self._request_session.proxies.update(proxy_config)

    self._bearer_token_exp: int = None
    if not bearer_token:
      if not api_key or not secret_key:
        raise ValueError(
            "api_key and secret_key must be specified"
            " if bearer_token is not specified"
        )

      # Load API Key and Secret Key into memory for future use when fetching
      # bearer tokens.  These will be required if the current token expires,
      # so we _do_ need to save them
      self._api_key = api_key
      self._secret_key = secret_key

      self._bearer_token, self._bearer_token_exp = self.fetch_bearer_token()
      return

    # If a user provided only a Bearer Token, rather than the
    # API Key and Secret Key, then leave the _bearer_token_exp field as
    # None to prevent any attempt to verify the expiration
    self._bearer_token = bearer_token
    self._api_key = None
    self._secret_key = None
    return

  @retry(
      retry=retry_if_exception(exception_is_retryable),
      wait=wait_exponential(multiplier=1, min=4, max=10),
      stop=stop_after_attempt(3),
  )
  def make_get_request(
      self,
      endpoint: str,
      headers: dict[str, str] = None,
      include_next: bool = False,
      **kwargs,
  ) -> Union[dict[str, typing.Any], str, bytes, None]:
    """Makes an HTTP GET request against the MATI API.

    Makes an HTTP GET request against the specified MATI API endpoint.

    Args:
      endpoint: A string containing the API endpoint (not including the `/v4`
        prefix)
      headers: An optional dict containing HTTP request headers.  If not
        specified, defaults to `ThreatIntelClient.headers`
      include_next: An optional boolean parameter that causes the value of the
        'links'.'next' to be injected into the JSON response
      **kwargs: Arbitrary keyword arguments to be passed to `requests.get`

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str, dict,
      or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of the
      HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a bytes
      object

    Raises:
      requests.exceptions.HTTPError: An error occurred accessing the MATI API
    """
    url = urllib.parse.urljoin(self._api_base, endpoint)

    if not headers:
      headers = self.headers

    response = self._request_session.get(
        url, headers=headers, timeout=self._request_timeout, **kwargs
    )
    response.raise_for_status()

    response_type = response.headers.get("content-type", [])

    if response.status_code == 204:
      return None

    if "application/json" in response_type:
      response_data = response.json()
      if include_next:
        response_data["page"] = response.links["next"]["url"]
      return response_data
    elif "text/html" in response_type:
      return response.text
    else:
      return response.content

  @retry(
      retry=retry_if_exception(exception_is_retryable),
      wait=wait_exponential(multiplier=1, min=4, max=10),
      stop=stop_after_attempt(3),
  )
  def make_post_request(
      self,
      endpoint: str,
      headers: dict[str, str] = None,
      include_next: bool = False,
      **kwargs,
  ) -> Union[dict[str, typing.Any], str, bytes] or None:
    """Makes an HTTP POST request against the MATI API.

    Makes an HTTP POST request against the specified MATI API endpoint.

    Args:
      endpoint: A string containing the API endpoint (not including the `/v4`
        prefix)
      headers: An optional dict containing HTTP request headers.  If not
        specified, defaults to `ThreatIntelClient.headers`
      **kwargs: Arbitrary keyword arguments to be passed to `requests.post`

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str, dict,
      or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of the
      HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a bytes
      object

    Raises:
      requests.exceptions.HTTPError: An error occurred accessing the MATI API
    """
    url = urllib.parse.urljoin(self._api_base, endpoint)

    if not headers:
      headers = self.headers

    response = self._request_session.post(
        url, headers=headers, timeout=self._request_timeout, **kwargs
    )
    response.raise_for_status()

    if response.status_code == 204:
      return None

    response_type = response.headers.get("content-type", [])
    if "application/json" in response_type:
      response_data = response.json()
      if include_next:
        response_data["page"] = response.links["next"]["url"]
      return response_data
    elif "text/html" in response_type:
      return response.text
    else:
      return response.content

  @retry(
      retry=retry_if_exception(exception_is_retryable),
      wait=wait_exponential(multiplier=1, min=4, max=10),
      stop=stop_after_attempt(3),
  )
  def make_put_request(
      self,
      endpoint: str,
      headers: dict[str, str] = None,
      include_next: bool = False,
      **kwargs,
  ) -> Union[dict[str, typing.Any], str, bytes] or None:
    """Makes an HTTP PUT request against the MATI API.

    Makes an HTTP PUT request against the specified MATI API endpoint.

    Args:
      endpoint: A string containing the API endpoint (not including the `/v4`
        prefix)
      headers: An optional dict containing HTTP request headers.  If not
        specified, defaults to `ThreatIntelClient.headers`
      **kwargs: Arbitrary keyword arguments to be passed to `requests.post`

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str, dict,
      or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of the
      HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a bytes
      object

    Raises:
      requests.exceptions.HTTPError: An error occurred accessing the MATI API
    """
    url = urllib.parse.urljoin(self._api_base, endpoint)

    if not headers:
      headers = self.headers

    print(kwargs["json"])

    response = self._request_session.put(
        url, headers=headers, timeout=self._request_timeout, **kwargs
    )

    print(response.text)

    response.raise_for_status()

    if response.status_code == 204:
      return None

    response_type = response.headers.get("content-type", [])
    if "application/json" in response_type:
      response_data = response.json()
      if include_next:
        response_data["page"] = response.links["next"]["url"]
      return response_data
    elif "text/html" in response_type:
      return response.text
    else:
      return response.content

  @retry(
      retry=retry_if_exception(exception_is_retryable),
      wait=wait_exponential(multiplier=1, min=4, max=10),
      stop=stop_after_attempt(3),
  )
  def make_patch_request(
      self, endpoint: str, headers: dict[str, str] = None, **kwargs
  ) -> Union[dict[str, typing.Any], str, bytes] or None:
    """Makes an HTTP PATCH request against the MATI API.

    Makes an HTTP PATCH request against the specified MATI API endpoint.

    Args:
      endpoint: A string containing the API endpoint (not including the `/v4`
        prefix)
      headers: An optional dict containing HTTP request headers.  If not
        specified, defaults to `ThreatIntelClient.headers`
      **kwargs: Arbitrary keyword arguments to be passed to `requests.patch`

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str, dict,
      or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of the
      HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a bytes
      object

    Raises:
      requests.exceptions.HTTPError: An error occurred accessing the MATI API
    """
    url = urllib.parse.urljoin(self._api_base, endpoint)

    if not headers:
      headers = self.headers

    response = self._request_session.patch(
        url, headers=headers, timeout=self._request_timeout, **kwargs
    )
    response.raise_for_status()

    if response.status_code == 204:
      return None

    response_type = response.headers.get("content-type", [])
    if "application/json" in response_type:
      return response.json()
    elif "text/html" in response_type:
      return response.text
    else:
      return response.content

  @retry(
      retry=retry_if_exception(exception_is_retryable),
      wait=wait_exponential(multiplier=1, min=4, max=10),
      stop=stop_after_attempt(3),
  )
  def make_delete_request(
      self, endpoint: str, headers: dict[str, str] = None, **kwargs
  ) -> Union[dict[str, typing.Any], str, bytes] or None:
    """Makes an HTTP DELETE request against the MATI API.

    Makes an HTTP DELETE request against the specified MATI API endpoint.

    Args:
      endpoint: A string containing the API endpoint (not including the `/v4`
        prefix)
      headers: An optional dict containing HTTP request headers.  If not
        specified, defaults to `ThreatIntelClient.headers`
      **kwargs: Arbitrary keyword arguments to be passed to `requests.patch`

    Returns:
      Depending on the `content-type` header of the HTTP Response, a str, dict,
      or bytes object can be returned.

      If the response `content-type` is `application/json`, the contents of the
      HTTP response body are parsed into a dict and returned

      If the response `content-type` is `text/html`, the contents of the HTTP
      response body are returned as a str

      Otherwise, the contents of the HTTP response body are returned as a bytes
      object

    Raises:
      requests.exceptions.HTTPError: An error occurred accessing the MATI API
    """
    url = urllib.parse.urljoin(self._api_base, endpoint)

    if not headers:
      headers = self.headers

    response = self._request_session.delete(
        url, headers=headers, timeout=self._request_timeout, **kwargs
    )
    response.raise_for_status()

    if response.status_code == 204:
      return None

    response_type = response.headers.get("content-type", [])
    if "application/json" in response_type:
      return response.json()
    elif "text/html" in response_type:
      return response.text
    else:
      return response.content

  def fetch_bearer_token(self) -> Tuple[str, int]:
    """Fetch a new Bearer Token from the MATI API.

    Make a POST request against the Authentication endpoint to retrieve a new
    Bearer Token for use with the MATI API.

    Returns:
        A tuple (bearer_token, token_expiration), where bearer_token is a str
        containing an API Bearer Token for the MATI API, and token_expiration is
        an int containing the expiration date of the token (in the form of
        seconds-from-epoch)

    Raises:
      ValueError: An exception occurred when attempting to retrieve a Bearer
      Token
    """

    if not self._api_key or not self._secret_key:
      raise ValueError(
          "Cannot fetch bearer token without api_key and secret_key"
      )

    headers = {"Accept": "application/json"}
    form_data = {"grant_type": "client_credentials"}
    auth_response = self.make_post_request(
        API_AUTHENTICATION_PATH,
        headers=headers,
        data=form_data,
        auth=(self._api_key, self._secret_key),
    )

    bearer_token_exp = int(datetime.now().timestamp()) + int(
        auth_response["expires_in"]
    )

    return auth_response["access_token"], bearer_token_exp

  @property
  def token(self) -> str:
    """A str containing a Bearer Token for the MATI API.

    If the token is expired, a new token will be fetched from the API.
    Otherwise, the stored token is returned
    """
    if self._bearer_token_exp is None:
      # If we don't have an expiration set for the token, then the token was
      # manually provided by the user and cannot be refreshed/renewed
      return self._bearer_token

    current_timestamp = datetime.now().timestamp()

    if current_timestamp >= self._bearer_token_exp:
      # If the token has expired, retrieve a new token and update the expiration
      self._bearer_token, self._bearer_token_exp = self.fetch_bearer_token()

    return self._bearer_token

  @property
  def headers(self) -> dict[str, str]:
    """A dict containing a default set of headers to use in API requests."""
    return {
        "Authorization": f"Bearer {self.token}",
        "Accept": "application/json",
        "X-App-Name": self._client_app_name,
    }

  @property
  def ThreatActors(self) -> ThreatActorsClient:
    """A ThreatActorsClient, initialized using the parent ThreatIntelClient."""
    return ThreatActorsClient(base_client=self)

  @property
  def Reports(self) -> ReportsClient:
    """A ReportsClient, initialized using the parent ThreatIntelClient."""
    return ReportsClient(base_client=self)

  @property
  def Malware(self) -> MalwareClient:
    """A MalwareClient, initialized using the parent ThreatIntelClient."""
    return MalwareClient(base_client=self)

  @property
  def Vulnerabilities(self) -> VulnerabilityClient:
    """A VulnerabilityClient, initialized using the parent ThreatIntelClient."""
    return VulnerabilityClient(base_client=self)

  @property
  def Indicators(self) -> IndicatorsClient:
    """An IndicatorsClient, initialized using the parent ThreatIntelClient."""
    return IndicatorsClient(base_client=self)

  @property
  def Campaigns(self) -> CampaignsClient:
    """A CampaignsClient, initialized using the parent ThreatIntelClient."""
    return CampaignsClient(base_client=self)

  @property
  def DTMAlerts(self) -> DTMAlertsClient:
    return DTMAlertsClient(base_client=self)

  @property
  def DTMDocs(self) -> DTMDocsClient:
    return DTMDocsClient(base_client=self)

  @property
  def DTMMonitors(self) -> DTMMonitorsClient:
    return DTMMonitorsClient(base_client=self)

  @property
  def DTMEmailSettings(self) -> DTMEmailSettingsClient:
    return DTMEmailSettingsClient(base_client=self)


class APIResponse:
  """A base API Response class with lazy-loading of data from the MATI API.

  A base API Response class that implements lazy-loading of attributes in order
  to minimize the number of unnecessary API calls
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "paginated: PaginationTypeEnum.NEXT,
      #   "content-type": "application/json",
      #   "preparser": lambda _: _, # For a Paginated data field, must accept a
      # list of dicts and return a single dict
      #   "postparser": lambda _: _,
      # },
  }
  _IDENTIFIER_FIELDS = ["id"]  # First field is the default

  def __init__(self, client: ThreatIntelClient, **kwargs):
    """Initialize an APIResponse object."""
    self._client = client

    # Create the API Response from the JSON data if available
    if kwargs.get("response") is not None:
      self._api_response = kwargs.get("response")

      # Locate the identifier field, and set it in the default identifier field
      # for use later
      if self._identifier is None:
        raise ValueError(f'Response must contain "{self._id_field}" field')

    elif kwargs.get("identifier") is not None:
      self._api_response = {self._id_field: kwargs.get("identifier")}

    else:
      raise ValueError("Must provide either response or identifier")

  @classmethod
  def from_json_response(
      cls, response: dict[str, typing.Any], client: ThreatIntelClient
  ) -> APIResponse:
    """Return an APIResponse from the provided response.

    Args:
      response: A dictionary containing the MATI API response
      client: The ThreatIntelClient to use to fetch attribute data

    Returns:
      An APIResponse object
    """
    return cls(client=client, response=response)

  @classmethod
  def from_identifier(
      cls, identifier: str, client: ThreatIntelClient
  ) -> APIResponse:
    """Return an APIResponse from the provided identifier.

    Args:
      identifier: A string containing a unique identifier
      client: The ThreatIntelClient to use to fetch attribute data

    Returns:
      An APIResponse object
    """
    return cls(client=client, identifier=identifier)

  def __getattr__(self, item) -> typing.Any:
    """Get an attribute of the API Response object.

    Args:
      item: A string containing the attribute name to retrieve

    Returns:
      An object representing the value of the attribute
    """

    # Verify that the attribute is part of the object
    if item not in self._QUERY_MAP:
      raise AttributeError(
          f"'{self.__class__.__name__}' object has no attribute '{item}'"
      )

    field_names = self._QUERY_MAP[item].get("field", item)
    if isinstance(field_names, str):
      field_names = [field_names]

    field_value = None
    try:
      field_value = get_field_from_response(self._api_response, field_names)
    except ValueError:
      pagination_mode = self._QUERY_MAP[item].get("paginated")

      api_data = self._get_subclient().get_raw(
          self._identifier,
          self._QUERY_MAP[item].get("api_path", ""),
          self._QUERY_MAP[item].get("content-type"),
      )

      if pagination_mode == PaginationTypeEnum.NEXT:
        current_page = api_data
        api_data = [api_data]
        while current_page.get("next") is not None:
          current_page = self._get_subclient().get_raw(
              self._identifier,
              self._QUERY_MAP[item].get("api_path", ""),
              self._QUERY_MAP[item].get("content-type"),
              params={"next": current_page.get("next")},
          )
          api_data.append(current_page)
      preparser = self._QUERY_MAP[item].get("preparser", lambda _: _)

      self._api_response.update(preparser(api_data))
      try:
        field_value = get_field_from_response(self._api_response, field_names)
      except ValueError:
        # TODO: Consult with MATI team to determine correct approach -
        #       Either separate Report classes per Report Type,
        #       or some sort of default/fallback value if attribute is absent
        self._api_response[field_names[0]] = None
        return None
        # raise AttributeError(f'Could not retrieve attribute {item} from API')

    postparser = self._QUERY_MAP[item].get("postparser", lambda _, client: _)

    if field_value is None:
      return None

    return postparser(field_value, self._client)

  def __dir__(self):
    """Return a list of attributes based on the query map."""
    return list(self._QUERY_MAP.keys()) + super().__dir__()

  def _get_subclient(self):
    """Get API SubClient for the given API object."""
    raise NotImplementedError()

  @property
  def _id_field(self) -> str:
    """Get the default identifier field."""
    return self._IDENTIFIER_FIELDS[0]

  @property
  def _identifier(self) -> typing.Optional[str]:
    identifier = None
    for i in self._IDENTIFIER_FIELDS:
      if self._api_response.get(i) is not None:
        identifier = self._api_response.get(i)
        self._api_response[self._id_field] = identifier
        break
    return identifier


class Malware(APIResponse):
  """An APIResponse object representing a Malware Family.

  An APIResponse object representing a Malware Family from the MATI API.

  Attributes:
    actors: A list of associated ThreatActors
    audience: A list of Audiences
    description: A description of the Malware Family
    detections: A list of detections
    id: The MATI Malware Family UUID
    industries: A list of targeted industries
    inherently_malicious: A boolean indicating if the object is inherently
      malicious
    last_activity_time: A datetime object indicating the last observed activity
      time
    last_updated: A datetime object indicating the last update
    malware: A list of associated Malware objects
    name: The name of the Malware Family
    operating_systems: A list containing the impacted Operating System Families
    yara: A list containing the YARA data
    is_publishable: A boolean indicating if this information can be published
    intel_free: A boolean indicating if this information is available for free
    aliases: A list of known or suspected aliases
    capabilities: A list of known capabilities
    cve: A list of associated Vulnerabilities
    roles: A list of associated Roles
    reports: A list of associated Reports
    attack_patterns: A list of associated MITRE ATT&CK Patterns
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "actors": {},
      "audience": {
          "postparser": lambda _, client: (Audience.from_api(i) for i in _)
      },
      "description": {},
      "detections": {},
      "id": {},
      "industries": {},
      "inherently_malicious": {"postparser": lambda _, client: bool(_)},
      "last_activity_time": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "last_updated": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "malware": {},
      "name": {},
      "operating_systems": {},
      "type": {},
      "yara": {},
      "is_publishable": {},
      "intel_free": {},
      "aliases": {
          "postparser": lambda _, client: (Alias.from_api(i) for i in _)
      },
      "capabilities": {},
      "cve": {},
      "roles": {},
      "reports": {
          "api_path": "/reports",
          "postparser": lambda _, c: (
              Report.from_json_response(report, c) for report in _
          ),
      },
      "attack_patterns": {
          "api_path": "/attack-pattern",
          "preparser": parse_malware_attck_patterns,
      },
      "campaigns": {
          "api_path": "/campaigns",
          "postparser": lambda _, client: (
              Campaign.from_json_response(campaign, client) for campaign in _
          ),
      },
  }

  def _get_subclient(self):
    return self._client.Malware


class Report(APIResponse):
  """An APIResponse object representing a Report.

  An APIResponse object representing a Report from the MATI API.

  Attributes:
    report_id: The ID of the report
    title: The title of the report
    pdf: The PDF version of the report, in `bytes` form
    indicators: A list of associated Indicator objects
    report_type: The type of report
    document_type: The type of document
    type_of_report: The type of report
    version: The report version
    publish_date: A datetime representing the date of publication
    title_full_text: The full text of the title
    requester_org_id: The requester of the report
    related_reports: A list of related Report objects
    story_link: A URL pointing to an external publication
    delivery_option: A string indicating the delivery options
    outlet: The name of the external report source
    customer_sensitive: A boolean indicating if this report contains
      customer-sensitive information
    active: A boolean indicating if this report is active
    no_threat_scapes: A boolean indicating if there are no Threat Scapes
    from_media: A string indicating if this report is from the media
    threat_scape: A list of associated Threat Scapes
    tmh_accuracy_ranking: The TMH Accuracy Ranking
    tag_version: A string containing the Tag Version
    isight_comment: The ISight Comment for the report
    actors: A list of associated ThreatActors
    affected_industries: A list of affected industries
    affected_systems: A list of affected systems
    intended_effects: A list of intended effects
    motivations: A list of motivations
    source_geographies: A list of source geographies
    ttps: A list of TTPs
    target_geographies: A list of target geographies
    targeted_information: A list of targeted information
    relations: A list of relations
    files: A list of associated files
    cvss_base_score: The CVSS Base Score
    cvss_temporal_score: The CVSS Temporal Score
    zero_day: A boolean indicating if this contains a zero-day
    in_the_wild: A boolean indicating if this was observed in the wild
    report_confidence: The confidence level of the report
    version: The version of the report
    previous_versions: A list of dictionaries containing the previous versions
      of the report
    threat_detail: The details of the threat
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "report_id": {"field": "reportId"},
      "title": {},
      "pdf": {
          "content-type": "application/pdf",
          "preparser": lambda _: {"pdf": _},
      },
      "indicators": {
          "api_path": "/indicators",
          "paginated": PaginationTypeEnum.NEXT,
          "preparser": lambda _: {
              "indicators": [
                  i for page in _ for i in page.get("indicators", [])
              ]
          },
          "postparser": lambda _, client: (
              create_indicator(i, client) for i in _
          ),
      },
      "report_type": {"field": ["reportType", "report_type"]},
      "document_type": {"field": "documentType"},
      "type_of_report": {"field": "typeOfReport"},
      "publish_date": {
          "field": ["publishDate", "publish_date"],
          "postparser": lambda _, client: dateutil_parser.parse(_),
      },
      "title_full_text": {"field": "titleFullText"},
      "requester_org_id": {},
      "related_reports": {
          "field": "relatedReports",
          "postparser": lambda _, client: (
              Report.from_json_response(related_report, client)
              for related_report in _
          ),
      },
      "story_link": {"field": "storyLink"},
      "delivery_option": {"field": "deliveryOption"},
      "outlet": {},
      "customer_sensitive": {"field": "customerSensitive"},
      "active": {},
      "no_threat_scapes": {"field": "noThreatScapes"},
      "from_media": {"field": "fromMedia"},
      "threat_scape": {"field": "threatScape"},
      "tmh_accuracy_ranking": {"field": "tmhAccuracyRanking"},
      "tag_version": {"field": "tagVersion"},
      "isight_comment": {"field": "isightComment"},
      "actors": {
          "field": "tags",
          "postparser": lambda _, client: (
              ThreatActor.from_json_response(act, client)
              for act in _.get("actors", [])
          ),
      },
      "audience": {
          "postparser": lambda _, c: (Audience(name=name) for name in _)
      },
      "version_one_publish_date": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "threat_detail": {},
      "executive_summary": {},
      "affected_industries": {
          "field": "tags",
          "postparser": lambda _, c: _.get("affected_industries"),
      },
      "affected_systems": {
          "field": "tags",
          "postparser": lambda _, c: _.get("affected_systems"),
      },
      "intended_effects": {
          "field": "tags",
          "postparser": lambda _, c: _.get("intended_effects"),
      },
      "motivations": {
          "field": "tags",
          "postparser": lambda _, c: _.get("motivations"),
      },
      "malware_families": {
          "field": "tags",
          "postparser": lambda _, client: (
              Malware.from_json_response(mal, client)
              for mal in _.get("malware_families", [])
          ),
      },
      "source_geographies": {
          "field": "tags",
          "postparser": lambda _, c: _.get("source_geographies"),
      },
      "ttps": {"field": "tags", "postparser": lambda _, c: _.get("ttps")},
      "target_geographies": {
          "field": "tags",
          "postparser": lambda _, c: _.get("target_geographies"),
      },
      "targeted_informations": {
          "field": "tags",
          "postparser": lambda _, c: _.get("targeted_informations"),
      },
      "relations": {},
      "files": {},
      "cvss_base_score": {},
      "cvss_temporal_score": {},
      "zero_day": {},
      "in_the_wild": {},
      "report_confidence": {},
      "version": {},
      "previous_versions": {},
      "html": {"content-type": "text/html", "preparser": lambda _: {"html": _}},
  }

  _IDENTIFIER_FIELDS = ["reportId", "report_id"]  # First field is the default

  def _get_subclient(self):
    return self._client.Reports


class ThreatActor(APIResponse):
  """An APIResponse object representing a Threat Actor.

  An APIResponse object representing a Threat Actor from the MATI API.

  Attributes:
    id: The MATI Threat Actor UUID
    name: The name of the Threat Actor
    description: The description of the Threat Actor
    last_updated: A datetime representing the last update
    audience: A list of Audiences
    motivations: A list of Motivations associated with this Threat Actor
    aliases: A list of Aliases associated with this Threat Actor
    industries: A list of targeted industries
    observed: A list of observations
    malware: A list of associated Malware objects
    tools: A list of associated Tools (non-malicious Malware)
    locations: A list of source and target locations
    cve: A list of associated Vulnerabilities
    last_activity_time: A datetime representing the last observed activity
    suspected_attribution: A list of suspected attributions
    associated_uncs: A list of associated ThreatActors
    is_publishable: A boolean indicating if this information is publishable
    intel_free: A boolean indicating if this information is availabile for free
    reports: A list of associated Reports
    attack_patterns: A list of associated MITRE ATT&CK Patterns
    history: A list containing the observed history
    suspected_groups: A list containing the suspected groups
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "id": {},
      "name": {},
      "description": {},
      "type": {},
      "last_updated": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "audience": {
          "postparser": lambda _, client: (Audience.from_api(i) for i in _)
      },
      "motivations": {
          "postparser": lambda _, client: (Motivation.from_api(i) for i in _)
      },
      "aliases": {
          "postparser": lambda _, client: (Alias.from_api(i) for i in _)
      },
      "industries": {},
      "observed": {},
      "malware": {
          "postparser": lambda _, client: (
              Malware.from_json_response(m, client) for m in _
          )
      },
      "tools": {
          "postparser": lambda _, client: (
              Malware.from_json_response(m, client) for m in _
          )
      },
      "locations": {},
      "cve": {
          "postparser": lambda _, client: (
              Vulnerability.from_json_response(v, client) for v in _
          )
      },
      "last_activity_time": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "suspected_attribution": {},
      "associated_uncs": {
          "postparser": lambda _, client: (
              ThreatActor.from_json_response(unc, client) for unc in _
          )
      },
      "is_publishable": {},
      "intel_free": {},
      "reports": {
          "api_path": "/reports",
          "postparser": lambda _, client: (
              Report.from_json_response(report, client) for report in _
          ),
      },
      "attack_patterns": {
          "api_path": "/attack-pattern",
          "preparser": parse_threatactor_attck_patterns,
      },
      "history": {
          "api_path": "/history",
          "preparser": lambda _: {
              k: v for k, v in _.items() if k in ["history", "suspected_groups"]
          },
      },
      "suspected_groups": {
          "api_path": "/history",
          "preparser": lambda _: {
              k: v for k, v in _ if k in ["history", "suspected_groups"]
          },
      },
      "campaigns": {
          "api_path": "/campaigns",
          "postparser": lambda _, client: (
              Campaign.from_json_response(campaign, client) for campaign in _
          ),
      },
  }

  def _get_subclient(self):
    return self._client.ThreatActors


class Vulnerability(APIResponse):
  """An APIResponse object representing a Vulnerability.

  An APIResponse object representing a Vulnerability from the MATI API.

  Attributes:
    id: The Vulnerability UUID from MATI
    type: A string indicating tye type of object
    is_publishable: A boolean indicating if this information can be published
    risk_rating: A string indicting the assigned risk rating
    analysis: The analysis of the vulnerability
    executive_summary: An executive summary of the vulnerability
    description: A description of the vulnerability
    exploitation_vectors: A list of associated exploitation vectors
    title: The title of the vulnerability
    associated_actors: A list of associated Threat Actors
    associated_malware: A list of associated Malware Families
    associated_reports: A list of associated reports
    exploitation_consequences: The known consequences of exploitation
    vendor_fix_references: A list of vendor fixes for the vulnerability
    date_of_disclosure: A datetime indicating the date of disclosure
    observed_in_the_wild: A boolean indicating if this vulnerability has been
      observed in the wild
    vulnerable_cpes: A list of vulnerable CPEs
    was_zero_day: A boolean indicating if this vulnerability was a Zero Day
    workarounds: A list of workarounds
    publish_date: A datetime indicating the date of publication
    updated_date: A datetime indicating the date of update
    last_modified_date: A datetime indicating the date of last modification
    available_mitigation: A list of available mitigations
    sources: A list of sources
    exploits: A list of exploits
    common_vulnerability_scores: A dict containing the CVE score information
    audience: A list of associated Audiences
    intel_free: A boolean indicating if the information is available for free
    affects_ot: A boolean indicating if the vulnerability affects OT
    aliases: A list of known aliases
    cisa_known_exploited: A boolean indicating if CISA has observed exploitation
    cpe_ranges: A list of CPE ranges
    cwe_details: The CWE details
    days_to_patch: A string indicating the days to patch
    epss: A string containing the EPSS
    version_history: A list containing the version history
    workarounds_list: A list containing the workarounds
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "id": {},
      "type": {},
      "is_publishable": {},
      "risk_rating": {},
      "analysis": {},
      "executive_summary": {},
      "description": {},
      "exploitation_vectors": {},
      "title": {},
      "associated_actors": {
          "postparser": lambda _, client: (
              ThreatActor.from_json_response(a, client) for a in _
          )
      },
      "associated_malware": {
          "postparser": lambda _, client: (
              Malware.from_json_response(a, client) for a in _
          )
      },
      "associated_reports": {
          "postparser": lambda _, client: (
              Report.from_json_response(a, client) for a in _
          )
      },
      "exploitation_consequence": {},
      "cwe": {},
      "cve_id": {},
      "vulnerable_products": {},
      "exploitation_state": {},
      "vendor_fix_references": {},
      "date_of_disclosure": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "observed_in_the_wild": {},
      "vulnerable_cpes": {},
      "was_zero_day": {},
      "workarounds": {},
      "publish_date": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "updated_date": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "last_modified_date": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "available_mitigation": {},
      "sources": {},
      "exploits": {},
      "common_vulnerability_scores": {},
      "audience": {},
      "intel_free": {},
      "affects_ot": {},
      "aliases": {},
      "cisa_known_exploited": {},
      "cpe_ranges": {},
      "cwe_details": {},
      "days_to_patch": {},
      "epss": {},
      "version_history": {},
      "workarounds_list": {},
  }

  def _get_subclient(self):
    return self._client.Vulnerabilities


class MD5Indicator(APIResponse):
  """An APIResponse object representing an MD5 Indicator

  An APIResponse object representing an MD5 Indicator from the MATI API.

  Attributes:
    id: The MD5 UUID from MATI
    mscore: An int containing the confidence score (from 0 to 100)
    type: A string representing the type of Indicator
    value: The indicator value
    is_publishable: A boolean indicating if this information can be published
    sources: A list of sources
    misp: A dict containing the MISP information
    last_updated: A datetime indicating the last update time
    first_seen: A datetime indicating the first time the indicator was observed
    last_seen: A datetime indicating the most recent time the indicator was
      observed
    md5: A string containing the MD5 hash of the indicator
    sha1: A string containing the SHA1 hash of the indicator
    sha256: A string containing the SHA256 hash of the indicator
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "id": {},
      "mscore": {},
      "threat_rating": {},
      "category": {},
      "type": {},
      "value": {},
      "is_publishable": {},
      "sources": {},
      "misp": {},
      "last_updated": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "first_seen": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "last_seen": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "md5": {
          "field": "value",
      },
      "sha1": {
          "field": "associated_hashes",
          "postparser": lambda _, client: get_associated_hash(_, "sha1"),
      },
      "sha256": {
          "field": "associated_hashes",
          "postparser": lambda _, client: get_associated_hash(_, "sha256"),
      },
      "attributed_associations": {
          "postparser": lambda _, client: (
              create_attributed_association(assoc, client) for assoc in _
          )
      },
      "reports": {
          "api_path": "/reports",
          "postparser": lambda _, client: (
              Report.from_json_response(report, client) for report in _
          ),
      },
      "campaigns": {
          "postparser": lambda _, client: (
              Campaign.from_json_response(campaign, client) for campaign in _
          )
      },
  }

  def _get_subclient(self):
    return self._client.Indicators


class FQDNIndicator(APIResponse):
  """An APIResponse object representing an FQDN Indicator

  An APIResponse object representing an FQDN Indicator from the MATI API.

  Attributes:
    id: The FQDN UUID from MATI
    mscore: An int containing the confidence score (from 0 to 100)
    type: A string representing the type of Indicator
    value: The indicator value
    is_publishable: A boolean indicating if this information can be published
    sources: A list of sources
    misp: A dict containing the MISP information
    last_updated: A datetime indicating the last update time
    first_seen: A datetime indicating the first time the indicator was observed
    last_seen: A datetime indicating the most recent time the indicator was
      observed
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "id": {},
      "mscore": {},
      "threat_rating": {},
      "category": {},
      "type": {},
      "value": {},
      "is_publishable": {},
      "sources": {},
      "misp": {},
      "last_updated": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "first_seen": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "last_seen": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "attributed_associations": {
          "postparser": lambda _, client: (
              create_attributed_association(assoc, client) for assoc in _
          )
      },
      "reports": {
          "api_path": "/reports",
          "postparser": lambda _, client: (
              Report.from_json_response(report, client) for report in _
          ),
      },
      "campaigns": {
          "postparser": lambda _, client: (
              Campaign.from_json_response(campaign, client) for campaign in _
          )
      },
  }

  def _get_subclient(self):
    return self._client.Indicators


class URLIndicator(APIResponse):
  """An APIResponse object representing a URL Indicator

  An APIResponse object representing a URL Indicator from the MATI API.

  Attributes:
    id: The URL UUID from MATI
    mscore: An int containing the confidence score (from 0 to 100)
    type: A string representing the type of Indicator
    value: The indicator value
    is_publishable: A boolean indicating if this information can be published
    sources: A list of sources
    misp: A dict containing the MISP information
    last_updated: A datetime indicating the last update time
    first_seen: A datetime indicating the first time the indicator was observed
    last_seen: A datetime indicating the most recent time the indicator was
      observed
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "id": {},
      "mscore": {},
      "threat_rating": {},
      "category": {},
      "type": {},
      "value": {},
      "is_publishable": {},
      "sources": {},
      "misp": {},
      "last_updated": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "first_seen": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "last_seen": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "attributed_associations": {
          "postparser": lambda _, client: (
              create_attributed_association(assoc, client) for assoc in _
          )
      },
      "reports": {
          "api_path": "/reports",
          "postparser": lambda _, client: (
              Report.from_json_response(report, client) for report in _
          ),
      },
      "campaigns": {
          "postparser": lambda _, client: (
              Campaign.from_json_response(campaign, client) for campaign in _
          )
      },
  }

  def _get_subclient(self):
    return self._client.Indicators


class IPIndicator(APIResponse):
  """An APIResponse object representing an IP Indicator

  An APIResponse object representing an IP Indicator from the MATI API.

  Attributes:
    id: The IP UUID from MATI
    mscore: An int containing the confidence score (from 0 to 100)
    type: A string representing the type of Indicator
    value: The indicator value
    is_publishable: A boolean indicating if this information can be published
    sources: A list of sources
    misp: A dict containing the MISP information
    last_updated: A datetime indicating the last update time
    first_seen: A datetime indicating the first time the indicator was observed
    last_seen: A datetime indicating the most recent time the indicator was
      observed
  """

  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "id": {},
      "mscore": {},
      "threat_rating": {},
      "category": {},
      "type": {},
      "value": {},
      "is_publishable": {},
      "sources": {},
      "misp": {},
      "last_updated": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "first_seen": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "last_seen": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "attributed_associations": {
          "postparser": lambda _, client: (
              create_attributed_association(assoc, client) for assoc in _
          )
      },
      "reports": {
          "api_path": "/reports",
          "postparser": lambda _, client: (
              Report.from_json_response(report, client) for report in _
          ),
      },
      "campaigns": {
          "postparser": lambda _, client: (
              Campaign.from_json_response(campaign, client) for campaign in _
          )
      },
  }

  def _get_subclient(self):
    return self._client.Indicators


class Campaign(APIResponse):
  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "id": {},
      "type": {},
      "name": {},
      "description": {},
      "releasable": {},
      "counts": {},
      "audience": {},
      "profile_updated": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "campaign_type": {},
      "short_name": {},
      "last_activity_time": {
          "postparser": lambda _, client: dateutil_parser.parse(_)
      },
      "indicators": {
          "api_path": "/indicators",
          "paginated": PaginationTypeEnum.NEXT,
          "preparser": lambda _: {
              "indicators": [
                  i for page in _ for i in page.get("indicators", [])
              ]
          },
          "postparser": lambda _, client: (
              create_indicator(i, client) for i in _
          ),
      },
      "campaigns": {},
      "timeline": {},
      "aliases": {},
      "actors": {
          "postparser": lambda _, client: (
              ThreatActor.from_json_response(a, client) for a in _
          )
      },
      "malware": {
          "postparser": lambda _, client: (
              Malware.from_json_response(a, client) for a in _
          )
      },
      "tools": {
          "postparser": lambda _, client: (
              Malware.from_json_response(a, client) for a in _
          )
      },
      "vulnerabilities": {
          "postparser": lambda _, client: (
              Vulnerability.from_json_response(v, client) for v in _
          )
      },
      "industries": {},
      "target_locations": {},
      "actor_collaborations": {},
      "is_publishable": {},
      "intel_free": {},
  }

  def _get_subclient(self):
    return self._client.Campaigns


class DTMAlert(APIResponse):
  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "id": {},
      "alert_summary": {},
      "alert_type": {},
      "created_at": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "doc": {
          "postparser": lambda _, client: DTMDocument.from_json_response(
              _, client
          )
      },
      "doc_matches": {},
      "email_sent_at": {},
      "indicator_attributions": {},
      "indicator_mscore": {},
      "label_matches": {},
      "labels_url": {},
      "monitor_id": {},
      "monitor_version": {},
      "relevance_class": {},
      "relevance_probability": {},
      "status": {},
      "tags": {},
      "title": {},
      "topic_matches": {},
      "topics": {},
      "topics_url": {},
      "updated_at": {"postparser": lambda _, client: dateutil_parser.parse(_)},
  }


class DTMDocument(APIResponse):
  _QUERY_MAP = {
      # "example": {
      #   "field": "example",
      #   "api_path": "/indicators",
      #   "content-type": "application/json",
      #   "preparser": lambda _: _,
      #   "postparser": lambda _: _,
      # },
      "uuid": {"field": "__id"},
      "type": {
          "field": "__type",
          "postparser": lambda _, client: DTMDocumentTypeEnum(_),
      },
      "author": {},
      "body": {},
      "id": {"field": "id_str"},
      "ingested": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "is_quote": {},
      "language": {},
      "possibly_sensitive": {},
      "quote_count": {},
      "reply_count": {},
      "retweet_count": {},
      "source": {},
      "timestamp": {"postparser": lambda _, client: dateutil_parser.parse(_)},
      "tweet_hashtags": {},
      "tweet_symbols": {},
      "tweet_urls": {},
      "tweet_user_mentions": {},
      "labels": {"api_path": "/labels"},
      "topics": {"api_path": "/topics"},
  }

  _IDENTIFIER_FIELDS = ["__id"]

  def _get_subclient(self):
    return self._client.DTMDocs

  @property
  def _identifier(self):
    return f"{self.type.value}/{self.uuid}"
