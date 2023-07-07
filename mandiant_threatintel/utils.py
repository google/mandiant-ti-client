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

import typing
from typing import List, Dict

import requests.exceptions

from mandiant_threatintel.threat_intel_client import ThreatIntelClient, parse_mitre_attck_patterns


def parse_threatactor_attck_patterns(attack_pattern_response: dict):
  return parse_mitre_attck_patterns("threat-actors", attack_pattern_response)


def parse_malware_attck_patterns(attack_pattern_response: dict):
  return parse_mitre_attck_patterns("malware", attack_pattern_response)


def create_indicator(indicator_api_response: dict, client: ThreatIntelClient):
  from mandiant_threatintel.threat_intel_client import (
      MD5Indicator,
      FQDNIndicator,
      IPIndicator,
      URLIndicator,
  )

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
    associated_hashes_list: List[Dict], hash_type: str = "md5"
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
    api_response: dict[str, typing.Any], fields: List[str]
):
  for field_name in fields:
    if field_name in api_response:
      return api_response.get(field_name)

  raise ValueError("No matching fields found in API response")


def create_attributed_association(
    attributed_association: dict, client: ThreatIntelClient
):
  from mandiant_threatintel.api_responses import ThreatActor, Malware

  if attributed_association["type"] == "threat-actor":
    return ThreatActor.from_identifier(attributed_association["id"], client)
  elif attributed_association["type"] == "malware":
    return Malware.from_identifier(attributed_association["id"], client)
