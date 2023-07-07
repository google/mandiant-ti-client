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

import os
import types
import unittest
import mandiant_threatintel
import vcr

mock_vcr = vcr.VCR(
    cassette_library_dir="fixtures/ThreatActorsClient",
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)


class Test_ThreatActor_APIResponse(unittest.TestCase):

  def setUp(self) -> None:
    self.mock_base_client: mandiant_threatintel.ThreatIntelClient = (
        unittest.mock.create_autospec(mandiant_threatintel.ThreatIntelClient)
    )

    self.mock_threatactors_client: mandiant_threatintel.ThreatActorsClient = (
        unittest.mock.create_autospec(mandiant_threatintel.ThreatActorsClient)
    )

  def test_init_threatactor_from_json(self):
    threatactor_response = {
        "id": "threat-actor--FAKE-UUID-THREATACTOR",
        "name": "THREAT_ACTOR_NAME",
        "description": "THREAT_ACTOR_DESCRIPTION_GOES_HERE",
        "type": "threat-actor",
        "last_updated": "2022-10-11T05:52:23.000Z",
        "audience": [],
        "motivations": [{
            "id": "motivation--FAKE-UUID-MOTIVATION",
            "name": "MOTIVATION",
            "attribution_scope": "confirmed",
        }],
        "aliases": [{"name": "ALIAS_NAME", "attribution_scope": "possible"}],
        "observed": [
            {
                "earliest": "2011-01-29T00:00:00.000Z",
                "recent": "2015-03-12T00:00:00.000Z",
                "attribution_scope": "suspected",
            },
            {
                "earliest": "2020-04-07T10:02:36.000Z",
                "recent": "2021-08-26T15:00:34.000Z",
                "attribution_scope": "possible",
            },
            {
                "earliest": "2002-11-17T00:00:00.000Z",
                "recent": "2022-08-11T14:29:04.000Z",
                "attribution_scope": "confirmed",
            },
        ],
        "malware": [{
            "id": "malware--FAKE-UUID-MALWARE",
            "name": "MALWARE_NAME",
            "attribution_scope": "confirmed",
            "first_seen": "2014-06-05T12:06:33.000Z",
            "last_seen": "2014-08-28T01:38:11.000Z",
        }],
        "tools": [{
            "id": "malware--FAKE-UUID-TOOL",
            "name": "TOOL_NAME",
            "attribution_scope": "confirmed",
        }],
        "locations": {
            "source": [{
                "region": {
                    "id": "location--FAKE-UUID-SOURCE-REGION",
                    "name": "SOURCE_REGION_NAME",
                    "attribution_scope": "confirmed",
                },
            }],
            "target": [{
                "id": "location--FAKE-UUID",
                "name": "TARGET_NAME_NAME",
                "iso2": "TG",
                "region": "TARGET_REGION",
                "attribution_scope": "confirmed",
                "sub-region": "TARGET_SUBREGION_NAME",
            }],
            "target_sub_region": [{
                "id": "location--FAKE-UUID-TARGET-SUBREGION",
                "name": "TARGET_SUBREGION_NAME",
                "key": "TARGET_SUBREGION_KEY",
                "region": "TARGET_REGION_NAME",
                "attribution_scope": "confirmed",
            }],
            "target_region": [
                {
                    "id": "location--FAKE-UUID-TARGET-REGION",
                    "name": "TARGET_REGION_NAME",
                    "key": "TARGET_REGION_KEY",
                    "attribution_scope": "confirmed",
                },
            ],
        },
        "cve": [
            {
                "id": "vulnerability--FAKE-UUID-TARGET",
                "cve_id": "CVE-YYYY-IDID",
                "attribution_scope": "suspected",
            },
        ],
        "last_activity_time": "2022-08-11T14:29:04.000Z",
        "suspected_attribution": [],
        "associated_uncs": [{
            "id": "threat-actor--FAKE-UUID",
            "name": "FAKE_UNC",
            "attribution_scope": "suspected",
        }],
        "is_publishable": True,
        "counts": {
            "reports": 0,
            "malware": 53,
            "cve": 4,
            "associated_uncs": 9,
            "aliases": 15,
            "industries": 21,
            "attack_patterns": 188,
        },
        "intel_free": False,
    }

    threatactor = mandiant_threatintel.ThreatActor.from_json_response(
        threatactor_response, self.mock_base_client
    )

    self.assertIsInstance(threatactor, mandiant_threatintel.ThreatActor)
    self.assertIsNotNone(threatactor.id)

  def test_init_threatactor_from_bad_json(self):
    threatactor_response = {}

    self.assertRaises(
        ValueError,
        mandiant_threatintel.ThreatActor.from_json_response,
        threatactor_response,
        self.mock_base_client,
    )

  def test_init_threatactor_from_identifier(self):
    fake_identifier = "FAKE-UUID"
    threatactor = mandiant_threatintel.ThreatActor.from_identifier(
        fake_identifier, self.mock_base_client
    )

    self.assertIsInstance(threatactor, mandiant_threatintel.ThreatActor)
    self.assertEqual(threatactor.id, fake_identifier)


class Test_ThreatActorsClient(unittest.TestCase):

  def setUp(self) -> None:
    self.API_KEY = os.environ.get("API_KEY")
    self.SECRET_KEY = os.environ.get("SECRET_KEY")

    if not self.API_KEY or not self.SECRET_KEY:
      self.TOKEN = "FAKE_TOKEN"
      self.base_client = mandiant_threatintel.ThreatIntelClient(
          bearer_token=self.TOKEN
      )
    else:
      self.base_client = mandiant_threatintel.ThreatIntelClient(
          api_key=self.API_KEY, secret_key=self.SECRET_KEY
      )

    self.threatactor_client: mandiant_threatintel.ThreatIntelClient.ThreatActorsClient = (
        self.base_client.ThreatActors
    )

  @mock_vcr.use_cassette
  def test_get_threatactor_by_id(self):
    actor_id = "threat-actor--7a39953e-0dae-569a-9d49-d52a4a8865b1"
    threatactor = self.threatactor_client.get(actor_id)

    self.assertEqual(threatactor.id, actor_id)
    self.assertIsNotNone(threatactor.name)

  @mock_vcr.use_cassette
  def test_get_all_attributes(self):
    actor_id = "threat-actor--7a39953e-0dae-569a-9d49-d52a4a8865b1"
    threatactor = self.threatactor_client.get(actor_id)

    attributes_list = [
        attr
        for attr in dir(threatactor)
        if attr[0:1] != "_" and attr[0:4] != "from" and attr not in ["reports"]
    ]
    for attr in attributes_list:
      attr_value = threatactor.__getattr__(attr)
      if isinstance(attr_value, types.GeneratorType):
        attr_value = [v for v in attr_value]

      print(f"{attr}: {attr_value}")

  @mock_vcr.use_cassette
  def test_get_threatactor_by_name(self):
    actor_name = "APT29"
    threatactor = self.threatactor_client.get(actor_name)

    self.assertEqual(threatactor.name, actor_name)
    self.assertIsNotNone(threatactor.id)

  @mock_vcr.use_cassette
  def test_get_threatactor_list_single_page(self):
    threatactors = self.threatactor_client.get_list()

    threatactors_list = list(threatactors)

    self.assertEqual(len(threatactors_list), 1)
    for threatactor in threatactors_list:
      with self.subTest():
        self.assertIsInstance(threatactor, mandiant_threatintel.ThreatActor)

  @mock_vcr.use_cassette
  def test_get_threatactor_list_multiple_pages(self):
    threatactors = self.threatactor_client.get_list(page_size=1)

    threatactors_list = list(threatactors)

    self.assertEqual(len(threatactors_list), 2)
    for threatactor in threatactors_list:
      with self.subTest():
        self.assertIsInstance(threatactor, mandiant_threatintel.ThreatActor)

  @mock_vcr.use_cassette
  def test_get_threatactor_aliases_string(self):
    actor_name = "APT29"
    threatactor = self.threatactor_client.get(actor_name)

    self.assertEqual(threatactor.name, actor_name)
    self.assertIsNotNone(threatactor.id)
    for alias in threatactor.aliases:
      self.assertIsNotNone(alias.name)


if __name__ == "__main__":
  unittest.main()
