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

import datetime
import os
import types
import unittest
from freezegun import freeze_time
import mandiant_threatintel
import vcr

mock_vcr = vcr.VCR(
    cassette_library_dir="fixtures/CampaignsClient",
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)


class Test_Campaign_APIResponse(unittest.TestCase):

  def setUp(self) -> None:
    self.mock_base_client: mandiant_threatintel.ThreatIntelClient = (
        unittest.mock.create_autospec(mandiant_threatintel.ThreatIntelClient)
    )

    self.mock_campaigns_client: mandiant_threatintel.CampaignsClient = (
        unittest.mock.create_autospec(mandiant_threatintel.CampaignsClient)
    )

  def test_init_campaign_from_json(self):
    mock_response = {
        "type": "campaign",
        "id": "campaign--ID",
        "name": "FAKE_NAME",
        "description": "DESCRIPTION",
        "releasable": True,
        "counts": {
            "actors": 1,
            "reports": 1,
            "malware": 2,
            "campaigns": 0,
            "industries": 2,
            "timeline": 60,
            "vulnerabilities": 0,
            "actor_collaborations": 0,
            "tools": 7,
        },
        "audience": [{"name": "intel_oper", "license": "INTEL_RBI_OPS"}],
        "profile_updated": "2023-01-27T07:13:10.090Z",
        "campaign_type": "Individual",
        "short_name": "FAKE_SHORT_NAME",
        "last_activity_time": "2021-12-21T00:00:00.000Z",
        "campaigns": [],
        "timeline": [
            {
                "name": "Campaign Created",
                "description": "Mandiant Declared Campaign",
                "releasable": True,
                "event_type": "created",
                "timestamp": "2021-12-21T00:00:00.000Z",
            },
            {
                "name": "First Observed",
                "description": "Mandiant Observed First Activity of Campaign",
                "releasable": True,
                "event_type": "first_observed",
                "timestamp": "2021-08-16T00:00:00.000Z",
            },
        ],
        "aliases": {
            "releasable": True,
            "actor": [],
            "malware": [],
            "campaign": [],
        },
        "actors": [{
            "type": "threat-actor",
            "id": "threat-actor--UID",
            "name": "FAKE_ACTOR",
            "attribution_scope": "confirmed",
            "releasable": True,
            "motivations": [{
                "type": "motivation",
                "id": "motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e",
                "name": "Espionage",
                "attribution_scope": "confirmed",
                "releasable": True,
            }],
            "source_locations": [{
                "releasable": True,
                "country": {
                    "type": "location",
                    "id": "location--188145fd-6fd1-5bd6-a70c-8e33ed149584",
                    "name": "Russia",
                    "attribution_scope": "confirmed",
                    "releasable": True,
                    "iso2": "RU",
                },
                "region": {
                    "type": "location",
                    "id": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f",
                    "name": "Europe",
                    "attribution_scope": "confirmed",
                    "releasable": True,
                },
                "sub_region": {
                    "type": "location",
                    "id": "location--57644af5-a064-5e14-be58-05b22d2768be",
                    "name": "East Europe",
                    "attribution_scope": "confirmed",
                    "releasable": True,
                },
            }],
        }],
        "malware": [{
            "type": "malware",
            "id": "malware--448e822d-8496-5021-88cb-599062f74176",
            "name": "MALWARE_NAME",
            "attribution_scope": "confirmed",
            "releasable": True,
        }],
        "tools": [{
            "type": "malware",
            "id": "malware--405817d8-a607-5231-a5f1-e0d1cb4226df",
            "name": "MALWARE_NAME_2",
            "attribution_scope": "confirmed",
            "releasable": True,
        }],
        "vulnerabilities": [],
        "industries": [
            {
                "type": "identity",
                "id": "identity--8d0881d8-d199-5e5a-bef9-be3ca6bb8f0d",
                "name": "Governments",
                "attribution_scope": "confirmed",
                "releasable": True,
            },
            {
                "type": "identity",
                "id": "identity--93209517-b16c-5893-b55e-b7edc9b478d0",
                "name": "Telecommunications",
                "attribution_scope": "confirmed",
                "releasable": True,
            },
        ],
        "target_locations": {
            "releasable": True,
            "countries": [{
                "type": "location",
                "id": "location--f66d95f4-10dc-55f9-a444-81dc49fcf238",
                "name": "United Kingdom",
                "attribution_scope": "confirmed",
                "iso2": "GB",
                "region": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f",
                "sub_region": "location--07071b1c-a0fb-56e7-9619-11397860bd4c",
                "releasable": True,
                "count": 2,
            }],
            "regions": [{
                "type": "location",
                "id": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f",
                "name": "Europe",
                "attribution_scope": "confirmed",
                "releasable": True,
                "count": 2,
            }],
            "sub_regions": [{
                "type": "location",
                "id": "location--07071b1c-a0fb-56e7-9619-11397860bd4c",
                "name": "North Europe",
                "attribution_scope": "confirmed",
                "region": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f",
                "releasable": True,
                "count": 2,
            }],
        },
        "actor_collaborations": [],
        "is_publishable": True,
        "intel_free": False,
    }
    campaign = mandiant_threatintel.Campaign.from_json_response(
        response=mock_response, client=self.mock_base_client
    )

    self.assertIsInstance(campaign, mandiant_threatintel.Campaign)
    self.assertEqual(campaign.name, "FAKE_NAME")

  def test_init_campaign_from_bad_json(self):
    mock_response = {}
    self.assertRaises(
        ValueError,
        mandiant_threatintel.Campaign.from_json_response,
        response=mock_response,
        client=self.mock_base_client,
    )

  def test_init_campaign_from_identifier(self):
    campaign = mandiant_threatintel.Campaign.from_identifier(
        "CAMPAIGN_ID", self.mock_base_client
    )

    self.assertIsInstance(campaign, mandiant_threatintel.Campaign)
    self.assertEqual(campaign.id, "CAMPAIGN_ID")


class Test_CampaignsClient(unittest.TestCase):

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

    self.campaigns_client = self.base_client.Campaigns

  @mock_vcr.use_cassette
  def test_get_campaign_by_name(self):
    campaign = self.campaigns_client.get("CAMP.22.063")
    self.assertIsInstance(campaign, mandiant_threatintel.Campaign)

    self.assertIsNotNone(campaign.name)
    self.assertEqual(
        campaign.id, "campaign--6ed45e70-f2c5-5f62-a5ec-d8c25764cd8c"
    )

  @mock_vcr.use_cassette
  def test_get_campaign_by_id(self):
    campaign = self.campaigns_client.get(
        "campaign--6ed45e70-f2c5-5f62-a5ec-d8c25764cd8c"
    )
    self.assertIsInstance(campaign, mandiant_threatintel.Campaign)

    self.assertIsNotNone(campaign.id)
    self.assertEqual(campaign.short_name, "CAMP.22.063")

  @mock_vcr.use_cassette
  def test_get_all_attributes(self):
    malware = self.campaigns_client.get(
        "campaign--6ed45e70-f2c5-5f62-a5ec-d8c25764cd8c"
    )

    attributes_list = [
        attr
        for attr in dir(malware)
        if attr[0:1] != "_" and attr[0:4] != "from"
    ]
    for attr in attributes_list:
      attr_value = malware.__getattr__(attr)
      if isinstance(attr_value, types.GeneratorType):
        attr_value = [v for v in attr_value]

      print(f"{attr}: {attr_value}")

  @mock_vcr.use_cassette
  def test_get_list_multiple_pages(self):
    start_date = datetime.datetime.fromtimestamp(1674825974)
    campaigns_list = [
        m
        for m in self.campaigns_client.get_list(
            page_size=1, start_date=start_date
        )
    ]

    self.assertEqual(len(campaigns_list), 2)

  @mock_vcr.use_cassette
  def test_get_list_single_page(self):
    start_date = datetime.datetime.fromtimestamp(1674825974)
    campaigns_list = [
        m
        for m in self.campaigns_client.get_list(
            page_size=50, start_date=start_date
        )
    ]

    self.assertEqual(len(campaigns_list), 1)


if __name__ == "__main__":
  unittest.main()
