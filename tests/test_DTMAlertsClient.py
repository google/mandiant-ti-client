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
    cassette_library_dir="fixtures/DTMAlertsClient",
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)


class Test_DTMAlertsClient(unittest.TestCase):

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

    self.dtm_alerts_client = self.base_client.DTMAlerts

  @mock_vcr.use_cassette
  def test_get_list_single_page(self):
    alerts_list = [m for m in self.dtm_alerts_client.get_list(size=1)]

    self.assertEqual(len(alerts_list), 1)

  @mock_vcr.use_cassette
  def test_get_list_single_page_parameters(self):
    alerts_list = [
        m
        for m in self.dtm_alerts_client.get_list(size=1, status=["new", "read"])
    ]

    self.assertEqual(len(alerts_list), 1)

  @mock_vcr.use_cassette
  def test_get_by_id(self):
    alert = self.dtm_alerts_client.get("cht33rmiq259s5f6q4l0")

    self.assertIsInstance(alert, mandiant_threatintel.DTMAlert)

  @mock_vcr.use_cassette
  def test_update_alert_status(self):
    alert = self.dtm_alerts_client.get("cht33rmiq259s5f6q4l0")

    self.dtm_alerts_client.update_alert(
        alert, mandiant_threatintel.DTMAlertStatusEnum.NEW
    )

  @mock_vcr.use_cassette
  def test_bulk_update_alert_status(self):
    alert = self.dtm_alerts_client.get("cht33rmiq259s5f6q4l0")

    self.dtm_alerts_client.bulk_update_alerts(
        [(alert, {"status": mandiant_threatintel.DTMAlertStatusEnum.NEW})]
    )


if __name__ == "__main__":
  unittest.main()
