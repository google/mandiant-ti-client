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
import dataclasses
import datetime
import os
import types
import unittest
from freezegun import freeze_time
import mandiant_threatintel
from mandiant_threatintel import DTMDocumentTypeEnum, DTMEmailFrequencyEnum
import vcr

mock_vcr = vcr.VCR(
    cassette_library_dir="fixtures/DTMEmailSettingsClient",
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)


class Test_DTMEmailSettingsClient(unittest.TestCase):

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

    self.dtm_email_client = self.base_client.DTMEmailSettings

  @mock_vcr.use_cassette
  def test_get_settings(self):
    settings = self.dtm_email_client.get_settings()

    self.assertIsInstance(settings, mandiant_threatintel.DTMEmailSettings)

  @mock_vcr.use_cassette
  def test_get_settings_by_id(self):
    settings = self.dtm_email_client.get("c7u79mmd3n4qvg37ct2g")

    self.assertIsInstance(settings, mandiant_threatintel.DTMEmailSettings)

  @mock_vcr.use_cassette
  def test_update(self):
    settings = self.dtm_email_client.get("c7u79mmd3n4qvg37ct2g")

    settings.frequency = [
        mandiant_threatintel.DTMEmailFrequencyEnum.MONDAY,
        mandiant_threatintel.DTMEmailFrequencyEnum.TUESDAY,
    ]

    settings = self.dtm_email_client.update(settings)

    self.assertIsInstance(settings, mandiant_threatintel.DTMEmailSettings)

  @mock_vcr.use_cassette
  def test_reverify_one_email(self):
    settings = self.dtm_email_client.get("c7u79mmd3n4qvg37ct2g")

    settings = self.dtm_email_client.reverify(
        settings_id=settings.id, recipients="test@test.com"
    )

    self.assertIsInstance(settings, mandiant_threatintel.DTMEmailSettings)

  @mock_vcr.use_cassette
  def test_reverify_multiple_email(self):
    settings = self.dtm_email_client.get("c7u79mmd3n4qvg37ct2g")

    settings = self.dtm_email_client.reverify(
        settings_id=settings.id, recipients=["test@test.com", "test2@test.com"]
    )

    self.assertIsInstance(settings, mandiant_threatintel.DTMEmailSettings)


if __name__ == "__main__":
  unittest.main()
