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
import unittest
from freezegun import freeze_time
import mandiant_threatintel
import vcr

mock_vcr = vcr.VCR(
    cassette_library_dir='fixtures/ThreatIntelClient',
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix('.yaml'),
)


class Test_ThreatIntelClient(unittest.TestCase):

  def test_init_from_token(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )

    self.assertEqual(client.token, fake_token)

  # Note: Time is frozen at approx 400 seconds before token expiration
  @mock_vcr.use_cassette
  @freeze_time(datetime.datetime.fromtimestamp(1668591000))
  def test_init_from_api_key_secret_key(self):
    api_key = 'FAKE_API_KEY'
    secret_key = 'FAKE_SECRET_KEY'

    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        api_key=api_key, secret_key=secret_key
    )

    self.assertEqual(client.token, 'FAKE_BEARER_TOKEN')

  @mock_vcr.use_cassette
  @freeze_time(datetime.datetime.fromtimestamp(1668591000))
  def test_init_with_proxy(self):
    fake_token = 'FAKE_BEARER_TOKEN'
    proxy_config = {'http': 'http://localhost', 'https': 'http://localhost'}

    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token, proxy_config=proxy_config
    )

    self.assertEqual(client.token, fake_token)

  def test_headers_from_token(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )

    expected_headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer THIS_is_A_fake_TOKEN',
        'X-App-Name': 'MA-TI-Python-Lib-v0.1',
    }

    self.assertDictEqual(client.headers, expected_headers)

  def test_headers_custom_name(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client_name = 'TEST_CLIENT'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token, client_name=client_name
    )

    expected_headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer THIS_is_A_fake_TOKEN',
        'X-App-Name': client_name,
    }

    self.assertDictEqual(client.headers, expected_headers)

  def test_init_no_parameters(self):
    self.assertRaises(
        ValueError, mandiant_threatintel.threat_intel_client.ThreatIntelClient
    )

  def test_fetch_token_without_keys(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )
    self.assertRaises(ValueError, client.fetch_bearer_token)

  @mock_vcr.use_cassette
  def test_get_bearer_token_after_expiration(self):
    api_key = 'FAKE_API_KEY'
    secret_key = 'FAKE_SECRET_KEY'
    # Initial request for token should retrieve an 'expired token'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        api_key=api_key, secret_key=secret_key
    )

    # When attempting to access the token, the expired token should
    # be detected and a new token should be returned
    token = client.token
    self.assertEqual(token, 'FAKE_BEARER_TOKEN')

  def test_get_IndicatorClient(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )

    self.assertIsInstance(
        client.Indicators,
        mandiant_threatintel.threat_intel_client.IndicatorsClient,
    )

  def test_get_MalwareClient(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )

    self.assertIsInstance(
        client.Malware,
        mandiant_threatintel.threat_intel_client.MalwareClient,
    )

  def test_get_ReportsClient(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )

    self.assertIsInstance(
        client.Reports,
        mandiant_threatintel.threat_intel_client.ReportsClient,
    )

  def test_get_ThreatActorsClient(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )

    self.assertIsInstance(
        client.ThreatActors,
        mandiant_threatintel.threat_intel_client.ThreatActorsClient,
    )

  def test_get_VulnerabilityClient(self):
    fake_token = 'THIS_is_A_fake_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )

    self.assertIsInstance(
        client.Vulnerabilities,
        mandiant_threatintel.threat_intel_client.VulnerabilityClient,
    )


if __name__ == '__main__':
  unittest.main()
