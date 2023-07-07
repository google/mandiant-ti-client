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

import unittest

import mandiant_threatintel
from mandiant_threatintel import filter_dataclass_attributes


class Test_Utils(unittest.TestCase):

  def test_create_indicator_from_type_field(self):
    indicator_types = [
        ({'type': 'md5', 'id': 'md5--uuid'}, mandiant_threatintel.MD5Indicator),
        ({'type': 'url', 'id': 'url--uuid'}, mandiant_threatintel.URLIndicator),
        (
            {'type': 'fqdn', 'id': 'fqdn--uuid'},
            mandiant_threatintel.FQDNIndicator,
        ),
        (
            {'type': 'ipv4', 'id': 'ipv4--uuid'},
            mandiant_threatintel.IPIndicator,
        ),
    ]

    fake_token = 'FAKE_TOKEN'

    client = mandiant_threatintel.ThreatIntelClient(bearer_token=fake_token)
    for indicator_response, indicator_class in indicator_types:
      with self.subTest():
        self.assertIsInstance(
            mandiant_threatintel.create_indicator(indicator_response, client),
            indicator_class,
        )

  def test_create_indicator_from_id_field(self):
    indicator_types = [
        ({'id': 'md5--uuid'}, mandiant_threatintel.MD5Indicator),
        ({'id': 'url--uuid'}, mandiant_threatintel.URLIndicator),
        ({'id': 'fqdn--uuid'}, mandiant_threatintel.FQDNIndicator),
        ({'id': 'ipv4--uuid'}, mandiant_threatintel.IPIndicator),
    ]

    fake_token = 'FAKE_TOKEN'
    client = mandiant_threatintel.threat_intel_client.ThreatIntelClient(
        bearer_token=fake_token
    )
    for indicator_response, indicator_class in indicator_types:
      with self.subTest():
        self.assertIsInstance(
            mandiant_threatintel.create_indicator(indicator_response, client),
            indicator_class,
        )

  def test_get_associated_hash(self):
    hash_types = [
        ('md5', 'fake_md5_hash'),
        ('sha1', 'fake_sha1_hash'),
        ('sha256', 'fake_sha256_hash'),
    ]
    associated_hashes = [
        {'type': 'md5', 'value': 'fake_md5_hash'},
        {'type': 'sha1', 'value': 'fake_sha1_hash'},
        {'type': 'sha256', 'value': 'fake_sha256_hash'},
    ]

    for hash_type, hash_value in hash_types:
      with self.subTest(msg=hash_type):
        self.assertEqual(
            mandiant_threatintel.get_associated_hash(
                associated_hashes, hash_type
            ),
            hash_value,
        )

  def test_filter_dataclass_attributes(self):
    bad_alias = {
        'name': 'BadAlias',
        'attribution_scope': 'Fake',
        'alias': 'BreakingTheAPI',
        'company': 'Mandiant',
        'DELETE_THIS_FIELD': 'IT WILL BREAK THINGS',
    }

    output_data = filter_dataclass_attributes(
        mandiant_threatintel.Alias, bad_alias
    )
    self.assertNotIn('DELETE_THIS_FIELD', output_data)


if __name__ == '__main__':
  unittest.main()
