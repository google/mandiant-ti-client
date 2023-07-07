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

from datetime import datetime
import os
import types
import unittest
from freezegun import freeze_time
import mandiant_threatintel
from mandiant_threatintel.threat_intel_client import Report
import vcr

mock_vcr = vcr.VCR(
    cassette_library_dir='fixtures/IndicatorsClient',
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix('.yaml'),
)


class Test_Indicators_APIResponse(unittest.TestCase):

  def setUp(self) -> None:
    self.mock_base_client: mandiant_threatintel.ThreatIntelClient = (
        unittest.mock.create_autospec(mandiant_threatintel.ThreatIntelClient)
    )

    self.mock_indicators_client: mandiant_threatintel.IndicatorsClient = (
        unittest.mock.create_autospec(mandiant_threatintel.IndicatorsClient)
    )

  def test_init_indicator_from_json(self):
    indicators = [
        (
            mandiant_threatintel.IPIndicator,
            {'id': 'ipv4--uuid', 'type': 'ipv4'},
        ),
        (mandiant_threatintel.MD5Indicator, {'id': 'md5--uuid', 'type': 'md5'}),
        (mandiant_threatintel.URLIndicator, {'id': 'url--uuid', 'type': 'url'}),
        (
            mandiant_threatintel.FQDNIndicator,
            {'id': 'fqdn--uuid', 'type': 'fqdn'},
        ),
    ]
    for indicator_class, indicator_response in indicators:
      indicator = indicator_class.from_json_response(
          indicator_response, self.mock_base_client
      )

      self.assertIsInstance(indicator, indicator_class)
      self.assertIsNotNone(indicator.id)

  def test_init_indicator_from_bad_json(self):
    indicators = [
        mandiant_threatintel.IPIndicator,
        mandiant_threatintel.MD5Indicator,
        mandiant_threatintel.URLIndicator,
        mandiant_threatintel.FQDNIndicator,
    ]
    for indicator_class in indicators:
      self.assertRaises(
          ValueError,
          indicator_class.from_json_response,
          {},
          self.mock_base_client,
      )

  def test_init_indicator_from_identifier(self):
    indicators = [
        (mandiant_threatintel.IPIndicator, 'ipv4--uuid'),
        (mandiant_threatintel.MD5Indicator, 'md5--uuid'),
        (mandiant_threatintel.URLIndicator, 'url--uuid'),
        (mandiant_threatintel.FQDNIndicator, 'fqdn--uuid'),
    ]
    for indicator_class, indicator_id in indicators:
      indicator = indicator_class.from_identifier(
          indicator_id, self.mock_base_client
      )

      self.assertIsInstance(indicator, indicator_class)
      self.assertIsNotNone(indicator.id)


class Test_IndicatorsClient(unittest.TestCase):

  def setUp(self) -> None:
    self.API_KEY = os.environ.get('API_KEY')
    self.SECRET_KEY = os.environ.get('SECRET_KEY')

    if not self.API_KEY or not self.SECRET_KEY:
      self.TOKEN = 'FAKE_TOKEN'
      self.base_client = mandiant_threatintel.ThreatIntelClient(
          bearer_token=self.TOKEN
      )
    else:
      self.base_client = mandiant_threatintel.ThreatIntelClient(
          api_key=self.API_KEY, secret_key=self.SECRET_KEY
      )

    self.indicators_client = self.base_client.Indicators

  @mock_vcr.use_cassette
  def test_get_indicator_by_id(self):
    indicator_types = [
        (
            'fqdn--7baea406-cc1b-53f9-b1b2-ea4ad2f56dc1',
            mandiant_threatintel.FQDNIndicator,
        ),
        (
            'md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f',
            mandiant_threatintel.MD5Indicator,
        ),
        (
            'url--431bfcd3-a8a5-5103-9ad7-ac7f05891875',
            mandiant_threatintel.URLIndicator,
        ),
        (
            'ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9',
            mandiant_threatintel.IPIndicator,
        ),
    ]
    for indicator_id, indicator_class in indicator_types:
      with self.subTest():
        indicator = self.indicators_client.get(indicator_id)
        self.assertIsInstance(indicator, indicator_class)

  @mock_vcr.use_cassette
  def test_get_indicator_list_single_page_no_parameters(self):
    start_time = datetime.fromtimestamp(1674670863)
    indicators = self.indicators_client.get_list(start_epoch=start_time)

    indicators_list = list(indicators)

    self.assertIsInstance(indicators_list[0], mandiant_threatintel.APIResponse)

    self.assertEqual(len(indicators_list), 1)

  @mock_vcr.use_cassette
  def test_get_indicator_list_multiple_pages_no_parameters(self):
    start_time = datetime.fromtimestamp(1674670863)
    indicators = self.indicators_client.get_list(
        start_epoch=start_time, page_size=1
    )

    indicators_list = list(indicators)
    for indicator in indicators_list:
      with self.subTest():
        self.assertIsInstance(indicator, mandiant_threatintel.APIResponse)

    self.assertEqual(len(indicators_list), 2)

  @freeze_time(datetime.fromtimestamp(1674843663))
  @mock_vcr.use_cassette
  def test_get_indicator_list_single_page_with_parameters(self):
    start_time = datetime.fromtimestamp(1674670863)
    end_time = datetime.now()
    minimum_mscore = 50
    exclude_osint = True
    page_size = 50
    indicators = self.indicators_client.get_list(
        start_epoch=start_time,
        end_epoch=end_time,
        minimum_mscore=minimum_mscore,
        exclude_osint=exclude_osint,
        page_size=page_size,
    )

    indicators_list = list(indicators)

    self.assertIsInstance(indicators_list[0], mandiant_threatintel.APIResponse)

    self.assertEqual(len(indicators_list), 1)

  @freeze_time(datetime.fromtimestamp(1674843663))
  @mock_vcr.use_cassette
  def test_get_indicator_list_single_page_with_kwargs(self):
    start_time = datetime.fromtimestamp(1674670863)
    end_time = datetime.now()
    minimum_mscore = 50
    exclude_osint = True
    page_size = 50
    indicators = self.indicators_client.get_list(
        start_epoch=start_time,
        end_epoch=end_time,
        minimum_mscore=minimum_mscore,
        exclude_osint=exclude_osint,
        page_size=page_size,
        last_updated='asc',
    )

    indicators_list = list(indicators)

    self.assertIsInstance(indicators_list[0], mandiant_threatintel.APIResponse)

    self.assertEqual(len(indicators_list), 1)

  @freeze_time(datetime.fromtimestamp(1668591000))
  @mock_vcr.use_cassette
  def test_get_indicator_list_multiple_pages_with_parameters(self):
    start_time = datetime.fromtimestamp(1662848797)
    end_time = datetime.now()
    minimum_mscore = 50
    exclude_osint = True
    page_size = 1
    indicators = self.indicators_client.get_list(
        start_epoch=start_time,
        end_epoch=end_time,
        minimum_mscore=minimum_mscore,
        exclude_osint=exclude_osint,
        page_size=page_size,
    )

    indicators_list = list(indicators)
    for indicator in indicators_list:
      with self.subTest():
        self.assertIsInstance(indicator, mandiant_threatintel.APIResponse)

    self.assertEqual(len(indicators_list), 2)

  @mock_vcr.use_cassette
  def test_get_indicator_from_value(self):
    indicator_types = [
        ('google.com', mandiant_threatintel.FQDNIndicator),
        ('fe09cf6d3a358305f8c2f687b6f6da02', mandiant_threatintel.MD5Indicator),
        ('https://google.com', mandiant_threatintel.URLIndicator),
        ('8.8.8.8', mandiant_threatintel.IPIndicator),
    ]
    for indicator_value, indicator_class in indicator_types:
      with self.subTest():
        self.assertIsInstance(
            self.indicators_client.get_from_value(indicator_value),
            indicator_class,
        )

  @mock_vcr.use_cassette
  def test_get_all_attributes(self):
    indicators = [
        'fqdn--7baea406-cc1b-53f9-b1b2-ea4ad2f56dc1',
        'md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f',
        'url--431bfcd3-a8a5-5103-9ad7-ac7f05891875',
        'ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9',
    ]
    for indicator_id in indicators:
      indicator_type = indicator_id[0 : indicator_id.index('--')]
      with self.subTest(msg=indicator_type):
        indicator = self.indicators_client.get(indicator_id)

        attributes_list = [
            attr
            for attr in dir(indicator)
            if attr[0:1] != '_'
            and attr[0:4] != 'from'
            and attr not in ['reports']
        ]
        for attr in attributes_list:
          attr_value = indicator.__getattr__(attr)
          if isinstance(attr_value, types.GeneratorType):
            attr_value = [v for v in attr_value]

          print(f'{attr}: {attr_value}')

  @mock_vcr.use_cassette
  def test_get_reports(self):
    indicators = [
        'fqdn--7baea406-cc1b-53f9-b1b2-ea4ad2f56dc1',
        'md5--734cb023-91b0-504c-b10e-3756eb3cd9b3',
        'url--431bfcd3-a8a5-5103-9ad7-ac7f05891875',
        'ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9',
    ]
    for indicator_id in indicators:
      indicator_type = indicator_id[0 : indicator_id.index('--')]
      with self.subTest(msg=indicator_type):
        indicator = self.indicators_client.get(indicator_id)
        for report in indicator.reports:
          self.assertIsInstance(report, Report)


if __name__ == '__main__':
  unittest.main()
