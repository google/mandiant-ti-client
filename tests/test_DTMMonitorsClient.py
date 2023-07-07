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
from mandiant_threatintel import DTMDocumentTypeEnum
import vcr

mock_vcr = vcr.VCR(
    cassette_library_dir='fixtures/DTMMonitorsClient',
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix('.yaml'),
)


class Test_DTMMonitorCondition(unittest.TestCase):

  def test_init_one_condition(self):
    monitor_json = {
        'operator': mandiant_threatintel.DTMMonitorOperatorEnum.MUST_EQUAL,
        'topic': mandiant_threatintel.DTMMonitorTopicEnum.ACCESS_TOKEN,
        'match': ['fake_token'],
    }

    monitor = mandiant_threatintel.DTMMonitorCondition(**monitor_json)

    self.assertIsInstance(monitor, mandiant_threatintel.DTMMonitorCondition)

  def test_init_nested_conditions(self):
    inner_match_json = {
        'operator': mandiant_threatintel.DTMMonitorOperatorEnum.MUST_EQUAL,
        'topic': mandiant_threatintel.DTMMonitorTopicEnum.ACCESS_TOKEN,
        'match': ['fake_token'],
    }
    inner_match = mandiant_threatintel.DTMMonitorCondition(**inner_match_json)
    monitor_json = {
        'operator': mandiant_threatintel.DTMMonitorOperatorEnum.ALL,
        'topic': mandiant_threatintel.DTMMonitorTopicEnum.MATCH_CONDITIONS,
        'match': [inner_match],
    }

    monitor = mandiant_threatintel.DTMMonitorCondition(**monitor_json)

    self.assertIsInstance(monitor, mandiant_threatintel.DTMMonitorCondition)

  def test_init_invalid_nested_conditions(self):
    inner_match_json = {
        'operator': mandiant_threatintel.DTMMonitorOperatorEnum.MUST_EQUAL,
        'topic': mandiant_threatintel.DTMMonitorTopicEnum.ACCESS_TOKEN,
        'match': ['fake_token'],
    }
    inner_match = mandiant_threatintel.DTMMonitorCondition(**inner_match_json)
    monitor_json = {
        'operator': mandiant_threatintel.DTMMonitorOperatorEnum.ALL,
        'topic': mandiant_threatintel.DTMMonitorTopicEnum.ACCESS_TOKEN,
        'match': [inner_match],
    }

    self.assertRaises(
        ValueError, mandiant_threatintel.DTMMonitorCondition, **monitor_json
    )

  def test_from_json_nested_conditions(self):
    input_json = {
        'operator': 'all',
        'topic': 'match_conditions',
        'match': [{
            'operator': 'must_equal',
            'topic': 'access_token',
            'match': ['fake_token'],
        }],
    }

    monitor_condition = mandiant_threatintel.DTMMonitorCondition.from_json(
        input_json
    )

    self.assertIsInstance(
        monitor_condition, mandiant_threatintel.DTMMonitorCondition
    )
    self.assertIsInstance(
        monitor_condition.match[0], mandiant_threatintel.DTMMonitorCondition
    )


class Test_DTMMonitorsClient(unittest.TestCase):

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

    self.dtm_monitors_client = self.base_client.DTMMonitors

  @mock_vcr.use_cassette
  def test_get_list_single_page(self):
    monitors = self.dtm_monitors_client.get_list(size=11)

    monitors = [i for i in monitors]
    for i in monitors:
      self.assertIsInstance(i, mandiant_threatintel.DTMMonitor)

    self.assertEqual(len(monitors), 10)

  @mock_vcr.use_cassette
  def test_get_list_multiple_pages(self):
    monitors = self.dtm_monitors_client.get_list(size=1)

    monitors = [i for i in monitors]
    for i in monitors:
      self.assertIsInstance(i, mandiant_threatintel.DTMMonitor)

    self.assertEqual(len(monitors), 1)

  @mock_vcr.use_cassette
  def test_get_by_id(self):
    monitor = self.dtm_monitors_client.get('chvgf4gl24d39uevvpeg')

    self.assertIsInstance(monitor, mandiant_threatintel.DTMMonitor)

  @mock_vcr.use_cassette
  def test_delete_does_not_raise(self):
    monitor = self.dtm_monitors_client.get('ci09hlgl24d39uf0c72g')

    self.dtm_monitors_client.delete(monitor)

  @mock_vcr.use_cassette
  def test_update(self):
    monitor = self.dtm_monitors_client.get('ci0ac90l24d39uf0cr3g')

    monitor.name = 'TEST CARD SHOP'

    updated_monitor = self.dtm_monitors_client.update(monitor)

    self.assertIsInstance(updated_monitor, mandiant_threatintel.DTMMonitor)

  @mock_vcr.use_cassette
  def test_create(self):
    condition_json = {
        'operator': mandiant_threatintel.DTMMonitorOperatorEnum.MUST_EQUAL,
        'topic': mandiant_threatintel.DTMMonitorTopicEnum.ACCESS_TOKEN,
        'match': ['fake_token'],
    }
    monitor = self.dtm_monitors_client.create(
        description='test',
        doc_condition=mandiant_threatintel.DTMMonitorCondition(
            **condition_json
        ),
        email_notify_enabled=False,
        email_notify_immediate=False,
        enabled=False,
        name='ChrisHultin Test',
    )

    self.assertIsInstance(monitor, mandiant_threatintel.DTMMonitor)


if __name__ == '__main__':
  unittest.main()
