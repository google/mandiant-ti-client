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
    cassette_library_dir='fixtures/ReportsClient',
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix('.yaml'),
)


class Test_Report_APIResponse(unittest.TestCase):

  def setUp(self) -> None:
    self.mock_base_client: mandiant_threatintel.ThreatIntelClient = (
        unittest.mock.create_autospec(
            mandiant_threatintel.threat_intel_client.ThreatIntelClient
        )
    )

    self.mock_reports_client: mandiant_threatintel.ReportsClient = (
        unittest.mock.create_autospec(mandiant_threatintel.ReportsClient)
    )

  def test_get_report_type(self):
    report_responses = [
        {'reportId': 'FAKE_ID', 'reportType': 'FAKE_TYPE'},
        {'reportId': 'FAKE_ID', 'report_type': 'FAKE_TYPE'},
    ]
    for report_response in report_responses:
      report = mandiant_threatintel.Report.from_json_response(
          report_response, self.mock_base_client
      )

      self.assertEqual(report.report_type, 'FAKE_TYPE')

  def test_get_report_publish_date(self):
    report_responses = [
        {'reportId': 'FAKE_ID', 'publish_date': '2022-08-01T16:33:59.053Z'},
        {'reportId': 'FAKE_ID', 'publishDate': '2022-08-01T16:33:59.053Z'},
    ]
    for report_response in report_responses:
      report = mandiant_threatintel.Report.from_json_response(
          report_response, self.mock_base_client
      )

      # Compare the value of the timestamp instead of the datetime object itself
      self.assertIsInstance(report.publish_date, datetime.datetime)
      self.assertEqual(report.publish_date.timestamp(), 1659371639.053)


class Test_ReportsClient(unittest.TestCase):

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

    self.reports_client = self.base_client.Reports

  def test_get_all_attributes(self):
    # Manually specifying cassette path and using `with` in order to allow
    # repeat playback and reduce the number of recorded API calls
    with mock_vcr.use_cassette(
        'fixtures/ReportsClient/test_get_all_attributes.yaml',
        allow_playback_repeats=True,
    ):
      report = self.reports_client.get('22-00018039')

      attributes_list = [
          attr
          for attr in dir(report)
          if attr[0:1] != '_' and attr[0:4] != 'from'
      ]
      ignore_list = ['indicators']

      for attr in attributes_list:
        if attr not in ignore_list:
          try:
            attr_value = report.__getattr__(attr)
            if isinstance(attr_value, types.GeneratorType):
              attr_value = [v for v in attr_value]
            if attr not in ['pdf', 'html']:
              print(f'{attr}: {attr_value}')
          except AttributeError as e:
            print(e)

  @mock_vcr.use_cassette
  def test_get_report_by_id(self):
    report_id = '22-00018039'

    report = self.reports_client.get(report_id)

    self.assertIsInstance(report, mandiant_threatintel.Report)
    self.assertIsNotNone(report.title)
    self.assertEqual(report.report_id, report_id)

  @mock_vcr.use_cassette
  def test_get_report_list_single_page_no_parameters(self):
    start_time = datetime.datetime.fromtimestamp(1662848797)
    reports = self.reports_client.get_list(start_epoch=start_time)

    reports_list = list(reports)

    self.assertIsInstance(reports_list[0], mandiant_threatintel.Report)

    self.assertEqual(len(reports_list), 1)

  @mock_vcr.use_cassette
  def test_get_report_list_multiple_pages_no_parameters(self):
    start_time = datetime.datetime.fromtimestamp(1662848797)
    reports = self.reports_client.get_list(start_epoch=start_time, page_size=1)

    reports_list = list(reports)
    for report in reports_list:
      with self.subTest():
        self.assertIsInstance(report, mandiant_threatintel.Report)

    self.assertEqual(len(reports_list), 2)

  @freeze_time(datetime.datetime.fromtimestamp(1668591000))
  @mock_vcr.use_cassette
  def test_get_report_list_single_page_with_parameters(self):
    start_time = datetime.datetime.fromtimestamp(1662848797)
    end_time = datetime.datetime.now()
    page_size = 50
    reports = self.reports_client.get_list(
        start_epoch=start_time, end_epoch=end_time, page_size=page_size
    )

    reports_list = list(reports)

    for report in reports_list:
      with self.subTest():
        self.assertIsInstance(report, mandiant_threatintel.Report)

    self.assertEqual(len(reports_list), 1)

  @freeze_time(datetime.datetime.fromtimestamp(1668591000))
  @mock_vcr.use_cassette
  def test_get_report_list_multiple_pages_with_parameters(self):
    start_time = datetime.datetime.fromtimestamp(1662848797)
    end_time = datetime.datetime.now()
    page_size = 1
    reports = self.reports_client.get_list(
        start_epoch=start_time, end_epoch=end_time, page_size=page_size
    )

    reports_list = list(reports)
    for report in reports_list:
      with self.subTest():
        self.assertIsInstance(report, mandiant_threatintel.Report)

    self.assertEqual(len(reports_list), 2)

  @freeze_time(datetime.datetime.fromtimestamp(1668591000))
  @mock_vcr.use_cassette
  def test_get_report_indicators_paginated(self):
    report = self.reports_client.get('22-00018620')

    indicators_list = list(report.indicators)
    for indicator in indicators_list:
      print(indicator.value)

    self.assertEqual(len(indicators_list), 60)


if __name__ == '__main__':
  unittest.main()
