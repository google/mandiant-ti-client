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
from mandiant_threatintel import DTMDocumentTypeEnum
import vcr

mock_vcr = vcr.VCR(
    cassette_library_dir="fixtures/DTMDocsClient",
    decode_compressed_response=True,
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)


class Test_DTMDocsClient(unittest.TestCase):

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

    self.dtm_docs_client = self.base_client.DTMDocs

  @mock_vcr.use_cassette
  def test_get_by_id(self):
    doc = self.dtm_docs_client.get(
        DTMDocumentTypeEnum.WEB_CONTENT_PUBLISH,
        "21ecacbe-18b7-464f-a38a-f3c5d0ca4bd6",
    )

    self.assertIsInstance(doc, mandiant_threatintel.DTMDocument)

  @mock_vcr.use_cassette
  def test_get_labels_does_not_raise(self):
    doc = mandiant_threatintel.DTMDocument.from_json_response(
        {
            "__id": "21ecacbe-18b7-464f-a38a-f3c5d0ca4bd6",
            "__type": "web_content_publish",
        },
        self.base_client,
    )

    labels = doc.labels

    for l in labels:
      print(l)

  @mock_vcr.use_cassette
  def test_get_topics_does_not_raise(self):
    doc = mandiant_threatintel.DTMDocument.from_json_response(
        {
            "__id": "21ecacbe-18b7-464f-a38a-f3c5d0ca4bd6",
            "__type": "web_content_publish",
        },
        self.base_client,
    )

    topics = doc.topics

    for l in topics:
      print(l)

  @mock_vcr.use_cassette
  def test_search_no_params_one_page(self):
    doc = self.dtm_docs_client.search(query="test", size=26)[0]

    self.assertIsInstance(doc, mandiant_threatintel.DTMDocument)

  @mock_vcr.use_cassette
  def test_search_no_params_one_page(self):
    doc = next(self.dtm_docs_client.search(query="test", size=26))

    self.assertIsInstance(doc, mandiant_threatintel.DTMDocument)

  @mock_vcr.use_cassette
  def test_search_no_params_two_page(self):
    docs = [i for i in self.dtm_docs_client.search(query="test", size=1)]

    self.assertIsInstance(docs[0], mandiant_threatintel.DTMDocument)
    self.assertEqual(len(docs), 1)


if __name__ == "__main__":
  unittest.main()
