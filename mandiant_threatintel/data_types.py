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

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
import typing
from typing import List, Optional, Union


def filter_dataclass_attributes(cls: "class", input_data: dict) -> dict:
  """Returns a dictionary containing only attributes that exist as part of a dataclass

  Args:
    cls: A Python `dataclass`
    input_data: A dictionary containing data intended to be passed as `kwargs`
  """
  return {k: v for k, v in input_data.items() if k in cls.__annotations__}


@dataclass
class Alias:
  name: str
  attribution_scope: Optional[str] = None
  alias: Optional[str] = None
  company: Optional[str] = None

  @classmethod
  def from_api(cls, input_data: typing.Union[dict, str]) -> Alias:
    if isinstance(input_data, str):
      return Alias(name=input_data)
    elif isinstance(input_data, dict):
      return Alias(**filter_dataclass_attributes(cls, input_data))


@dataclass
class Audience:
  name: str
  license: Optional[str] = None

  @classmethod
  def from_api(cls, input_data: typing.Union[dict, str]) -> Audience:
    if isinstance(input_data, str):
      return Audience(name=input_data)
    elif isinstance(input_data, dict):
      return Audience(**filter_dataclass_attributes(cls, input_data))


@dataclass
class Motivation:
  id: Optional[str]
  name: str
  attribution_scope: Optional[str]

  @classmethod
  def from_api(cls, input_data: typing.Union[dict, str]) -> Motivation:
    if isinstance(input_data, str):
      return Motivation(name=input_data)
    elif isinstance(input_data, dict):
      return Motivation(**filter_dataclass_attributes(cls, input_data))


@dataclass
class AttackPattern:
  created: datetime
  name: str
  x_mitre_is_subtechnique: bool
  attack_pattern_identifier: str
  description: str
  modified: datetime
  id: str
  sub_techniques: List[AttackPattern] = field(default_factory=list)

  @classmethod
  def from_api(cls, input_data: dict) -> AttackPattern:
    return AttackPattern(**filter_dataclass_attributes(cls, input_data))


class PaginationTypeEnum(Enum):
  NEXT = "next"
  OFFSET = "offset"
  NONE = None


class DTMAlertStatusEnum(Enum):
  NEW = "new"
  READ = "read"
  CLOSED = "closed"


class DTMDocumentTypeEnum(Enum):
  DOCUMENT_ANALYSIS = "document_analysis"
  DOMAIN_DISCOVERY = "domain_discovery"
  EMAIL_ANALYSIS = "email_analysis"
  FORUM_POST = "forum_post"
  PASTE = "paste"
  SHOP_LISTING = "shop_listing"
  TWEET = "tweet"
  WEB_CONTENT_PUBLISH = "web_content_publish"
  MESSAGE = "message"


class DTMMonitorTopicEnum(Enum):
  ACCESS_TOKEN = "access_token"
  ATOM_ADDRESS = "atom_address"
  BCH_ADDRESS = "bch_address"
  BIN = "bin"
  BRAND = "brand"
  BTC_ADDRESS = "btc_address"
  CITY = "city"
  CLIENT_IDENTIFIER = "client_identifier"
  COUNTRY = "country"
  CRYPTO_KEY_PRIVATE = "crypto_key_private"
  CRYPTO_KEY_PUBLIC = "crypto_key_public"
  CVE = "cve"
  CWE = "cwe"
  DASH_ADDRESS = "dash_address"
  DOGE_ADDRESS = "doge_address"
  DOMAIN = "domain"
  EMAIL_ADDRESS = "email_address"
  FILENAME = "filename"
  HASHTAG = "hashtag"
  ICQ_UIN = "icq_uin"
  IDENTITY_NAME = "identity_name"
  IPV4_ADDRESS = "ipv4_address"
  IPV6_ADDRESS = "ipv6_address"
  JID = "jid"
  LOCATION_NAME = "location_name"
  LTC_ADDRESS = "ltc_address"
  MAC_ADDRESS = "mac_address"
  MD5_HASH = "md5_hash"
  NAME = "name"
  ORGANIZATION = "organization"
  PASSWORD_PLAINTEXT = "password_plaintext"
  PATH = "path"
  PHONE_NUMBER = "phone_number"
  PREDICT_PASSWORD_PLAINTEXT = "predict_password_plaintext"
  PRODUCT = "product"
  PRODUCT_BATCH_NAME = "product_batch_name"
  REGISTRY_KEY = "registry_key"
  SERVICE_NAME = "service_name"
  SHA1_HASH = "sha1_hash"
  SHA256_HASH = "sha256_hash"
  TELEGRAM_USER_NAME = "telegram_user_name"
  THREAT_GROUP_NAME = "threat_group_name"
  THREAT_NAME = "threat_name"
  TWITTER_HANDLE = "twitter_handle"
  URL = "url"
  XLM_ADDRESS = "xml_address"
  XMR_ADDRESS = "xmr_address"

  GROUP_BRAND = "group_brand"
  GROUP_IDENTITY = "group_identity"
  GROUP_NETWORK = "group_network"
  GROUP_BIN = "group_bin"
  GROUP_LOCATION = "group_location"
  GROUP_PATHS = "group_paths"
  GROUP_THREATS = "group_threats"
  GROUP_KEYS = "group_keys"
  GROUP_HASH = "group_hash"
  GROUP_SOCIAL = "group_social"
  GROUP_CRYPTO = "group_crypto"

  LABEL_TYPE = "label_type"
  LABEL_LANGUAGE = "label_language"
  LABEL_INDUSTRY = "label_industry"
  LABEL_THREAT = "label_threat"
  LABEL_CONTENT = "label_content"

  DOC_TYPE = "doc_type"
  SOURCE = "source"
  MATCH_CONDITIONS = "match_conditions"
  TYPOSQUATTED_DOMAIN = "typosquatted_domain"
  LUCENE = "lucene"
  KEYWORD = "keyword"


@dataclass
class DTMMonitor:
  name: str
  description: str
  doc_condition: DTMMonitorCondition
  enabled: Optional[bool] = None
  email_notify_enabled: bool = False
  email_notify_immediate: bool = False
  id: Optional[str] = None
  updated_at: Optional[datetime] = None
  created_at: Optional[datetime] = None
  template_id: Optional[str] = None
  created_by_user_id: Optional[str] = None
  last_updated_by_user_id: Optional[str] = None
  created_by_user_email: Optional[str] = None
  last_updated_user_email: Optional[str] = None
  disabled_code: Optional[str] = None
  disabled_reason: Optional[str] = None

  def __post_init__(self):
    if not isinstance(self.doc_condition, DTMMonitorCondition):
      self.doc_condition = DTMMonitorCondition(**self.doc_condition)


class DTMMonitorOperatorEnum(Enum):
  MUST_EQUAL = "must_equal"
  MUST_NOT_EQUAL = "must_not_equal"
  MUST_START_WITH = "must_start_with"
  MUST_NOT_START_WITH = "must_not_start_with"
  MUST_END_WITH = "must_end_with"
  MUST_NOT_END_WITH = "must_not_end_with"
  MUST_CONTAIN = "must_contain"
  MUST_NOT_CONTAIN = "must_not_contain"
  ALL = "all"
  ANY = "any"


class DTMMonitorCondition:
  operator: DTMMonitorOperatorEnum
  topic: DTMMonitorTopicEnum
  match: typing.List[typing.Union[str, DTMMonitorCondition]]

  def __init__(
      self,
      operator: DTMMonitorOperatorEnum,
      topic: DTMMonitorTopicEnum,
      match: typing.List[typing.Union[str, DTMMonitorCondition]],
  ):
    if topic != DTMMonitorTopicEnum.MATCH_CONDITIONS:
      for m in match:
        if isinstance(m, DTMMonitorCondition):
          raise ValueError(
              f"{topic.value} is not allowed to have nested DTMMonitorCondition"
          )

    if isinstance(operator, str):
      operator = DTMMonitorOperatorEnum(operator)
    self.operator = operator
    if isinstance(topic, str):
      topic = DTMMonitorTopicEnum(topic)
    self.topic = topic
    self.match = match

  def json(self) -> typing.Dict:
    output = {
        "operator": self.operator.value,
        "topic": self.topic.value,
        "match": [],
    }

    for i in self.match:
      if isinstance(i, DTMMonitorCondition):
        output["match"].append(i.json())
      else:
        output["match"].append(i)

    return output

  @classmethod
  def from_json(cls, input_json: typing.Dict) -> DTMMonitorCondition:
    topic = DTMMonitorTopicEnum(input_json.get("topic"))
    match = []

    if topic == DTMMonitorTopicEnum.MATCH_CONDITIONS:
      match = [
          DTMMonitorCondition.from_json(i) for i in input_json.get("match", [])
      ]
    else:
      match = input_json.get("match", [])

    return DTMMonitorCondition(
        operator=input_json.get("operator"), topic=topic, match=match
    )


@dataclass
class DTMEmailSettings:
  created_at: typing.Optional[datetime]
  updated_at: typing.Optional[datetime]
  delivery_times: typing.List[DTMEmailDeliveryTimeEnum]
  recipients: typing.List[DTMEmailRecipient]
  timezone_location: str
  id: typing.Optional[str]
  frequency: typing.List[DTMEmailFrequencyEnum]

  def __post_init__(self):
    delivery_times = []
    for i in self.delivery_times:
      if isinstance(i, str):
        delivery_times.append(DTMEmailDeliveryTimeEnum(i))
      else:
        delivery_times.append(i)

    self.delivery_times = delivery_times

    recipients = []
    for i in self.recipients:
      if isinstance(i, str):
        recipients.append(DTMEmailRecipient(email_address=i))
      else:
        recipients.append(i)

    self.recipients = recipients

    frequency = []
    for i in self.frequency:
      if isinstance(i, str):
        frequency.append(DTMEmailFrequencyEnum(i))
      else:
        frequency.append(i)

    self.frequency = frequency

  def json(self):
    return {
        "delivery_times": [i.value for i in self.delivery_times],
        "recipients": [asdict(i) for i in self.recipients],
        "timezone_location": self.timezone_location,
        "frequency": [i.value for i in self.frequency],
    }


class DTMEmailDeliveryTimeEnum(Enum):
  H00M00 = "00:00"
  H00M30 = "00:30"
  H01M00 = "01:00"
  H01M30 = "01:30"
  H02M00 = "02:00"
  H02M30 = "02:30"
  H03M00 = "03:00"
  H03M30 = "03:30"
  H04M00 = "04:00"
  H04M30 = "04:30"
  H05M00 = "05:00"
  H05M30 = "05:30"
  H06M00 = "06:00"
  H06M30 = "06:30"
  H07M00 = "07:00"
  H07M30 = "07:30"
  H08M00 = "08:00"
  H08M30 = "08:30"
  H09M00 = "09:00"
  H09M30 = "09:30"
  H10M00 = "10:00"
  H10M30 = "10:30"
  H11M00 = "11:00"
  H11M30 = "11:30"
  H12M00 = "12:00"
  H12M30 = "12:30"
  H13M00 = "13:00"
  H13M30 = "13:30"
  H14M00 = "14:00"
  H14M30 = "14:30"
  H15M00 = "15:00"
  H15M30 = "15:30"
  H16M00 = "16:00"
  H16M30 = "16:30"
  H17M00 = "17:00"
  H17M30 = "17:30"
  H18M00 = "18:00"
  H18M30 = "18:30"
  H19M00 = "19:00"
  H19M30 = "19:30"
  H20M00 = "20:00"
  H20M30 = "20:30"
  H21M00 = "21:00"
  H21M30 = "21:30"
  H22M00 = "22:00"
  H22M30 = "22:30"
  H23M00 = "23:00"
  H23M30 = "23:30"


class DTMEmailFrequencyEnum(Enum):
  SUNDAY = "sunday"
  MONDAY = "monday"
  TUESDAY = "tuesday"
  WEDNESDAY = "wednesday"
  THURSDAY = "thursday"
  FRIDAY = "friday"
  SATURDAY = "saturday"


@dataclass
class DTMEmailRecipient:
  email_address: str
  status: typing.Optional[str]
  verification_sent_at: typing.Optional[datetime]
