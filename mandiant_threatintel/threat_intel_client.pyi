from typing import List, Dict

from mandiant_threatintel.threat_intel_client import ThreatIntelClient
from mandiant_threatintel.data_types import *

class ThreatIntelClient: ...

class Malware:
    actors: List[ThreatActor]
    audience: List[Audience]
    description: str
    detections: List
    id: str
    industries: List
    inherently_malicious: bool
    last_activity_time: datetime
    last_updated: datetime
    malware: List[Malware]
    name: str
    operating_systems: List[str]
    type: str
    yara: List
    is_publishable: bool
    intel_free: bool
    aliases: List[Alias]
    capabilities: List
    cve: List
    roles: List[str]
    reports: List[Report]
    attack_patterns: List[AttackPattern]

    @classmethod
    def from_json_response(cls, response: dict, client: ThreatIntelClient): ...
    @classmethod
    def from_identifier(cls, identifier: str, client: ThreatIntelClient): ...

class Report:
    title: str
    pdf: bytes
    indicators: List
    report_type: str
    document_type: str
    type_of_report: str
    version: str
    publish_date: datetime
    report_id: str
    title_full_text: str
    requester_org_id: str
    related_reports: List[Report]
    story_link: str
    delivery_option: str
    outlet: str
    customer_sensitive: bool
    active: bool
    no_threat_scapes: bool
    from_media: str
    threat_scape: List
    tmh_accuracy_ranking: str
    tag_version: str
    isight_comment: str
    actors: List[ThreatActor]
    affected_industries: List[str]
    affected_systems: List[str]
    intended_effects: List[str]
    motivations: List[str]
    source_geographies: List[str]
    ttps: List[str]
    target_geographies: List[str]
    targeted_information: List[str]
    relations: List
    files: List[dict[str, str]]
    cvss_base_score: str
    cvss_temporal_score: str
    zero_day: bool
    in_the_wild: bool
    report_confidence: str
    version: str
    previous_versions: list[dict[str, str]]
    threat_detail: str

    @classmethod
    def from_json_response(cls, response: dict, client: ThreatIntelClient): ...
    @classmethod
    def from_identifier(cls, identifier: str, client: ThreatIntelClient): ...

class ThreatActor:
    id: str
    name: str
    description: str
    last_updated: datetime
    audience: List[Audience]
    motivations: List[Motivation]
    aliases: List[Alias]
    industries: List
    observed: List
    malware: List[Malware]
    tools: List[Malware]
    locations: List
    cve: List
    last_activity_time: datetime
    suspected_attribution: List
    associated_uncs: List[ThreatActor]
    is_publishable: bool
    intel_free: bool
    reports: List[Report]
    attack_patterns: List[AttackPattern]
    history: List
    suspected_groups: List

    @classmethod
    def from_json_response(cls, response: dict, client: ThreatIntelClient): ...
    @classmethod
    def from_identifier(cls, identifier: str, client: ThreatIntelClient): ...

class Vulnerability:
    id: str
    type: str
    is_publishable: bool
    risk_rating: str
    analysis: str
    executive_summary: str
    description: str
    exploitation_vectors: List[str]
    title: str
    associated_actors: List[ThreatActor]
    associated_malware: List[Malware]
    associated_reports: List[Report]
    exploitation_consequence: str
    cwe: str
    cve_id: str
    vulnerable_products: str
    exploitation_state: str
    vendor_fix_references: List
    date_of_disclosure: datetime
    observed_in_the_wild: bool
    vulnerable_cpes: List
    was_zero_day: bool
    workarounds: List
    publish_date: datetime
    updated_date: datetime
    last_modified_date: datetime
    available_mitigation: List[str]
    sources: List
    exploits: List
    common_vulnerablity_scores: Dict
    audience: List
    intel_free: bool
    affects_ot: bool
    aliases: List[str]
    cisa_known_exploited: bool
    cpe_ranges: List
    cwe_details: str
    days_to_patch: str
    epss: str
    version_history: List
    workarounds_list: []

class MD5Indicator:
    id: str
    mscore: int
    type: str
    value: str
    is_publishable: bool
    sources: List
    misp: Dict
    last_updated: datetime
    first_seen: datetime
    last_seen: datetime
    md5: str
    sha1: str
    sha256: str
    attributed_associations: List

class FQDNIndicator:
    id: str
    mscore: int
    type: str
    value: str
    is_publishable: bool
    sources: List
    misp: Dict
    last_updated: datetime
    first_seen: datetime
    last_seen: datetime
    attributed_associations: List

class URLIndicator:
    id: str
    mscore: int
    type: str
    value: str
    is_publishable: bool
    sources: List
    misp: Dict
    last_updated: datetime
    first_seen: datetime
    last_seen: datetime
    attributed_associations: List

class IPIndicator:
    id: str
    mscore: int
    type: str
    value: str
    is_publishable: bool
    sources: List
    misp: Dict
    last_updated: datetime
    first_seen: datetime
    last_seen: datetime
    attributed_associations: List
