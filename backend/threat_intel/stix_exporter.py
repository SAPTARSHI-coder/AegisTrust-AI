"""
STIX 2.1 Standard Threat Intelligence Bundle Exporter
Transforms detected phishing, malicious website indicators, and certificate
vulnerabilities into OASIS STIX 2.1 standard format for automated SIEM/SOAR ingestion.
"""

import uuid
import datetime
from typing import List, Dict, Any

class STIX21Exporter:
    def __init__(self):
        pass

    def export_bundle(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Converts AegisTrust threat intelligence entries into an OASIS STIX 2.1 Bundle.
        """
        bundle_id = f"bundle--{uuid.uuid4()}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Identity Object (AegisTrust Platform)
        identity_id = f"identity--{uuid.uuid4()}"
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "AegisTrust Threat Intelligence Exchange",
            "identity_class": "system",
            "sectors": ["cybersecurity", "financial-services", "education", "government"]
        }

        objects = [identity_obj]

        for report in reports:
            created_time = report.get("created_at", now_iso)
            domain = report.get("domain", "")
            url = report.get("url", "")
            threat_name = report.get("threat_type", "Phishing Campaign")
            brand = report.get("target_brand", "Unknown Entity")

            # 1. Indicator SDO
            indicator_id = f"indicator--{uuid.uuid4()}"
            pattern = f"[url:value = '{url}']" if url else f"[domain-name:value = '{domain}']"
            
            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created_by_ref": identity_id,
                "created": created_time,
                "modified": created_time,
                "name": f"Malicious Phishing Indicator: {brand} Impersonation",
                "description": report.get("evidence_notes", f"Phishing site impersonating {brand}"),
                "indicator_types": ["malicious-activity", "phishing"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": created_time,
                "confidence": min(100, int(report.get("risk_score", 75)))
            }
            objects.append(indicator_obj)

            # 2. Attack Pattern SDO
            attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
            attack_pattern_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id,
                "created_by_ref": identity_id,
                "created": created_time,
                "modified": created_time,
                "name": threat_name,
                "description": f"Adversary impersonating {brand} via deceptive domain infrastructure and credential harvesting.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1566.002",
                        "url": "https://attack.mitre.org/techniques/T1566/002/"
                    }
                ]
            }
            objects.append(attack_pattern_obj)

            # 3. Relationship SDO (indicates)
            relationship_id = f"relationship--{uuid.uuid4()}"
            rel_obj = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": relationship_id,
                "created_by_ref": identity_id,
                "created": created_time,
                "modified": created_time,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": attack_pattern_id
            }
            objects.append(rel_obj)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
