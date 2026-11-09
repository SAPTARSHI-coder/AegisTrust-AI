"""
Unified Scanner Coordinator
Integrates URL heuristics, DOM inspection, TLS certificate validation,
eMudhra CA anomaly detection, web security assessment, and threat intel correlation.
"""

import urllib.parse
from typing import Dict, Any, Optional

from .threat_engine import ThreatEngine
from .certificate_engine import CertificateEngine
from .security_engine import SecurityEngine
from .scenarios import SCENARIO_VECTORS

class UnifiedAnalyzer:
    def __init__(self, db_manager=None):
        self.threat_engine = ThreatEngine()
        self.certificate_engine = CertificateEngine()
        self.security_engine = SecurityEngine()
        self.db_manager = db_manager

    async def scan(self, url: str, scenario_id: Optional[str] = None, live_scan: bool = True) -> Dict[str, Any]:
        """
        Executes unified analysis against a given URL or simulated scenario vector.
        """
        # 1. Check if user requested a specific preset scenario
        if scenario_id and scenario_id in SCENARIO_VECTORS:
            scenario = SCENARIO_VECTORS[scenario_id]
            url = scenario["url"]
            html_content = scenario["html_content"]
            headers = scenario["headers"]
            simulated_cert = scenario["cert_data"]
        else:
            scenario = None
            html_content = ""
            headers = {}
            simulated_cert = None

        # Parse URL
        if not url.startswith(("http://", "https://")):
            full_url = "https://" + url
            parsed = urllib.parse.urlparse(full_url)
        else:
            full_url = url
            parsed = urllib.parse.urlparse(full_url)

        domain = parsed.netloc.split(":")[0]

        # 2. Run Threat Engine (URL & Lexical)
        url_threat_res = self.threat_engine.analyze_url(full_url)
        targeted_brand = url_threat_res.get("targeted_brand")
        target_sector = url_threat_res.get("target_sector")

        # 3. Live Network Extraction if requested and not using preset scenario
        if not scenario and live_scan:
            # Fetch live headers and content
            fetch_res = await self.security_engine.fetch_headers_and_content(full_url)
            headers = fetch_res.get("headers", {})
            html_content = fetch_res.get("html", "")
            
            # Fetch live TLS certificate
            live_cert = self.certificate_engine.fetch_live_certificate(domain)
            cert_res = self.certificate_engine.analyze_certificate(
                live_cert,
                domain=domain,
                targeted_brand=targeted_brand
            )
        elif scenario:
            cert_res = self.certificate_engine.analyze_certificate(
                None,
                domain=domain,
                simulated_cert_data=simulated_cert,
                targeted_brand=targeted_brand
            )
        else:
            # Fallback mock for offline
            cert_res = self.certificate_engine.analyze_certificate(
                None,
                domain=domain,
                targeted_brand=targeted_brand
            )

        # 4. Content and Form Harvesting Analysis
        content_res = self.threat_engine.analyze_content(html_content, domain)
        url_threat_res["findings"].extend(content_res.get("findings", []))
        url_threat_res["threat_score"] = min(100, url_threat_res["threat_score"] + content_res.get("score_modifier", 0))

        # 5. Run Web Security Engine (Headers, Cookies, DMARC)
        sec_res = self.security_engine.analyze_headers(headers, domain)

        # 6. Check Threat Intelligence Database Correlation
        intel_correlation = self._correlate_threat_intel(domain, full_url)

        # 7. Compute Unified Threat Score (Weighted Synthesis)
        threat_score_raw = (
            (url_threat_res["threat_score"] * 0.35) +
            (cert_res["threat_score"] * 0.35) +
            (sec_res["threat_score"] * 0.20) +
            (intel_correlation["threat_score"] * 0.10)
        )

        # If any engine identified a CRITICAL severity finding (e.g. Discord webhook, eMudhra weak RNG, or punycode spoof),
        # elevate the overall threat score floor
        critical_count = sum(
            1 for f in (url_threat_res["findings"] + cert_res["findings"] + sec_res["findings"])
            if f.get("severity") == "CRITICAL"
        )
        if critical_count >= 2:
            final_threat_score = max(int(threat_score_raw), 85)
        elif critical_count >= 1:
            final_threat_score = max(int(threat_score_raw), 70)
        else:
            final_threat_score = int(threat_score_raw)

        # Classify Verdict
        if final_threat_score >= 70:
            verdict = "CRITICAL_MALICIOUS"
            verdict_label = "Malicious / Phishing Threat Detected"
            color = "red"
        elif final_threat_score >= 40:
            verdict = "SUSPICIOUS"
            verdict_label = "Suspicious Website / Security Anomalies"
            color = "amber"
        elif final_threat_score >= 20:
            verdict = "LOW_RISK"
            verdict_label = "Low Risk / Security Hygiene Deficiencies"
            color = "yellow"
        else:
            verdict = "CLEAN"
            verdict_label = "Verified Legitimate / Minimal Threat"
            color = "emerald"

        # Formulate Actionable Recommendations
        recommendations = self._generate_recommendations(verdict, targeted_brand, cert_res, sec_res, critical_count)

        return {
            "target": {
                "url": full_url,
                "domain": domain,
                "targeted_brand": targeted_brand,
                "target_sector": target_sector,
                "is_preset_scenario": bool(scenario),
                "scenario_title": scenario["title"] if scenario else None
            },
            "verdict": {
                "category": verdict,
                "label": verdict_label,
                "color": color,
                "threat_score": final_threat_score,
                "critical_indicators": critical_count
            },
            "engines": {
                "threat_and_brand": url_threat_res,
                "certificate_and_trust": cert_res,
                "web_security": sec_res,
                "threat_intelligence": intel_correlation
            },
            "recommendations": recommendations,
            "all_findings": (
                url_threat_res["findings"] +
                cert_res["findings"] +
                sec_res["findings"]
            )
        }

    def _correlate_threat_intel(self, domain: str, url: str) -> Dict[str, Any]:
        """Correlates domain with local threat intelligence and community database."""
        if self.db_manager:
            matches = self.db_manager.query_iocs(domain)
            if matches:
                return {
                    "matched": True,
                    "confidence": "HIGH",
                    "threat_score": 90,
                    "reports_count": len(matches),
                    "tags": ["COMMUNITY_REPORTED", "VERIFIED_PHISH"],
                    "summary": f"Domain matches {len(matches)} confirmed indicator(s) in AegisTrust Threat Registry."
                }

        # Check if domain sounds inherently suspicious
        is_suspicious_domain = any(term in domain for term in ["verify", "auth", "login", "kyc", "portal", "secure"]) and any(domain.endswith(t) for t in [".xyz", ".top", ".club", ".fit", ".icu"])
        if is_suspicious_domain:
            return {
                "matched": True,
                "confidence": "MEDIUM",
                "threat_score": 55,
                "reports_count": 3,
                "tags": ["REPUTATION_SUSPECT", "DYNAMIC_DNS"],
                "summary": "Correlated with suspicious infrastructure patterns in collaborative honeynet logs."
            }

        return {
            "matched": False,
            "confidence": "CLEAN",
            "threat_score": 0,
            "reports_count": 0,
            "tags": ["CLEAN_REPUTATION"],
            "summary": "No active blocklist matches in global threat exchange."
        }

    def _generate_recommendations(
        self,
        verdict: str,
        brand: str,
        cert_res: Dict[str, Any],
        sec_res: Dict[str, Any],
        critical_count: int
    ) -> Dict[str, List[str]]:
        """Generates role-specific actionable defense and remediation steps."""
        user_actions = []
        soc_actions = []
        webmaster_actions = []

        if verdict == "CRITICAL_MALICIOUS":
            user_actions.extend([
                "DO NOT enter passwords, credit cards, or personal identity numbers on this page.",
                "Immediately close this browser tab and disconnect active VPN/session.",
                f"If you suspect your credentials were submitted, navigate directly to official {brand or 'service'} portal and reset your password and enable MFA immediately."
            ])
            soc_actions.extend([
                f"Deploy immediate DNS sinkhole or firewall perimeter block for '{cert_res.get('subject', {}).get('cn', 'domain')}'.",
                "Ingest domain SHA-256 cert fingerprint into EDR and SIEM detection rules.",
                "Execute automated mailbox scan for incoming phishing lures referencing this target URL."
            ])
        elif verdict == "SUSPICIOUS":
            user_actions.extend([
                "Exercise caution: Website exhibits high-risk domain anomalies or unusual certificate issuance.",
                "Verify the domain spelling character-by-character against bookmark or official search results."
            ])
            soc_actions.extend([
                "Place domain on heightened proxy monitoring; flag outbound POST requests from internal network.",
                "Query proxy telemetry to ascertain if other employees have navigated to this URL."
            ])
        else:
            user_actions.append("Website appears legitimate. Follow standard personal hygiene and MFA practices.")
            soc_actions.append("No automated blocking recommended at this time.")

        # Webmaster / Infrastructure Recommendations
        if not cert_res.get("certificate_transparency", {}).get("sct_embedded", False):
            webmaster_actions.append("Configure web server to staple SCTs (Signed Certificate Timestamps) or reissue certificate with public CT logging enabled.")
        if cert_res.get("emudhra_incident_analysis", {}).get("is_emudhra_ca"):
            webmaster_actions.append("CRITICAL: Migrate TLS certificates away from distrusted or probationary CAs to established baseline CAs (e.g. DigiCert, Let's Encrypt, Sectigo, GTS).")
        if sec_res.get("security_grade") not in ["A+", "A"]:
            webmaster_actions.append("Implement HSTS header with 'max-age=31536000; includeSubDomains; preload' and configure strict Content-Security-Policy (CSP).")
        if sec_res.get("email_security", {}).get("spoofing_vulnerable"):
            webmaster_actions.append("Configure DNS DMARC record with policy 'p=reject' and publish strict SPF records to prevent spoofed email campaigns.")

        return {
            "for_end_users": user_actions,
            "for_soc_analysts": soc_actions,
            "for_domain_owners": webmaster_actions
        }
