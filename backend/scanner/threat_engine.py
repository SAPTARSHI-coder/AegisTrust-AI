"""
Threat Analysis & Phishing Engine
Performs lexical, morphological, homoglyph, typosquatting/combosquatting,
and DOM/content credential-harvesting inspections.
"""

import re
import urllib.parse
from typing import Dict, List, Any, Optional

# Curated registry of high-value brands across critical sectors
BRAND_REGISTRY = {
    # Banking & Financial Services
    "chase": {"name": "JPMorgan Chase & Co.", "domain": "chase.com", "sector": "Banking & Finance"},
    "wellsfargo": {"name": "Wells Fargo", "domain": "wellsfargo.com", "sector": "Banking & Finance"},
    "bankofamerica": {"name": "Bank of America", "domain": "bankofamerica.com", "sector": "Banking & Finance"},
    "citibank": {"name": "Citibank", "domain": "citi.com", "sector": "Banking & Finance"},
    "paypal": {"name": "PayPal", "domain": "paypal.com", "sector": "Banking & Finance"},
    "stripe": {"name": "Stripe", "domain": "stripe.com", "sector": "Banking & Finance"},
    "sbi": {"name": "State Bank of India", "domain": "onlinesbi.sbi", "sector": "Banking & Finance"},
    "hdfc": {"name": "HDFC Bank", "domain": "hdfcbank.com", "sector": "Banking & Finance"},
    "barclays": {"name": "Barclays", "domain": "barclays.co.uk", "sector": "Banking & Finance"},
    "hsbc": {"name": "HSBC", "domain": "hsbc.com", "sector": "Banking & Finance"},
    "revolut": {"name": "Revolut", "domain": "revolut.com", "sector": "Banking & Finance"},
    "venmo": {"name": "Venmo", "domain": "venmo.com", "sector": "Banking & Finance"},

    # Education & Academia
    "oxford": {"name": "University of Oxford", "domain": "ox.ac.uk", "sector": "Education & Academia"},
    "harvard": {"name": "Harvard University", "domain": "harvard.edu", "sector": "Education & Academia"},
    "cambridge": {"name": "University of Cambridge", "domain": "cam.ac.uk", "sector": "Education & Academia"},
    "mit": {"name": "Massachusetts Institute of Technology", "domain": "mit.edu", "sector": "Education & Academia"},
    "stanford": {"name": "Stanford University", "domain": "stanford.edu", "sector": "Education & Academia"},
    "coursera": {"name": "Coursera", "domain": "coursera.org", "sector": "Education & Academia"},
    "blackboard": {"name": "Blackboard Learn", "domain": "blackboard.com", "sector": "Education & Academia"},

    # Government & Citizen Services
    "irs": {"name": "Internal Revenue Service (IRS)", "domain": "irs.gov", "sector": "Government & Public Services"},
    "incometax": {"name": "Income Tax Department", "domain": "incometax.gov.in", "sector": "Government & Public Services"},
    "uidai": {"name": "UIDAI / Aadhaar", "domain": "uidai.gov.in", "sector": "Government & Public Services"},
    "govuk": {"name": "GOV.UK", "domain": "gov.uk", "sector": "Government & Public Services"},
    "usps": {"name": "United States Postal Service", "domain": "usps.com", "sector": "Logistics & Public Services"},
    "dhl": {"name": "DHL Express", "domain": "dhl.com", "sector": "Logistics & Public Services"},

    # Recruitment & Career Portals
    "linkedin": {"name": "LinkedIn", "domain": "linkedin.com", "sector": "Recruitment & Professional"},
    "indeed": {"name": "Indeed", "domain": "indeed.com", "sector": "Recruitment & Professional"},
    "workday": {"name": "Workday", "domain": "workday.com", "sector": "Recruitment & Professional"},
    "greenhouse": {"name": "Greenhouse Software", "domain": "greenhouse.io", "sector": "Recruitment & Professional"},

    # Tech & Cloud SSO
    "google": {"name": "Google", "domain": "google.com", "sector": "Technology & Cloud"},
    "microsoft": {"name": "Microsoft 365", "domain": "microsoft.com", "sector": "Technology & Cloud"},
    "apple": {"name": "Apple iCloud", "domain": "apple.com", "sector": "Technology & Cloud"},
    "amazon": {"name": "Amazon", "domain": "amazon.com", "sector": "E-Commerce & Cloud"},
    "netflix": {"name": "Netflix", "domain": "netflix.com", "sector": "Entertainment & Streaming"},
    "dropbox": {"name": "Dropbox", "domain": "dropbox.com", "sector": "Technology & Cloud"},

    # Cryptocurrency & Web3
    "binance": {"name": "Binance", "domain": "binance.com", "sector": "Cryptocurrency & Web3"},
    "coinbase": {"name": "Coinbase", "domain": "coinbase.com", "sector": "Cryptocurrency & Web3"},
    "metamask": {"name": "MetaMask", "domain": "metamask.io", "sector": "Cryptocurrency & Web3"},
    "phantom": {"name": "Phantom Wallet", "domain": "phantom.app", "sector": "Cryptocurrency & Web3"},
    "opensea": {"name": "OpenSea", "domain": "opensea.io", "sector": "Cryptocurrency & Web3"},
}

HIGH_RISK_TLDS = {
    "top", "xyz", "club", "work", "buzz", "fit", "icu", "tk", "ml", "ga", "cf", "gq",
    "link", "click", "download", "racing", "stream", "live", "rest", "surf", "date",
    "men", "loan", "win", "bid", "accountant", "science", "party"
}

COMBOSQUAT_KEYWORDS = [
    "login", "verify", "secure", "portal", "update", "auth", "account",
    "support", "service", "kyc", "claim", "refund", "billing", "signin",
    "recover", "wallet", "connect", "access", "resolve", "validation",
    "confirm", "alert", "security", "online", "official", "careers", "apply"
]

HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0455': 's', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j',
    # Greek lookalikes
    '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p', '\u03c5': 'u', '\u03bd': 'v',
    # Numbers used as letters
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
}

SUSPICIOUS_URGENCY_PATTERNS = [
    r"urgent\s+action\s+required",
    r"account\s+(?:suspended|restricted|blocked|disabled)",
    r"within\s+\d+\s*(?:hours|mins|minutes)",
    r"immediate\s+kyc\s+verification",
    r"unauthorized\s+access\s+detected",
    r"security\s+alert.*verify",
    r"confirm\s+your\s+identity",
    r"tax\s+refund\s+pending",
    r"claim\s+your\s+(?:refund|grant|lottery|prize|reward)",
    r"job\s+offer\s+confirmed.*registration\s+fee",
    r"connect\s+wallet.*claim\s+airdrop",
    r"update\s+payment\s+method\s+immediately"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class ThreatEngine:
    def __init__(self):
        pass

    def analyze_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Performs in-depth lexical, morphological, homoglyph, and brand impersonation analysis.
        """
        # Ensure scheme for URL parsing
        if not raw_url.startswith(("http://", "https://")):
            parsed_test = urllib.parse.urlparse("http://" + raw_url)
            full_url = "https://" + raw_url
        else:
            parsed_test = urllib.parse.urlparse(raw_url)
            full_url = raw_url

        netloc = parsed_test.netloc.lower()
        if "@" in netloc:
            # Strips userinfo if embedded (e.g. http://google.com@evil.com)
            netloc = netloc.split("@")[-1]
        
        hostname = netloc.split(":")[0]  # remove port if present
        path = parsed_test.path
        query = parsed_test.query

        findings: List[Dict[str, Any]] = []
        risk_score = 0
        targeted_brand = None
        target_sector = None

        # 1. IP Address as Hostname
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        if is_ip:
            risk_score += 35
            findings.append({
                "category": "Lexical Analysis",
                "severity": "CRITICAL",
                "title": "Raw IP Address as Hostname",
                "detail": f"Website is addressed directly via IP ({hostname}) rather than a legitimate FQDN. Common in ephemeral phishing nodes and C2 servers.",
                "penalty": 35
            })

        # 2. Punycode / IDN Homoglyph Detection
        is_punycode = hostname.startswith("xn--") or ".xn--" in hostname
        decoded_hostname = hostname
        has_homoglyphs = False
        homoglyph_details = []

        if is_punycode:
            try:
                decoded_hostname = hostname.encode("ascii").decode("idna")
            except Exception:
                decoded_hostname = hostname

        # Inspect decoded hostname for mixed script or non-latin lookalikes
        for char in decoded_hostname:
            if char in HOMOGLYPH_MAP:
                has_homoglyphs = True
                homoglyph_details.append(f"'{char}' -> '{HOMOGLYPH_MAP[char]}'")

        if is_punycode or has_homoglyphs:
            penalty = 40
            risk_score += penalty
            findings.append({
                "category": "Homoglyph & Punycode",
                "severity": "CRITICAL",
                "title": "Internationalized Domain Spoofing / Lookalike Homoglyph Detected",
                "detail": f"Domain utilizes Punycode ('{hostname}') or visually identical unicode characters to spoof legitimate brand identities: {', '.join(set(homoglyph_details[:4]))}.",
                "penalty": penalty
            })

        # 3. High-Risk TLD Analysis
        domain_parts = hostname.split(".")
        tld = domain_parts[-1] if len(domain_parts) > 1 else ""
        if tld in HIGH_RISK_TLDS:
            penalty = 20
            risk_score += penalty
            findings.append({
                "category": "Domain Infrastructure",
                "severity": "HIGH",
                "title": f"High-Abuse Top-Level Domain (.{tld})",
                "detail": f"The top-level domain '.{tld}' possesses a disproportionately high incidence of phishing and spam according to global threat intelligence registries.",
                "penalty": penalty
            })

        # 4. Excessive Subdomains & Token Stuffing
        if len(domain_parts) >= 4 and not is_ip:
            penalty = 15
            risk_score += penalty
            findings.append({
                "category": "Lexical Analysis",
                "severity": "MEDIUM",
                "title": f"Excessive Subdomain Stacking ({len(domain_parts)} labels)",
                "detail": f"Domain contains {len(domain_parts)} subdomain levels ('{hostname}'). Attackers commonly stack subdomains (e.g., login.verify.chase.com.evil-portal.net) to deceive mobile users where URL bars are truncated.",
                "penalty": penalty
            })

        # 5. Hyphen and Digit Abuse
        hyphen_count = hostname.count("-")
        if hyphen_count >= 2:
            penalty = 15
            risk_score += penalty
            findings.append({
                "category": "Lexical Analysis",
                "severity": "MEDIUM",
                "title": f"Suspicious Hyphen Concatenation ({hyphen_count} hyphens)",
                "detail": "High frequency of hyphens in hostname is a hallmark of combosquatting campaigns.",
                "penalty": penalty
            })

        # 6. Combosquatting & Brand Typosquatting Check
        normalized_host = decoded_hostname.replace("-", "").replace(".", "")
        matched_brand_key = None

        for brand_key, brand_info in BRAND_REGISTRY.items():
            legit_domain = brand_info["domain"].lower()
            
            # Exact legitimate match - this is the real site!
            if hostname == legit_domain or hostname.endswith("." + legit_domain):
                # Clean match!
                targeted_brand = brand_info["name"]
                target_sector = brand_info["sector"]
                matched_brand_key = brand_key
                break

            # Brand name appears in hostname or path
            if brand_key in hostname:
                matched_brand_key = brand_key
                targeted_brand = brand_info["name"]
                target_sector = brand_info["sector"]

                # Check if it has combosquatting keywords
                found_keywords = [kw for kw in COMBOSQUAT_KEYWORDS if kw in hostname or kw in path.lower()]
                penalty = 45 if found_keywords else 30
                risk_score += penalty

                findings.append({
                    "category": "Brand Impersonation",
                    "severity": "CRITICAL",
                    "title": f"Combosquatting Impersonation targeting {brand_info['name']}",
                    "detail": f"Domain '{hostname}' illegitimately incorporates brand keyword '{brand_key}' combined with security/login lures ({', '.join(found_keywords) if found_keywords else 'suspicious domain structure'}). Legitimate service resides at '{legit_domain}'.",
                    "penalty": penalty
                })
                break

            # Typosquatting (Levenshtein distance <= 2 on main domain token)
            main_token = domain_parts[0] if len(domain_parts) >= 2 else hostname
            dist = levenshtein_distance(main_token, brand_key)
            if dist in [1, 2] and len(brand_key) > 3:
                matched_brand_key = brand_key
                targeted_brand = brand_info["name"]
                target_sector = brand_info["sector"]
                penalty = 35
                risk_score += penalty

                findings.append({
                    "category": "Brand Impersonation",
                    "severity": "CRITICAL",
                    "title": f"Typosquatting Detected (Edit Distance: {dist})",
                    "detail": f"Domain label '{main_token}' is a near-identical typosquat variation of legitimate protected entity '{brand_info['name']}' ({legit_domain}).",
                    "penalty": penalty
                })
                break

        # 7. Suspicious Path & Query Signatures
        suspicious_params = ["redirect_to", "next", "url", "dest", "auth_token", "session_payload", "kyc_doc"]
        for param in suspicious_params:
            if f"{param}=" in query.lower() or f"{param}=" in path.lower():
                risk_score += 15
                findings.append({
                    "category": "Evasion & Redirection",
                    "severity": "MEDIUM",
                    "title": f"Suspicious Open Redirect / Exfiltration Parameter ('{param}')",
                    "detail": f"URL carries parameter '{param}' typically exploited in open redirect chains or credential token passing.",
                    "penalty": 15
                })
                break

        # If it was confirmed exact legitimate domain, cancel spoofing penalties
        if matched_brand_key and (hostname == BRAND_REGISTRY[matched_brand_key]["domain"] or hostname.endswith("." + BRAND_REGISTRY[matched_brand_key]["domain"])):
            risk_score = 0
            findings = [f for f in findings if f["category"] != "Brand Impersonation"]
            findings.append({
                "category": "Identity Verification",
                "severity": "INFO",
                "title": f"Verified Domain for {targeted_brand}",
                "detail": f"Hostname matches legitimate registered domain '{BRAND_REGISTRY[matched_brand_key]['domain']}'.",
                "penalty": 0
            })

        return {
            "engine": "Threat & Brand Analysis",
            "hostname": hostname,
            "url": full_url,
            "is_ip": is_ip,
            "is_punycode": is_punycode,
            "has_homoglyphs": has_homoglyphs,
            "targeted_brand": targeted_brand or "Generic / Unclassified",
            "target_sector": target_sector or "General Web",
            "findings": findings,
            "threat_score": min(100, risk_score)
        }

    def analyze_content(self, html_content: str, current_domain: str) -> Dict[str, Any]:
        """
        Inspects DOM structure for credential harvesting forms, third-party POST actions,
        discordant webhooks, urgency lures, and anti-analysis scripts.
        """
        if not html_content:
            return {"findings": [], "score_modifier": 0, "has_credential_form": False}

        findings: List[Dict[str, Any]] = []
        score_mod = 0
        content_lower = html_content.lower()

        # 1. Credential harvesting inputs
        has_password_field = bool(re.search(r'<input[^>]*type=["\']password["\']', content_lower))
        has_card_field = bool(re.search(r'(cardnumber|cvv|cvc|card_num|exp_month|exp_year|card_expiry)', content_lower))
        has_ssn_id_field = bool(re.search(r'(ssn|social_security|aadhaar|pan_number|national_id|id_proof)', content_lower))

        if has_password_field:
            score_mod += 25
            findings.append({
                "category": "Credential Harvesting",
                "severity": "HIGH",
                "title": "Password Input Field Present",
                "detail": "DOM contains authentication password entry inputs. Combined with suspicious domain reputation, this indicates a high likelihood of credential theft.",
                "penalty": 25
            })

        if has_card_field:
            score_mod += 35
            findings.append({
                "category": "Credential Harvesting",
                "severity": "CRITICAL",
                "title": "Payment Card / CVV Harvesting Form",
                "detail": "DOM contains form fields soliciting Credit/Debit Card numbers, CVV codes, or expiry dates.",
                "penalty": 35
            })

        if has_ssn_id_field:
            score_mod += 30
            findings.append({
                "category": "Credential Harvesting",
                "severity": "CRITICAL",
                "title": "Government Identity Number Solicitation",
                "detail": "Form requests national identity credentials (SSN, Aadhaar, National ID, or Tax ID).",
                "penalty": 30
            })

        # 2. Form Action Destination Check (Third-party exfiltration or Webhooks)
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', content_lower)
        for action in form_actions:
            if "discord.com/api/webhooks" in action or "api.telegram.org/bot" in action or "webhook.site" in action:
                score_mod += 45
                findings.append({
                    "category": "Exfiltration Architecture",
                    "severity": "CRITICAL",
                    "title": "Form Submits Directly to Discord/Telegram Webhook",
                    "detail": f"Form action targets known public webhook API endpoint ('{action[:50]}...'). This is an undeniable indicator of modern turnkey phishing kits exfiltrating stolen victim data to private chat channels.",
                    "penalty": 45
                })
            elif action.startswith("http://") or action.startswith("https://"):
                action_parsed = urllib.parse.urlparse(action)
                if action_parsed.netloc and current_domain not in action_parsed.netloc and action_parsed.netloc not in current_domain:
                    score_mod += 25
                    findings.append({
                        "category": "Form Action Discordance",
                        "severity": "HIGH",
                        "title": "Cross-Domain Form Action Exfiltration Target",
                        "detail": f"Form renders on '{current_domain}' but submits POST credentials to foreign domain '{action_parsed.netloc}'.",
                        "penalty": 25
                    })

        # 3. Social Engineering & Urgency Lures
        matched_urgency = []
        for pat in SUSPICIOUS_URGENCY_PATTERNS:
            if re.search(pat, content_lower):
                matched_urgency.append(pat.replace(r"\s+", " ").replace(r"\d+", "N").replace(".*", " ... "))

        if matched_urgency:
            score_mod += 20
            findings.append({
                "category": "Social Engineering",
                "severity": "HIGH",
                "title": "High-Pressure Psychological Urgency & Fear Lures",
                "detail": f"Page contains coercive social engineering patterns designed to manipulate victims into immediate action without verification ({', '.join(matched_urgency[:2])}).",
                "penalty": 20
            })

        # 4. Anti-Analysis & Context Menu Disabling
        if "event.button==2" in content_lower or "contextmenu" in content_lower and "preventdefault" in content_lower:
            score_mod += 15
            findings.append({
                "category": "Evasion Techniques",
                "severity": "MEDIUM",
                "title": "Anti-Inspection / Context Menu Suppression",
                "detail": "Scripts attempt to disable right-click context menu and browser inspection tools to hinder manual analysis.",
                "penalty": 15
            })

        return {
            "findings": findings,
            "score_modifier": min(60, score_mod),
            "has_credential_form": has_password_field or has_card_field or has_ssn_id_field,
            "form_actions": form_actions
        }
