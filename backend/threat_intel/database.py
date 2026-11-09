"""
Collaborative Threat Intelligence Database & Community Defense
SQLite database handling community phishing reports, peer verification votes,
analyst endorsements, and Indicator of Compromise (IOC) registries.
"""

import sqlite3
import datetime
import os
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "threat_intel.db")

class ThreatDatabase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()
        self._seed_initial_intel()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            # Community Reports Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    target_brand TEXT NOT NULL,
                    target_sector TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    evidence_notes TEXT,
                    submitted_by TEXT NOT NULL,
                    verified_by_analyst INTEGER DEFAULT 0,
                    upvotes INTEGER DEFAULT 1,
                    downvotes INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)

            # Indicators of Compromise (IOCs) Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL UNIQUE,
                    threat_name TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def _seed_initial_intel(self):
        """Seeds realistic community threat intelligence entries if database is fresh."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM reports")
            count = cursor.fetchone()[0]
            if count > 0:
                return

            now = datetime.datetime.now(datetime.timezone.utc)
            initial_reports = [
                (
                    "https://secure-banking-auth.net/login",
                    "secure-banking-auth.net",
                    "Banking Consortia",
                    "Banking & Finance",
                    "eMudhra CA Rogue Certificate / Weak Key Anomaly",
                    95,
                    "Discovered during Certificate Transparency audit. Certificate issued via eMudhra with anomalous low-entropy RSA key and zero SCT timestamps.",
                    "CertHawk_Sentinel",
                    1,
                    42,
                    1,
                    (now - datetime.timedelta(hours=2)).isoformat()
                ),
                (
                    "https://chase-security-verify-auth.xyz/signin",
                    "chase-security-verify-auth.xyz",
                    "JPMorgan Chase & Co.",
                    "Banking & Finance",
                    "Credential Harvester & Discord Webhook Exfiltration",
                    92,
                    "Spear-phishing email lure leading to Chase lookalike. Harvests passwords, account numbers, and debit CVVs, POSTing them directly to Discord webhook API.",
                    "SOC_Analyst_Sarah",
                    1,
                    68,
                    0,
                    (now - datetime.timedelta(hours=5)).isoformat()
                ),
                (
                    "http://oxford-portal-careers.xyz/apply",
                    "oxford-portal-careers.xyz",
                    "University of Oxford",
                    "Education & Academia",
                    "Fake Academic Recruitment & Passport Harvester",
                    88,
                    "Soliciting international student and researcher applications with passport uploads and unencrypted $120 registration fee payments over plain HTTP.",
                    "EduShield_Node",
                    1,
                    31,
                    2,
                    (now - datetime.timedelta(hours=9)).isoformat()
                ),
                (
                    "https://gov-irs-tax-refund-claim.online/direct-deposit",
                    "gov-irs-tax-refund-claim.online",
                    "Internal Revenue Service (IRS)",
                    "Government & Public Services",
                    "Tax Refund Phishing & Identity Theft",
                    94,
                    "Mass SMS smishing campaign advertising $1,420 pending tax refund to harvest SSNs and bank direct deposit accounts.",
                    "GovWatch_Analyst",
                    1,
                    54,
                    1,
                    (now - datetime.timedelta(hours=14)).isoformat()
                ),
                (
                    "https://metamask-airdrop-claim-rewards.top/connect",
                    "metamask-airdrop-claim-rewards.top",
                    "MetaMask",
                    "Cryptocurrency & Web3",
                    "Web3 Wallet Drainer & Malicious Smart Contract Approval",
                    96,
                    "Promoting fake 2.5 ETH airdrop on Twitter/X ads. Prompts users to sign malicious approval tx to drain ERC-20 tokens.",
                    "Web3_ThreatHunter",
                    1,
                    77,
                    3,
                    (now - datetime.timedelta(hours=21)).isoformat()
                ),
                (
                    "https://sbi-kyc-verify-card.live/portal",
                    "sbi-kyc-verify-card.live",
                    "State Bank of India",
                    "Banking & Finance",
                    "Mandatory KYC SMS Lure",
                    90,
                    "Targeting retail banking customers with SMS threatening SIM blocking unless NetBanking credentials and OTP are submitted.",
                    "FinSec_Mumbai",
                    1,
                    49,
                    0,
                    (now - datetime.timedelta(days=1)).isoformat()
                ),
                (
                    "https://workday-internal-jobs-auth.icu/portal",
                    "workday-internal-jobs-auth.icu",
                    "Workday",
                    "Recruitment & Professional",
                    "Corporate SSO Impersonation",
                    86,
                    "Corporate SSO credential harvester spoofing Workday HR portal on .icu domain.",
                    "CorpDefense_Alex",
                    0,
                    19,
                    0,
                    (now - datetime.timedelta(days=1, hours=4)).isoformat()
                )
            ]

            cursor.executemany("""
                INSERT INTO reports (
                    url, domain, target_brand, target_sector, threat_type,
                    risk_score, evidence_notes, submitted_by, verified_by_analyst,
                    upvotes, downvotes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, initial_reports)

            # Seed IOCs
            iocs = [
                ("domain", "secure-banking-auth.net", "eMudhra CA Weak Key Impersonation", "HIGH", now.isoformat()),
                ("domain", "chase-security-verify-auth.xyz", "Chase Credential Harvester", "HIGH", now.isoformat()),
                ("domain", "oxford-portal-careers.xyz", "Oxford Recruitment Phishing", "HIGH", now.isoformat()),
                ("domain", "gov-irs-tax-refund-claim.online", "IRS Tax Phishing Lure", "HIGH", now.isoformat()),
                ("domain", "metamask-airdrop-claim-rewards.top", "MetaMask Web3 Drainer", "HIGH", now.isoformat()),
                ("sha256_cert", "4a71b128f9c2e0b57134d1938fa2c61093ebca591244e4fa431f4a9b6b72a910", "eMudhra Weak Modulus Cert", "CRITICAL", now.isoformat())
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO iocs (ioc_type, ioc_value, threat_name, confidence, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, iocs)
            conn.commit()

    def get_recent_reports(self, limit: int = 50, sector: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if sector and sector != "ALL":
                cursor.execute(
                    "SELECT * FROM reports WHERE target_sector = ? ORDER BY id DESC LIMIT ?",
                    (sector, limit)
                )
            else:
                cursor.execute("SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def submit_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO reports (
                    url, domain, target_brand, target_sector, threat_type,
                    risk_score, evidence_notes, submitted_by, verified_by_analyst,
                    upvotes, downvotes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["url"],
                data["domain"],
                data.get("target_brand", "Unknown Entity"),
                data.get("target_sector", "General Web"),
                data.get("threat_type", "Phishing / Malicious Site"),
                data.get("risk_score", 75),
                data.get("evidence_notes", ""),
                data.get("submitted_by", "Community_Member"),
                0,
                1,
                0,
                now
            ))
            report_id = cursor.lastrowid

            # Also insert domain IOC
            cursor.execute("""
                INSERT OR IGNORE INTO iocs (ioc_type, ioc_value, threat_name, confidence, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, ("domain", data["domain"], f"Community: {data.get('threat_type')}", "MEDIUM", now))

            conn.commit()
            return {"id": report_id, "status": "SUBMITTED_SUCCESSFULLY", "created_at": now}

    def vote_report(self, report_id: int, vote_type: str) -> Dict[str, Any]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if vote_type == "up":
                cursor.execute("UPDATE reports SET upvotes = upvotes + 1 WHERE id = ?", (report_id,))
            elif vote_type == "down":
                cursor.execute("UPDATE reports SET downvotes = downvotes + 1 WHERE id = ?", (report_id,))
            
            cursor.execute("SELECT upvotes, downvotes FROM reports WHERE id = ?", (report_id,))
            row = cursor.fetchone()
            conn.commit()
            return dict(row) if row else {"error": "Report not found"}

    def verify_report(self, report_id: int, analyst: str = "AegisTrust_Lead_Analyst") -> Dict[str, Any]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE reports SET verified_by_analyst = 1 WHERE id = ?", (report_id,))
            conn.commit()
            return {"id": report_id, "verified": True, "analyst": analyst}

    def query_iocs(self, indicator: str) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            clean = indicator.lower().strip()
            cursor.execute("SELECT * FROM iocs WHERE LOWER(ioc_value) = ?", (clean,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_metrics(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM reports")
            total_reports = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM iocs")
            total_iocs = cursor.fetchone()[0]

            cursor.execute("SELECT target_sector, COUNT(*) as count FROM reports GROUP BY target_sector")
            sector_counts = {row["target_sector"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("SELECT target_brand, COUNT(*) as count FROM reports GROUP BY target_brand ORDER BY count DESC LIMIT 6")
            top_brands = [dict(row) for row in cursor.fetchall()]

            cursor.execute("SELECT COUNT(*) FROM reports WHERE verified_by_analyst = 1")
            verified_count = cursor.fetchone()[0]

            return {
                "total_reports": total_reports,
                "total_iocs": total_iocs,
                "verified_threats": verified_count,
                "sector_breakdown": sector_counts,
                "top_targeted_brands": top_brands,
                "active_honeypots": 14,
                "ca_watchlist_count": 4
            }
