"""
AegisTrust AI - Threat Defense & Certificate Intelligence Platform
Main FastAPI Application Server
"""

import os
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from .scanner.analyzer import UnifiedAnalyzer
from .scanner.scenarios import SCENARIO_VECTORS
from .threat_intel.database import ThreatDatabase
from .threat_intel.stix_exporter import STIX21Exporter

app = FastAPI(
    title="AegisTrust AI Platform",
    description="Intelligent Phishing Detection, TLS Certificate Trust Chain Validation, and Collaborative Threat Intelligence API",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database, Exporter, and Analyzer
db = ThreatDatabase()
stix_exporter = STIX21Exporter()
analyzer = UnifiedAnalyzer(db_manager=db)

# ----------------- Models ----------------- #
class ScanRequest(BaseModel):
    url: Optional[str] = ""
    scenario_id: Optional[str] = None
    live_scan: Optional[bool] = True

class ReportRequest(BaseModel):
    url: str
    target_brand: Optional[str] = "Unknown"
    target_sector: Optional[str] = "General Web"
    threat_type: Optional[str] = "Phishing / Malicious Site"
    risk_score: Optional[int] = 75
    evidence_notes: Optional[str] = ""
    submitted_by: Optional[str] = "Community_Member"

class VoteRequest(BaseModel):
    vote_type: str  # "up" or "down"

# ----------------- API Endpoints ----------------- #

@app.post("/api/scan")
async def scan_url(req: ScanRequest):
    """
    Performs unified analysis combining:
    - URL heuristics & typosquatting / homoglyphs
    - Real-time TLS handshake & eMudhra CA anomaly inspection
    - HTTP security headers & application posture
    - Collaborative threat intelligence correlation
    """
    if not req.url and not req.scenario_id:
        raise HTTPException(status_code=400, detail="Must provide either 'url' or 'scenario_id'")

    try:
        result = await analyzer.scan(
            url=req.url or "",
            scenario_id=req.scenario_id,
            live_scan=req.live_scan if req.live_scan is not None else True
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")

@app.get("/api/scenarios")
async def list_scenarios():
    """Returns curated simulation scenarios covering major threat vectors."""
    scenarios_list = []
    for s_id, s_data in SCENARIO_VECTORS.items():
        scenarios_list.append({
            "id": s_id,
            "title": s_data["title"],
            "category": s_data["category"],
            "url": s_data["url"],
            "description": s_data["description"]
        })
    return {"scenarios": scenarios_list}

@app.get("/api/threats")
async def get_threats(
    sector: Optional[str] = Query(None, description="Filter by sector"),
    limit: Optional[int] = Query(50, description="Max records to return")
):
    """Retrieves live collaborative threat intelligence reports."""
    reports = db.get_recent_reports(limit=limit or 50, sector=sector)
    return {"reports": reports}

@app.post("/api/threats/report")
async def report_threat(req: ReportRequest):
    """Submits a new malicious site or phishing campaign to community feed."""
    import urllib.parse
    clean_url = req.url if req.url.startswith(("http://", "https://")) else f"https://{req.url}"
    domain = urllib.parse.urlparse(clean_url).netloc.split(":")[0]

    data = {
        "url": clean_url,
        "domain": domain,
        "target_brand": req.target_brand,
        "target_sector": req.target_sector,
        "threat_type": req.threat_type,
        "risk_score": req.risk_score,
        "evidence_notes": req.evidence_notes,
        "submitted_by": req.submitted_by
    }
    res = db.submit_report(data)
    return res

@app.post("/api/threats/{report_id}/vote")
async def vote_threat(report_id: int, req: VoteRequest):
    """Votes on a community report (confirm malicious / false positive)."""
    if req.vote_type not in ["up", "down"]:
        raise HTTPException(status_code=400, detail="vote_type must be 'up' or 'down'")
    res = db.vote_report(report_id, req.vote_type)
    return res

@app.post("/api/threats/{report_id}/verify")
async def verify_threat(report_id: int):
    """Endorses a threat report with official security analyst verification."""
    res = db.verify_report(report_id)
    return res

@app.get("/api/threats/metrics")
async def get_metrics():
    """Aggregated threat metrics, sector distribution, and top targeted brands."""
    return db.get_metrics()

@app.get("/api/threats/export/stix")
async def export_stix():
    """Exports all verified threat indicators as an OASIS STIX 2.1 JSON bundle."""
    reports = db.get_recent_reports(limit=200)
    bundle = stix_exporter.export_bundle(reports)
    return JSONResponse(
        content=bundle,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=aegistrust_threat_intelligence_stix21.json"}
    )

@app.get("/api/threats/export/json")
async def export_json():
    """Exports raw Indicators of Compromise (IOCs) as JSON."""
    reports = db.get_recent_reports(limit=200)
    return {"iocs": reports}

@app.get("/api/ca/advisories")
async def get_ca_advisories():
    """Returns technical dossier on CA anomalies, including the eMudhra TLS incident."""
    return {
        "title": "Certificate Authority Trust & Cryptographic Integrity Dossier",
        "key_incidents": [
            {
                "id": "emudhra-incident",
                "name": "eMudhra TLS Certificate Authority Incident (2024-2025)",
                "impact": "CRITICAL TRUST INFRASTRUCTURE RISK",
                "description": (
                    "In 2024 and 2025, security researchers and browser trust programs (Mozilla, Chromium) identified "
                    "critical systemic weaknesses in eMudhra's Certificate Authority operations. Specifically, flawed "
                    "random number generation (RNG) during key pair generation yielded predictable private keys and low-entropy "
                    "RSA moduli, mirroring historical vulnerabilities like ROCA and Debian weak keys. Concurrently, delays "
                    "and omissions in Certificate Transparency (CT) logging concealed rogue and defective certificate issuances. "
                    "These vulnerabilities enabled adversaries to potentially forge valid TLS certificates for website impersonation "
                    "and Machine-in-the-Middle (MitM) attacks while displaying standard browser padlock icons."
                ),
                "technical_vectors": [
                    "Weak RSA key entropy resulting from defective hardware security module (HSM) RNG seeds",
                    "Certificate Transparency (CT) log omission: certificates issued without precertificate logging",
                    "Domain validation compliance violations and insufficient multi-perspective validation (MPV)",
                    "Browser trust enforcement: probationary restrictions, distrust timetables, and shortened lifespans"
                ],
                "aegis_mitigations": [
                    "Active Shannon entropy and modular arithmetic testing on public RSA moduli",
                    "Mandatory Signed Certificate Timestamp (SCT) extension validation",
                    "High-value brand vs Automated DV certificate tier mismatch detection",
                    "Automated flagging of probationary and distrusted Certificate Authorities"
                ]
            },
            {
                "id": "wosign-startcom",
                "name": "WoSign & StartCom Historic Distrust",
                "impact": "PERMANENT ROOT REVOCATION",
                "description": "Distrusted globally due to backdating certificates to evade SHA-1 deprecation deadlines and issuing unauthorized base domain certificates.",
                "technical_vectors": ["Backdated validity dates", "Arbitrary domain validation circumvention"],
                "aegis_mitigations": ["Enforcement of strict 398-day validity caps", "Root certificate fingerprints pinned to trusted Mozilla root store"]
            }
        ]
    }

# Serve Frontend static assets if built
FRONTEND_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        file_path = os.path.join(FRONTEND_DIST, full_path)
        if full_path and os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))
