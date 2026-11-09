import React, { useState, useEffect } from 'react';
import { 
  Shield, ShieldAlert, ShieldCheck, AlertTriangle, Lock, Unlock, 
  Globe, Server, CheckCircle2, XCircle, Search, RefreshCw, Key, 
  ExternalLink, ArrowRight, Layers, FileCode, Check, Eye
} from 'lucide-react';

export default function ScannerView({ onOpenInterstitial }) {
  const [urlInput, setUrlInput] = useState('');
  const [liveScan, setLiveScan] = useState(true);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [activeSubTab, setActiveSubTab] = useState('threat');
  const [scenarios, setScenarios] = useState([]);
  const [scanStep, setScanStep] = useState(0);

  // Fetch scenarios on load
  useEffect(() => {
    fetch('/api/scenarios')
      .then(res => res.json())
      .then(data => {
        if (data.scenarios) setScenarios(data.scenarios);
      })
      .catch(err => console.error('Failed to load scenarios:', err));

    // Default initial scan to demonstrate immediate value
    executeScan('', 'emudhra-ca-incident');
  }, []);

  const executeScan = async (urlToScan, scenarioId = null) => {
    setLoading(true);
    setScanResult(null);
    setScanStep(1);

    // Visual sequence animation
    const stepTimer1 = setTimeout(() => setScanStep(2), 350);
    const stepTimer2 = setTimeout(() => setScanStep(3), 700);
    const stepTimer3 = setTimeout(() => setScanStep(4), 1050);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: urlToScan,
          scenario_id: scenarioId,
          live_scan: liveScan && !scenarioId
        })
      });

      const data = await response.json();
      setScanResult(data);
      if (urlToScan) setUrlInput(urlToScan);
    } catch (error) {
      console.error('Scan failed:', error);
    } finally {
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);
      setLoading(false);
      setScanStep(0);
    }
  };

  const handleFormSubmit = (e) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    executeScan(urlInput.trim(), null);
  };

  const getVerdictBadge = (category) => {
    switch (category) {
      case 'CRITICAL_MALICIOUS':
        return {
          bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
          dot: 'bg-rose-500',
          glow: 'glow-red',
          label: 'CRITICAL MALICIOUS THREAT'
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
          dot: 'bg-amber-500',
          glow: 'glow-amber',
          label: 'SUSPICIOUS HIGH RISK'
        };
      case 'LOW_RISK':
        return {
          bg: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
          dot: 'bg-yellow-500',
          glow: '',
          label: 'LOW RISK / HYGIENE WARNING'
        };
      default:
        return {
          bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
          dot: 'bg-emerald-500',
          glow: 'glow-cyan',
          label: 'VERIFIED CLEAN & AUTHENTIC'
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Search Bar & Scenario Selector */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              Unified Web Threat & Certificate Inspector
            </h2>
            <p className="text-sm text-slate-400">
              Analyze live websites, detect typosquatting, uncover eMudhra-style CA weak keys, and audit application security posture.
            </p>
          </div>

          <div className="flex items-center gap-3 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-xs">
            <label className="flex items-center gap-2 cursor-pointer text-slate-300">
              <input
                type="checkbox"
                checked={liveScan}
                onChange={(e) => setLiveScan(e.target.checked)}
                className="rounded border-slate-700 text-cyan-500 focus:ring-0 bg-slate-800"
              />
              <span>Live TLS Socket & Network Inspection</span>
            </label>
          </div>
        </div>

        {/* Search Input Form */}
        <form onSubmit={handleFormSubmit} className="relative flex items-center mb-4">
          <div className="absolute left-4 text-slate-500">
            <Globe className="w-5 h-5" />
          </div>
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="Enter URL or domain (e.g. chase-security-auth.net, cloudflare.com, or test scenario)..."
            className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-12 pr-36 py-3.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition-all"
          />
          <button
            type="submit"
            disabled={loading}
            className="absolute right-2 px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs transition-all shadow-md flex items-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5" />
                Deep Scan
              </>
            )}
          </button>
        </form>

        {/* Preset Threat Scenarios */}
        <div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            Quick-Load Threat Vector Scenarios:
          </div>
          <div className="flex flex-wrap gap-2">
            {scenarios.map((sc) => {
              const isSelected = scanResult?.target?.scenario_title === sc.title;
              return (
                <button
                  key={sc.id}
                  onClick={() => executeScan('', sc.id)}
                  className={`text-xs px-3 py-1.5 rounded-lg border transition-all text-left flex items-center gap-1.5 ${
                    isSelected
                      ? 'bg-cyan-500/20 border-cyan-400 text-cyan-300 font-medium shadow-sm'
                      : 'bg-slate-950/70 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    sc.id.includes('emudhra') ? 'bg-rose-400' :
                    sc.id.includes('chase') ? 'bg-amber-400' :
                    sc.id.includes('baseline') ? 'bg-emerald-400' : 'bg-cyan-400'
                  }`}></span>
                  {sc.title}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Loading Radar Console */}
      {loading && (
        <div className="bg-slate-900/80 border border-cyan-500/30 rounded-2xl p-6 shadow-2xl animate-pulse">
          <div className="flex items-center gap-3 mb-4">
            <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
            <div>
              <h3 className="font-bold text-white text-base">Multi-Engine Telemetry Scan in Progress</h3>
              <p className="text-xs text-slate-400 font-mono">Parallelizing X.509 socket parsing, entropy evaluation, and DOM inspection</p>
            </div>
          </div>
          <div className="space-y-2 text-xs font-mono">
            <div className={`flex items-center gap-2 ${scanStep >= 1 ? 'text-cyan-400' : 'text-slate-600'}`}>
              <span className="w-4">01.</span>
              <span>Resolving DNS, parsing Punycode/homoglyphs, and computing Levenshtein brand distance...</span>
            </div>
            <div className={`flex items-center gap-2 ${scanStep >= 2 ? 'text-cyan-400' : 'text-slate-600'}`}>
              <span className="w-4">02.</span>
              <span>Establishing TLS handshake & extracting leaf X.509 certificate...</span>
            </div>
            <div className={`flex items-center gap-2 ${scanStep >= 3 ? 'text-cyan-400' : 'text-slate-600'}`}>
              <span className="w-4">03.</span>
              <span>Evaluating eMudhra & CA trust status; testing RSA modulus Shannon entropy for weak RNG defects...</span>
            </div>
            <div className={`flex items-center gap-2 ${scanStep >= 4 ? 'text-cyan-400' : 'text-slate-600'}`}>
              <span className="w-4">04.</span>
              <span>Auditing HSTS, CSP, X-Frame headers, email DMARC policies, and querying community threat feed...</span>
            </div>
          </div>
        </div>
      )}

      {/* Scan Results View */}
      {scanResult && !loading && (
        <div className="space-y-6">
          {/* Top Verdict Overview Card */}
          {(() => {
            const badge = getVerdictBadge(scanResult.verdict.category);
            const isMalicious = scanResult.verdict.threat_score >= 40;
            return (
              <div className={`bg-slate-900/70 border rounded-2xl p-6 backdrop-blur-md transition-all ${badge.bg} ${badge.glow}`}>
                <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
                  {/* Left: Verdict and target */}
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${badge.bg} border`}>
                        <span className={`w-2 h-2 rounded-full ${badge.dot} animate-pulse`}></span>
                        {badge.label}
                      </span>

                      {scanResult.target.targeted_brand !== 'Generic / Unclassified' && (
                        <span className="px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700 text-xs font-medium text-slate-300">
                          Impersonating: <strong className="text-white">{scanResult.target.targeted_brand}</strong>
                        </span>
                      )}

                      <span className="px-2.5 py-1 rounded-full bg-slate-800/80 border border-slate-700 text-xs text-slate-400">
                        Sector: <strong className="text-slate-200">{scanResult.target.target_sector}</strong>
                      </span>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-lg font-bold text-white break-all">
                      <span>{scanResult.target.url}</span>
                    </div>

                    <p className="text-xs text-slate-400">
                      {scanResult.verdict.critical_indicators > 0 ? (
                        <span className="text-rose-400 font-semibold">
                          ⚠️ {scanResult.verdict.critical_indicators} Critical Security Vulnerabilities Flagged.
                        </span>
                      ) : (
                        <span className="text-emerald-400 font-semibold">
                          ✓ No critical anomalies detected. Standard cryptographic trust paths verified.
                        </span>
                      )}
                      {' '}{scanResult.engines.threat_intelligence.summary}
                    </p>
                  </div>

                  {/* Right: Score Dial & Interstitial Trigger */}
                  <div className="flex items-center gap-4">
                    {isMalicious && (
                      <button
                        onClick={() => onOpenInterstitial(scanResult)}
                        className="px-3.5 py-2 rounded-xl bg-slate-950 border border-rose-500/40 text-rose-300 hover:bg-rose-500/10 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
                      >
                        <Eye className="w-3.5 h-3.5 text-rose-400" />
                        Preview Browser Block Warning
                      </button>
                    )}

                    {/* Threat Score Radial Pill */}
                    <div className="flex items-center gap-3 bg-slate-950/80 px-5 py-3 rounded-2xl border border-slate-800">
                      <div className="text-right">
                        <div className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">Threat Index</div>
                        <div className="text-xs text-slate-500">Max: 100</div>
                      </div>
                      <div className={`text-3xl font-black font-mono ${
                        scanResult.verdict.threat_score >= 70 ? 'text-rose-400' :
                        scanResult.verdict.threat_score >= 40 ? 'text-amber-400' :
                        scanResult.verdict.threat_score >= 20 ? 'text-yellow-400' : 'text-emerald-400'
                      }`}>
                        {scanResult.verdict.threat_score}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Sub-engine Breakdown Bars */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800/80">
                  <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/60">
                    <div className="text-[11px] text-slate-400 font-medium">Brand & URL Risk</div>
                    <div className="text-lg font-bold font-mono text-white mt-0.5">
                      {scanResult.engines.threat_and_brand.threat_score}<span className="text-xs text-slate-500">/100</span>
                    </div>
                  </div>

                  <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/60">
                    <div className="text-[11px] text-slate-400 font-medium">Certificate Risk</div>
                    <div className="text-lg font-bold font-mono text-white mt-0.5">
                      {scanResult.engines.certificate_and_trust.threat_score}<span className="text-xs text-slate-500">/100</span>
                    </div>
                  </div>

                  <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/60">
                    <div className="text-[11px] text-slate-400 font-medium">App Security Grade</div>
                    <div className="text-lg font-bold font-mono text-cyan-400 mt-0.5">
                      {scanResult.engines.web_security.security_grade}
                      <span className="text-xs text-slate-500 font-normal ml-1">({scanResult.engines.web_security.security_score}%)</span>
                    </div>
                  </div>

                  <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/60">
                    <div className="text-[11px] text-slate-400 font-medium">Threat Intelligence</div>
                    <div className="text-lg font-bold font-mono text-white mt-0.5">
                      {scanResult.engines.threat_intelligence.confidence}
                    </div>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Sub-Engine Navigation Tabs */}
          <div className="flex border-b border-slate-800 gap-2">
            <button
              onClick={() => setActiveSubTab('threat')}
              className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 ${
                activeSubTab === 'threat'
                  ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              1. Brand & Threat Analysis ({scanResult.engines.threat_and_brand.findings.length})
            </button>

            <button
              onClick={() => setActiveSubTab('cert')}
              className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 ${
                activeSubTab === 'cert'
                  ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              2. Certificate & eMudhra CA Trust ({scanResult.engines.certificate_and_trust.findings.length})
            </button>

            <button
              onClick={() => setActiveSubTab('security')}
              className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 ${
                activeSubTab === 'security'
                  ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              3. Web Security & Headers ({scanResult.engines.web_security.findings.length})
            </button>

            <button
              onClick={() => setActiveSubTab('remediation')}
              className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 ${
                activeSubTab === 'remediation'
                  ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              4. Actionable Remediation
            </button>
          </div>

          {/* TAB 1: Brand & Threat Heuristics */}
          {activeSubTab === 'threat' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                  <div className="text-xs text-slate-400 mb-1">Targeted Organization</div>
                  <div className="text-base font-bold text-white">{scanResult.target.targeted_brand}</div>
                  <div className="text-xs text-slate-500 mt-1">Sector: {scanResult.target.target_sector}</div>
                </div>

                <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                  <div className="text-xs text-slate-400 mb-1">Domain Morphological Flags</div>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Punycode / IDN:</span>
                      <span className={scanResult.engines.threat_and_brand.is_punycode ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                        {scanResult.engines.threat_and_brand.is_punycode ? 'YES (Homoglyph Risk)' : 'No'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Direct IP Address:</span>
                      <span className={scanResult.engines.threat_and_brand.is_ip ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                        {scanResult.engines.threat_and_brand.is_ip ? 'YES' : 'No'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                  <div className="text-xs text-slate-400 mb-1">Threat Correlator Confidence</div>
                  <div className="text-base font-bold text-cyan-400">{scanResult.engines.threat_intelligence.confidence}</div>
                  <div className="text-xs text-slate-500 mt-1">
                    Matching IOCs: {scanResult.engines.threat_intelligence.reports_count}
                  </div>
                </div>
              </div>

              {/* Finding Cards */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Engine Findings & Risk Penalties:</h4>
                {scanResult.engines.threat_and_brand.findings.map((f, i) => (
                  <div 
                    key={i} 
                    className={`p-4 rounded-xl border text-xs ${
                      f.severity === 'CRITICAL' ? 'bg-rose-500/10 border-rose-500/30' :
                      f.severity === 'HIGH' ? 'bg-amber-500/10 border-amber-500/30' :
                      f.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/20' : 'bg-slate-900/40 border-slate-800'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                          f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' :
                          f.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300' :
                          f.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-300' : 'bg-slate-800 text-slate-300'
                        }`}>
                          {f.severity}
                        </span>
                        <span className="font-semibold text-slate-200 text-sm">{f.title}</span>
                      </div>
                      {f.penalty > 0 && (
                        <span className="font-mono text-rose-400 font-bold">+{f.penalty} pts risk</span>
                      )}
                    </div>
                    <p className="text-slate-300 leading-relaxed">{f.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 2: Certificate & Trust Infrastructure (eMudhra Incident) */}
          {activeSubTab === 'cert' && (
            <div className="space-y-6">
              {/* Special eMudhra Incident Advisory Banner */}
              {scanResult.engines.certificate_and_trust.emudhra_incident_analysis?.is_emudhra_ca && (
                <div className="bg-gradient-to-r from-rose-950/60 to-purple-950/40 border border-rose-500/40 rounded-xl p-5 shadow-lg">
                  <div className="flex items-start gap-3">
                    <ShieldAlert className="w-6 h-6 text-rose-400 flex-shrink-0 mt-0.5" />
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-sm">eMudhra TLS Certificate Authority Incident Triggered</span>
                        <span className="px-2 py-0.5 rounded bg-rose-500 text-slate-950 font-bold text-[10px]">
                          CRITICAL CA ADVISORY
                        </span>
                      </div>
                      <p className="text-xs text-rose-200/90 leading-relaxed">
                        This website utilizes a certificate issued by eMudhra or an affiliated intermediate CA. 
                        In 2024-2025, browser trust bodies (Mozilla, Chromium) documented critical vulnerabilities in eMudhra's 
                        cryptographic key generation, low-entropy RNG seeds, delayed Certificate Transparency logging, and unauthorized issuance.
                      </p>
                      <div className="text-[11px] text-rose-300 font-mono pt-1">
                        Status: Distrust Enforcement Active in Major Root Stores
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Visual Certificate Trust Hierarchy Tree */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  X.509 Certificate Chain of Trust Hierarchy:
                </div>

                <div className="space-y-3">
                  {scanResult.engines.certificate_and_trust.chain?.map((node, idx) => (
                    <div key={idx} className="flex items-center gap-3">
                      <div className="w-8 flex flex-col items-center">
                        <div className={`w-3.5 h-3.5 rounded-full flex items-center justify-center ${
                          node.trusted ? 'bg-emerald-500 text-slate-950' : 'bg-rose-500 text-slate-950'
                        }`}>
                          {node.trusted ? <Check className="w-2.5 h-2.5" /> : <XCircle className="w-2.5 h-2.5" />}
                        </div>
                        {idx < scanResult.engines.certificate_and_trust.chain.length - 1 && (
                          <div className="w-0.5 h-6 bg-slate-800 my-0.5"></div>
                        )}
                      </div>

                      <div className={`flex-1 p-3 rounded-lg border text-xs ${
                        node.trusted 
                          ? 'bg-slate-950/70 border-slate-800 text-slate-200' 
                          : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
                      }`}>
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-sm">{node.level}: {node.name}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                            node.trusted ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-300'
                          }`}>
                            {node.trusted ? 'TRUSTED IN ROOT STORE' : 'DISTRUSTED / REVOKED / SUSPECT'}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1 font-mono">{node.notes}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Cryptographic Technical Details Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                  <div className="text-[11px] text-slate-400">Public Key & Size</div>
                  <div className="text-sm font-bold text-white font-mono mt-1">
                    {scanResult.engines.certificate_and_trust.cryptography?.key_type || 'N/A'}{' '}
                    {scanResult.engines.certificate_and_trust.cryptography?.key_size ? `(${scanResult.engines.certificate_and_trust.cryptography.key_size}-bit)` : ''}
                  </div>
                </div>

                <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                  <div className="text-[11px] text-slate-400">Signature Algorithm</div>
                  <div className="text-sm font-bold text-white font-mono mt-1">
                    {scanResult.engines.certificate_and_trust.cryptography?.signature_algorithm || 'N/A'}
                  </div>
                </div>

                <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                  <div className="text-[11px] text-slate-400">Certificate Transparency (CT)</div>
                  <div className={`text-sm font-bold font-mono mt-1 ${
                    scanResult.engines.certificate_and_trust.certificate_transparency?.sct_embedded
                      ? 'text-emerald-400'
                      : 'text-rose-400'
                  }`}>
                    {scanResult.engines.certificate_and_trust.certificate_transparency?.status || 'UNKNOWN'}
                  </div>
                </div>

                <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                  <div className="text-[11px] text-slate-400">Validity Span</div>
                  <div className="text-sm font-bold text-white font-mono mt-1">
                    {scanResult.engines.certificate_and_trust.validity?.days_remaining || 0} days remaining
                  </div>
                </div>
              </div>

              {/* Certificate Findings */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Certificate Anomaly Findings:</h4>
                {scanResult.engines.certificate_and_trust.findings?.map((f, i) => (
                  <div key={i} className={`p-4 rounded-xl border text-xs ${
                    f.severity === 'CRITICAL' ? 'bg-rose-500/10 border-rose-500/30' :
                    f.severity === 'HIGH' ? 'bg-amber-500/10 border-amber-500/30' : 'bg-slate-900/40 border-slate-800'
                  }`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-slate-200 text-sm">{f.title}</span>
                      <span className="font-mono text-rose-400">+{f.penalty} pts</span>
                    </div>
                    <p className="text-slate-300 leading-relaxed">{f.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: Web Security & Headers */}
          {activeSubTab === 'security' && (
            <div className="space-y-6">
              {/* Grade Header */}
              <div className="bg-slate-900/60 p-5 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white">Application Security Posture</h3>
                  <p className="text-xs text-slate-400">HTTP response headers, cookie flags, and DNS email anti-spoofing policies.</p>
                </div>
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400 font-bold uppercase">Security Grade</div>
                    <div className="text-xs text-slate-500">Score: {scanResult.engines.web_security.security_score}/100</div>
                  </div>
                  <div className="w-12 h-12 rounded-xl bg-slate-950 border border-cyan-500/40 flex items-center justify-center text-2xl font-black text-cyan-400 font-mono">
                    {scanResult.engines.web_security.security_grade}
                  </div>
                </div>
              </div>

              {/* Headers Checklist Table */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-4">Security Header</th>
                      <th className="py-2.5 px-4">Status</th>
                      <th className="py-2.5 px-4">Evaluation / Configured Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {scanResult.engines.web_security.checklist?.map((item, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/20">
                        <td className="py-2.5 px-4 font-mono font-medium text-slate-200">{item.header}</td>
                        <td className="py-2.5 px-4">
                          <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                            item.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' :
                            item.status === 'WARNING' ? 'bg-amber-500/20 text-amber-400' : 'bg-rose-500/20 text-rose-400'
                          }`}>
                            {item.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-slate-400 font-mono text-[11px]">{item.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Email Anti-Spoofing & DMARC Status Card */}
              <div className="bg-slate-900/60 p-5 rounded-xl border border-slate-800">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Email Phishing Defense & DMARC Posture:
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">DMARC Policy:</span>
                    <span className="font-mono font-semibold text-slate-200">
                      {scanResult.engines.web_security.email_security?.dmarc_policy}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">SPF Record:</span>
                    <span className="font-mono font-semibold text-slate-200">
                      {scanResult.engines.web_security.email_security?.spf_configured ? 'Configured' : 'Missing'}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">Spoofing Vulnerable:</span>
                    <span className={`font-mono font-bold ${
                      scanResult.engines.web_security.email_security?.spoofing_vulnerable ? 'text-rose-400' : 'text-emerald-400'
                    }`}>
                      {scanResult.engines.web_security.email_security?.spoofing_vulnerable ? 'YES (High Lure Risk)' : 'NO (Protected)'}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-slate-400 mt-2">
                  {scanResult.engines.web_security.email_security?.detail}
                </p>
              </div>
            </div>
          )}

          {/* TAB 4: Actionable Remediation Guidance */}
          {activeSubTab === 'remediation' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* For End Users */}
                <div className="bg-slate-900/60 p-5 rounded-xl border border-slate-800 space-y-3">
                  <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                    <ShieldCheck className="w-4 h-4" />
                    For Individuals & End-Users
                  </div>
                  <ul className="space-y-2 text-xs text-slate-300">
                    {scanResult.recommendations.for_end_users?.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-cyan-400 font-bold">•</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* For SOC & Incident Response */}
                <div className="bg-slate-900/60 p-5 rounded-xl border border-slate-800 space-y-3">
                  <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
                    <ShieldAlert className="w-4 h-4" />
                    For SOC & Security Analysts
                  </div>
                  <ul className="space-y-2 text-xs text-slate-300">
                    {scanResult.recommendations.for_soc_analysts?.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-rose-400 font-bold">•</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* For Domain Owners & Webmasters */}
                <div className="bg-slate-900/60 p-5 rounded-xl border border-slate-800 space-y-3">
                  <div className="flex items-center gap-2 text-amber-400 font-bold text-sm">
                    <Server className="w-4 h-4" />
                    For Domain Administrators
                  </div>
                  <ul className="space-y-2 text-xs text-slate-300">
                    {scanResult.recommendations.for_domain_owners?.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-amber-400 font-bold">•</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
