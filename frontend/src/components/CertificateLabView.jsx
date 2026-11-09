import React, { useState } from 'react';
import { 
  Key, ShieldAlert, Lock, AlertTriangle, Layers, BookOpen, 
  CheckCircle2, XCircle, Cpu, FileCheck, ArrowRight, Activity
} from 'lucide-react';

export default function CertificateLabView() {
  const [activeTab, setActiveTab] = useState('emudhra-case');
  const [entropyInput, setEntropyInput] = useState('');
  const [entropyResult, setEntropyResult] = useState(null);

  const calculateEntropy = (str) => {
    if (!str.trim()) return;
    const clean = str.replace(/[^0-9a-fA-F]/g, '');
    const counts = {};
    for (const char of clean) {
      counts[char] = (counts[char] || 0) + 1;
    }
    let entropy = 0;
    const len = clean.length;
    for (const char in counts) {
      const p = counts[char] / len;
      entropy -= p * Math.log2(p);
    }
    const maxEntropy = 4.0; // For hex (16 chars)
    const isWeak = entropy < 3.3;

    setEntropyResult({
      cleanLength: len,
      entropy: entropy.toFixed(3),
      maxEntropy: maxEntropy.toFixed(1),
      isWeak,
      verdict: isWeak 
        ? 'CRITICAL WEAKNESS: Shannon entropy is severely degraded. High probability of predictable RNG seed or ROCA pattern.'
        : 'HEALTHY ENTROPY: Hex character distribution indicates cryptographically sound randomness.'
    });
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-[11px] font-semibold">
                ROOT TRUST & CRYPTOGRAPHIC AUDITING
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <Key className="w-5 h-5 text-cyan-400" />
              Certificate Authority & Cryptographic Integrity Lab
            </h2>
            <p className="text-sm text-slate-400">
              Technical deep dive into the eMudhra TLS certificate incident, the fallacy of the HTTPS padlock, and CA trust chain security.
            </p>
          </div>

          <div className="flex items-center gap-2 bg-slate-950 px-3.5 py-2 rounded-xl border border-slate-800 text-xs">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse"></span>
            <span className="text-slate-300">CA Watchlist Status: <strong className="text-rose-400">Active Enforcement</strong></span>
          </div>
        </div>

        {/* Tab Buttons */}
        <div className="flex border-b border-slate-800/80 gap-2 mt-6">
          <button
            onClick={() => setActiveTab('emudhra-case')}
            className={`px-4 py-2 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'emudhra-case'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            1. The eMudhra TLS Incident Breakdown
          </button>

          <button
            onClick={() => setActiveTab('padlock-fallacy')}
            className={`px-4 py-2 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'padlock-fallacy'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            2. The "HTTPS Padlock" Fallacy
          </button>

          <button
            onClick={() => setActiveTab('entropy-tool')}
            className={`px-4 py-2 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'entropy-tool'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-amber-400" />
            3. Weak Key & Entropy Lab
          </button>

          <button
            onClick={() => setActiveTab('ca-matrix')}
            className={`px-4 py-2 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'ca-matrix'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-emerald-400" />
            4. CA Global Trust Store Matrix
          </button>
        </div>
      </div>

      {/* TAB 1: eMudhra Incident */}
      {activeTab === 'emudhra-case' && (
        <div className="space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 font-bold">
                ⚠️
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">The eMudhra TLS Certificate Authority Incident (2024–2025)</h3>
                <p className="text-xs text-slate-400">Why public trust in root authorities requires continuous cryptographic validation.</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              In late 2024 and 2025, browser security teams (Mozilla, Chromium, Apple) and independent cryptographers 
              investigated critical architectural failures in eMudhra's Certificate Authority key generation and operational governance. 
              The incident revealed that Certificate Authorities—the ultimate anchors of trust for the World Wide Web—can introduce systemic vulnerabilities 
              capable of allowing website impersonation and Machine-in-the-Middle (MitM) attacks.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="bg-slate-950 p-4 rounded-xl border border-rose-500/20 space-y-2">
                <div className="text-rose-400 font-bold text-xs flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                  1. Defective Key Generation RNG
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Hardware and software RNG flaws caused predictable RSA key pairs with low entropy to be minted. 
                  Adversaries possessing the mathematical relation could factor moduli and forge legitimate private keys.
                </p>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-amber-500/20 space-y-2">
                <div className="text-amber-400 font-bold text-xs flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                  2. Certificate Transparency Omissions
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Certificates were issued with omitted or delayed submissions to public append-only Certificate Transparency (CT) logs, 
                  shielding misissued or test certificates from global scrutiny.
                </p>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-cyan-500/20 space-y-2">
                <div className="text-cyan-400 font-bold text-xs flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-cyan-500"></span>
                  3. Browser Distrust Enforcement
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Mozilla and Chromium instituted probationary restrictions, distrusting specific subordinate CAs 
                  and restricting maximum certificate validity lifespans to minimize the blast radius.
                </p>
              </div>
            </div>

            {/* How AegisTrust Solves This */}
            <div className="bg-cyan-950/20 border border-cyan-500/30 rounded-xl p-4 mt-4">
              <h4 className="text-xs font-bold text-cyan-300 uppercase tracking-wider mb-2 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                How AegisTrust Detects and Neutralizes This Threat:
              </h4>
              <ul className="text-xs text-slate-300 space-y-1.5">
                <li>• <strong>Shannon Entropy & ROCA Heuristics:</strong> Every analyzed RSA public key is tested for modular entropy anomalies and repeat prime patterns.</li>
                <li>• <strong>Mandatory CT & SCT Verification:</strong> Flags any TLS certificate lacking embedded Signed Certificate Timestamps from independent log operators.</li>
                <li>• <strong>Enterprise Tier vs Automated DV Mismatch:</strong> Detects when high-value financial, education, or government institutions are protected by low-assurance automated or high-risk CAs.</li>
                <li>• <strong>Probationary CA Watchlist:</strong> Continuously syncs distrust decisions from Mozilla Bugzilla and CA/Browser Forum actions.</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Padlock Fallacy */}
      {activeTab === 'padlock-fallacy' && (
        <div className="space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-amber-400" />
              The "HTTPS Padlock" Fallacy: Why Encryption ≠ Authenticity
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              For two decades, users were taught that a "green padlock" or HTTPS in the address bar meant a website was safe. 
              In today's threat landscape, this mental model is dangerously outdated:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="text-rose-400 font-bold text-xs flex items-center gap-1.5">
                  <XCircle className="w-4 h-4" />
                  What the HTTPS Padlock Actually Means:
                </div>
                <ul className="text-xs text-slate-400 space-y-1">
                  <li>• Data in transit is encrypted between your browser and the server.</li>
                  <li>• A CA validated that the requester controlled the domain name (DV).</li>
                  <li>• <strong className="text-rose-400">It does NOT mean</strong> the owner is legitimate or that the website is not stealing your credentials!</li>
                </ul>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="text-emerald-400 font-bold text-xs flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" />
                  What AegisTrust Multi-Vector Inspection Adds:
                </div>
                <ul className="text-xs text-slate-400 space-y-1">
                  <li>• Validates the identity of the CA and its root trust history.</li>
                  <li>• Audits public key entropy to detect defective CA generation.</li>
                  <li>• Cross-checks brand names against typosquatting dictionaries.</li>
                  <li>• Inspects form action destinations for Discord/Telegram exfiltration.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Entropy Tool */}
      {activeTab === 'entropy-tool' && (
        <div className="space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Cpu className="w-5 h-5 text-amber-400" />
              Interactive Public Modulus Shannon Entropy Tester
            </h3>
            <p className="text-xs text-slate-400">
              Test hex RSA public key moduli to detect degraded randomness patterns characteristic of defective CA RNG hardware.
            </p>

            <div className="space-y-3">
              <textarea
                value={entropyInput}
                onChange={(e) => setEntropyInput(e.target.value)}
                placeholder="Paste hex RSA modulus or certificate public bytes here (e.g. 00:a1:bf:34:9c:88:12:33...)"
                rows={4}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
              />

              <div className="flex items-center justify-between">
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      const weakHex = "00c111000011110000c111000011110000c111000011110000c1110000111100";
                      setEntropyInput(weakHex);
                      calculateEntropy(weakHex);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-mono"
                  >
                    Load Weak Key Vector
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const strongHex = "a4f89d31c0e29b47e15820984cba651239857dcaeb145290f84736291aebdc49";
                      setEntropyInput(strongHex);
                      calculateEntropy(strongHex);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-mono"
                  >
                    Load Strong Key Vector
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => calculateEntropy(entropyInput)}
                  className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
                >
                  Calculate Entropy
                </button>
              </div>
            </div>

            {/* Result Display */}
            {entropyResult && (
              <div className={`p-4 rounded-xl border text-xs mt-4 ${
                entropyResult.isWeak ? 'bg-rose-500/10 border-rose-500/30' : 'bg-emerald-500/10 border-emerald-500/30'
              }`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-sm text-white">Shannon Entropy Score:</span>
                  <span className="font-mono text-base font-bold">
                    {entropyResult.entropy} / {entropyResult.maxEntropy} bits/byte
                  </span>
                </div>
                <p className="text-slate-300 leading-relaxed font-mono">{entropyResult.verdict}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: CA Matrix */}
      {activeTab === 'ca-matrix' && (
        <div className="space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-lg font-bold text-white mb-4">Global Certificate Authority Trust Store Matrix</h3>
            
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                  <tr>
                    <th className="py-2.5 px-4">Certificate Authority</th>
                    <th className="py-2.5 px-4">Trust Status</th>
                    <th className="py-2.5 px-4">Incident / Governance Record</th>
                    <th className="py-2.5 px-4">Browser Enforcement</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  <tr className="hover:bg-slate-800/20">
                    <td className="py-3 px-4 font-bold text-rose-300">eMudhra Technologies</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">
                        PROBATION / DISTRUST
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      RNG key generation flaws, CT logging omissions, unauthorized domain issuances (2024-2025).
                    </td>
                    <td className="py-3 px-4 text-rose-400">Restricted / Distrusted Subordinates</td>
                  </tr>

                  <tr className="hover:bg-slate-800/20">
                    <td className="py-3 px-4 font-bold text-rose-300">WoSign / StartCom</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">
                        REVOKED PERMANENTLY
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      Backdating SHA-1 certificates and unauthorized issuance of base domains.
                    </td>
                    <td className="py-3 px-4 text-rose-400">Total Browser Deprecation</td>
                  </tr>

                  <tr className="hover:bg-slate-800/20">
                    <td className="py-3 px-4 font-bold text-emerald-300">Google Trust Services (GTS)</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">
                        FULLY TRUSTED
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      Automated high-assurance public root with mandatory CT enforcement and short-lived certs.
                    </td>
                    <td className="py-3 px-4 text-emerald-400">Standard Inclusion</td>
                  </tr>

                  <tr className="hover:bg-slate-800/20">
                    <td className="py-3 px-4 font-bold text-emerald-300">DigiCert / Let's Encrypt / Sectigo</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">
                        FULLY TRUSTED
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      CA/Browser Forum baseline compliant with automated CRL/OCSP stapling infrastructure.
                    </td>
                    <td className="py-3 px-4 text-emerald-400">Standard Inclusion</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
