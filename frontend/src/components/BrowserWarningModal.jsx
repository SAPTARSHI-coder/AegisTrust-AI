import React, { useState } from 'react';
import { ShieldAlert, ArrowLeft, AlertTriangle, Lock, Globe, ChevronDown, ChevronUp, X } from 'lucide-react';

export default function BrowserWarningModal({ scanData, onClose }) {
  const [showAdvanced, setShowAdvanced] = useState(false);

  const fallbackData = {
    target: {
      url: 'https://secure-banking-auth.net/login',
      targeted_brand: 'Banking Consortia',
      target_sector: 'Banking & Finance'
    },
    verdict: {
      threat_score: 95,
      category: 'CRITICAL_MALICIOUS'
    },
    engines: {
      certificate_and_trust: {
        issuer: { org: 'eMudhra Technologies Limited', cn: 'eMudhra Sub-CA' }
      }
    },
    all_findings: [
      { title: 'eMudhra CA Anomaly Flagged', detail: 'Certificate Authority is under browser distrust enforcement.' },
      { title: 'Weak Key Generation Detected', detail: 'RSA public modulus has low entropy indicative of flawed CA RNG.' },
      { title: 'Credential Theft Forms', detail: 'Page solicits debit cards and CVVs.' }
    ]
  };

  const data = scanData || fallbackData;
  const brand = data.target?.targeted_brand !== 'Generic / Unclassified' ? data.target?.targeted_brand : 'Protected Online Service';

  return (
    <div className="min-h-[80vh] flex items-center justify-center p-4">
      <div className="max-w-2xl w-full bg-slate-900 border-2 border-rose-500/50 rounded-3xl p-8 sm:p-10 shadow-2xl relative glow-red text-slate-100">
        {onClose && (
          <button
            onClick={onClose}
            className="absolute top-6 right-6 text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        )}

        {/* Warning Icon & Heading */}
        <div className="flex items-center gap-4 mb-6">
          <div className="w-14 h-14 rounded-2xl bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <div>
            <div className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400">
              AegisTrust Gateway Intercept
            </div>
            <h2 className="text-2xl font-black text-white tracking-tight">
              Deceptive / Malicious Website Blocked
            </h2>
          </div>
        </div>

        {/* Target Details */}
        <div className="bg-slate-950/80 border border-rose-500/30 rounded-xl p-4 mb-6 space-y-2">
          <div className="flex justify-between items-center text-xs">
            <span className="text-slate-400">Target Address:</span>
            <span className="font-mono text-rose-300 font-bold truncate max-w-xs">{data.target?.url}</span>
          </div>
          <div className="flex justify-between items-center text-xs">
            <span className="text-slate-400">Detected Impersonation:</span>
            <span className="font-semibold text-white">{brand}</span>
          </div>
          <div className="flex justify-between items-center text-xs">
            <span className="text-slate-400">Calculated Threat Index:</span>
            <span className="font-mono text-rose-400 font-bold text-sm">
              {data.verdict?.threat_score || 90} / 100 (CRITICAL)
            </span>
          </div>
        </div>

        {/* Explanatory Text */}
        <p className="text-sm text-slate-300 leading-relaxed mb-6">
          AegisTrust AI Sentinel intercepted this connection because it identified sophisticated phishing indicators, 
          unauthorized brand impersonation, or compromised Certificate Authority trust chains. Entering passwords, 
          payment details, or personal data on this site would likely result in immediate financial theft or identity compromise.
        </p>

        {/* Primary Action Buttons */}
        <div className="flex flex-col sm:flex-row items-center gap-3 mb-6">
          <button
            onClick={() => {
              if (onClose) onClose();
              window.history.back();
            }}
            className="w-full sm:w-auto flex-1 px-6 py-3 rounded-xl bg-rose-500 hover:bg-rose-400 text-slate-950 font-bold text-sm transition-all shadow-lg flex items-center justify-center gap-2"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Safety (Recommended)
          </button>

          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full sm:w-auto px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 text-xs font-medium flex items-center justify-center gap-1.5 transition-all"
          >
            <span>Advanced Forensics</span>
            {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Expandable Advanced Forensics */}
        {showAdvanced && (
          <div className="bg-slate-950 rounded-xl p-4 border border-slate-800 text-xs space-y-3">
            <div className="font-mono text-slate-400 font-semibold uppercase text-[11px]">
              Technical Telemetry Triggering Block:
            </div>
            <ul className="space-y-1.5 text-slate-300 font-mono text-[11px]">
              {data.all_findings?.slice(0, 4).map((f, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-rose-400 font-bold">•</span>
                  <span><strong>{f.title}:</strong> {f.detail}</span>
                </li>
              ))}
            </ul>
            <div className="pt-2 border-t border-slate-800 flex justify-between items-center text-[10px] text-slate-500">
              <span>Security Event ID: aegis-sec-{(Math.random()*1e9).toFixed(0)}</span>
              <button 
                onClick={() => alert("Bypassing security warnings exposes your credentials and identity to hostile actors. Proceed only in an isolated sandbox!")}
                className="text-rose-400/70 hover:text-rose-300 underline"
              >
                Proceed anyway (Unsafe)
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
