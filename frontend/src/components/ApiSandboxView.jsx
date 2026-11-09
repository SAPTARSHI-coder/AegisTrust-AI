import React, { useState } from 'react';
import { Terminal, Copy, Check, Play, Download, Code, Globe } from 'lucide-react';

export default function ApiSandboxView() {
  const [selectedLang, setSelectedLang] = useState('curl');
  const [copied, setCopied] = useState(false);
  const [endpointResult, setEndpointResult] = useState(null);
  const [apiLoading, setApiLoading] = useState(false);

  const codeSnippets = {
    curl: `curl -X POST "http://localhost:8000/api/scan" \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://secure-banking-auth.net/login", "live_scan": true}'`,

    python: `import requests

url = "http://localhost:8000/api/scan"
payload = {
    "url": "https://secure-banking-auth.net/login",
    "live_scan": True
}

response = requests.post(url, json=payload)
data = response.json()
print("Verdict:", data["verdict"]["category"])
print("Threat Score:", data["verdict"]["threat_score"])
print("eMudhra CA Flagged:", data["engines"]["certificate_and_trust"]["emudhra_incident_analysis"]["is_emudhra_ca"])`,

    javascript: `const response = await fetch('http://localhost:8000/api/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: 'https://secure-banking-auth.net/login',
    live_scan: true
  })
});

const data = await response.json();
console.log('Threat Index:', data.verdict.threat_score);
console.log('Actionable Steps:', data.recommendations.for_soc_analysts);`
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const testLiveEndpoint = async () => {
    setApiLoading(true);
    try {
      const res = await fetch('/api/threats/metrics');
      const data = await res.json();
      setEndpointResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setEndpointResult(JSON.stringify({ error: err.message }, null, 2));
    } finally {
      setApiLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 mb-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-[11px] font-semibold">
                DEVELOPER API & AUTOMATION
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              REST API & OASIS STIX 2.1 Documentation
            </h2>
            <p className="text-sm text-slate-400">
              Integrate AegisTrust scanning into your SIEM, SOAR, EDR agents, or browser proxy gateways.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <a
              href="/docs"
              target="_blank"
              rel="noreferrer"
              className="px-3.5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-md"
            >
              <Globe className="w-3.5 h-3.5" />
              Interactive OpenAPI Docs (/docs)
            </a>
          </div>
        </div>

        {/* Endpoints Table */}
        <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden mb-6">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 text-slate-400 font-mono border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Method</th>
                <th className="py-2.5 px-4">Endpoint</th>
                <th className="py-2.5 px-4">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              <tr>
                <td className="py-2.5 px-4"><span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-bold">POST</span></td>
                <td className="py-2.5 px-4 text-cyan-300">/api/scan</td>
                <td className="py-2.5 px-4 text-slate-300 font-sans">Multi-engine threat, certificate, and web posture scan.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4"><span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold">GET</span></td>
                <td className="py-2.5 px-4 text-cyan-300">/api/threats</td>
                <td className="py-2.5 px-4 text-slate-300 font-sans">Query collaborative threat feed by sector.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4"><span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-bold">POST</span></td>
                <td className="py-2.5 px-4 text-cyan-300">/api/threats/report</td>
                <td className="py-2.5 px-4 text-slate-300 font-sans">Submit community threat report with evidence.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4"><span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold">GET</span></td>
                <td className="py-2.5 px-4 text-cyan-300">/api/threats/export/stix</td>
                <td className="py-2.5 px-4 text-slate-300 font-sans">Download verified threat bundle in OASIS STIX 2.1 format.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4"><span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold">GET</span></td>
                <td className="py-2.5 px-4 text-cyan-300">/api/threats/metrics</td>
                <td className="py-2.5 px-4 text-slate-300 font-sans">Real-time aggregate platform metrics.</td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Code Snippets Box */}
        <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
          <div className="flex items-center justify-between bg-slate-900/80 px-4 py-2 border-b border-slate-800">
            <div className="flex gap-2">
              {['curl', 'python', 'javascript'].map((lang) => (
                <button
                  key={lang}
                  onClick={() => setSelectedLang(lang)}
                  className={`px-3 py-1 rounded text-xs font-mono capitalize transition-all ${
                    selectedLang === lang
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {lang}
                </button>
              ))}
            </div>

            <button
              onClick={() => copyToClipboard(codeSnippets[selectedLang])}
              className="text-xs text-slate-400 hover:text-white flex items-center gap-1 font-mono"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>

          <pre className="p-4 text-xs font-mono text-cyan-300 overflow-x-auto leading-relaxed bg-slate-950">
            {codeSnippets[selectedLang]}
          </pre>
        </div>

        {/* Live Interactive Test Box */}
        <div className="mt-6 pt-6 border-t border-slate-800">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Play className="w-3.5 h-3.5 text-emerald-400" />
              Live Endpoint Sandbox Tester (GET /api/threats/metrics)
            </h4>

            <button
              onClick={testLiveEndpoint}
              disabled={apiLoading}
              className="px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all"
            >
              {apiLoading ? 'Executing...' : 'Run Query'}
            </button>
          </div>

          {endpointResult && (
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-60">
              {endpointResult}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
