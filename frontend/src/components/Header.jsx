import React from 'react';
import { Shield, ShieldAlert, Activity, Database, Key, Terminal, Download, Globe, Radio } from 'lucide-react';

export default function Header({ activeTab, setActiveTab, metrics }) {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40">
      {/* Top Threat Telemetry Ticker */}
      <div className="bg-slate-900/90 border-b border-slate-800/80 px-4 py-1.5 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-cyan-400 font-medium">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              AegisTrust Global Radar
            </span>
            <span className="text-slate-600">|</span>
            <span>Threat Index: <strong className="text-amber-400 font-semibold">Elevated (Tier-3)</strong></span>
            <span className="text-slate-600 hidden sm:inline">|</span>
            <span className="hidden sm:inline">Active Honeypots: <strong className="text-emerald-400">{metrics?.active_honeypots || 14} Nodes</strong></span>
            <span className="text-slate-600 hidden md:inline">|</span>
            <span className="hidden md:inline">CA Integrity Watchlist: <strong className="text-rose-400">eMudhra & 3 Roots Flagged</strong></span>
          </div>
          <div className="flex items-center gap-3 text-slate-400">
            <span>Verified Community IOCs: <strong className="text-cyan-400">{metrics?.total_iocs || 6}+</strong></span>
            <span className="text-slate-600">|</span>
            <span className="text-emerald-400 font-mono text-[11px] flex items-center gap-1">
              <Radio className="w-3 h-3 animate-spin" /> Engine v1.0.4 Online
            </span>
          </div>
        </div>
      </div>

      {/* Main Header Navigation */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div 
          onClick={() => setActiveTab('scanner')} 
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/10 group-hover:border-cyan-400 transition-all">
            <Shield className="w-5 h-5 group-hover:scale-110 transition-transform" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-bold text-white tracking-tight">AegisTrust</span>
              <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-semibold">
                AI SENTINEL
              </span>
            </div>
            <p className="text-xs text-slate-400">Phishing Detection & TLS Certificate Trust Intelligence</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1.5 bg-slate-900/80 p-1.5 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'scanner'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            Threat Scanner
          </button>

          <button
            onClick={() => setActiveTab('threat-intel')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'threat-intel'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            Threat Intelligence
          </button>

          <button
            onClick={() => setActiveTab('ca-dossier')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'ca-dossier'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            eMudhra & CA Lab
          </button>

          <button
            onClick={() => setActiveTab('interstitial')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'interstitial'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Browser Warning
          </button>

          <button
            onClick={() => setActiveTab('api-docs')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'api-docs'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            API & STIX
          </button>
        </nav>

        {/* Quick STIX export */}
        <div className="hidden lg:flex items-center gap-2">
          <a
            href="/api/threats/export/stix"
            download="aegistrust_threat_intelligence_stix21.json"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-700 text-slate-300 hover:border-cyan-500 hover:text-cyan-400 transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Export STIX 2.1
          </a>
        </div>
      </div>
    </header>
  );
}
