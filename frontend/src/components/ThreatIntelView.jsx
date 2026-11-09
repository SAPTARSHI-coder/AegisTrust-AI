import React, { useState, useEffect } from 'react';
import { 
  Database, Plus, Download, ThumbsUp, ThumbsDown, ShieldCheck, 
  AlertTriangle, Filter, ExternalLink, X, RefreshCw, CheckCircle2, UserCheck
} from 'lucide-react';

export default function ThreatIntelView({ metrics, onRefreshMetrics }) {
  const [reports, setReports] = useState([]);
  const [selectedSector, setSelectedSector] = useState('ALL');
  const [loading, setLoading] = useState(false);
  const [isSubmitModalOpen, setIsSubmitModalOpen] = useState(false);

  // Form State
  const [formUrl, setFormUrl] = useState('');
  const [formBrand, setFormBrand] = useState('');
  const [formSector, setFormSector] = useState('Banking & Finance');
  const [formThreatType, setFormThreatType] = useState('Phishing & Credential Theft');
  const [formNotes, setFormNotes] = useState('');
  const [formReporter, setFormReporter] = useState('SOC_Analyst');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const sectors = [
    'ALL',
    'Banking & Finance',
    'Education & Academia',
    'Government & Public Services',
    'Cryptocurrency & Web3',
    'Recruitment & Professional'
  ];

  const fetchReports = async () => {
    setLoading(true);
    try {
      const url = selectedSector === 'ALL' 
        ? '/api/threats' 
        : `/api/threats?sector=${encodeURIComponent(selectedSector)}`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.reports) {
        setReports(data.reports);
      }
    } catch (err) {
      console.error('Error fetching threats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [selectedSector]);

  const handleVote = async (reportId, voteType) => {
    try {
      const res = await fetch(`/api/threats/${reportId}/vote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vote_type: voteType })
      });
      const data = await res.json();
      if (!data.error) {
        setReports(reports.map(r => r.id === reportId ? { ...r, upvotes: data.upvotes, downvotes: data.downvotes } : r));
      }
    } catch (err) {
      console.error('Voting error:', err);
    }
  };

  const handleVerify = async (reportId) => {
    try {
      const res = await fetch(`/api/threats/${reportId}/verify`, { method: 'POST' });
      const data = await res.json();
      if (data.verified) {
        setReports(reports.map(r => r.id === reportId ? { ...r, verified_by_analyst: 1 } : r));
        if (onRefreshMetrics) onRefreshMetrics();
      }
    } catch (err) {
      console.error('Verify error:', err);
    }
  };

  const handleSubmitReport = async (e) => {
    e.preventDefault();
    if (!formUrl.trim()) return;
    setIsSubmitting(true);

    try {
      const res = await fetch('/api/threats/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: formUrl.trim(),
          target_brand: formBrand.trim() || 'Unknown Brand',
          target_sector: formSector,
          threat_type: formThreatType,
          risk_score: 85,
          evidence_notes: formNotes,
          submitted_by: formReporter.trim() || 'Community_Analyst'
        })
      });

      if (res.ok) {
        setIsSubmitModalOpen(false);
        setFormUrl('');
        setFormBrand('');
        setFormNotes('');
        fetchReports();
        if (onRefreshMetrics) onRefreshMetrics();
      }
    } catch (err) {
      console.error('Submit report error:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner and Metrics */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <Database className="w-5 h-5 text-cyan-400" />
              Collaborative Threat Intelligence Exchange
            </h2>
            <p className="text-sm text-slate-400">
              Crowdsourced security indicators, verified analyst endorsements, and standardized STIX 2.1 intelligence sharing.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={() => setIsSubmitModalOpen(true)}
              className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center gap-1.5 transition-all shadow-md"
            >
              <Plus className="w-4 h-4" />
              Report Malicious Site
            </button>

            <a
              href="/api/threats/export/stix"
              download="aegistrust_threat_intelligence_stix21.json"
              className="px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 hover:border-cyan-500 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-all"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              STIX 2.1
            </a>

            <a
              href="/api/threats/export/json"
              download="aegistrust_iocs.json"
              className="px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 hover:border-cyan-500 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-all"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              JSON
            </a>
          </div>
        </div>

        {/* Aggregate Stats Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-slate-950/70 p-3.5 rounded-xl border border-slate-800">
            <span className="text-[11px] text-slate-400 font-medium">Community Threat Reports</span>
            <div className="text-2xl font-bold font-mono text-white mt-1">
              {metrics?.total_reports || reports.length}
            </div>
          </div>

          <div className="bg-slate-950/70 p-3.5 rounded-xl border border-slate-800">
            <span className="text-[11px] text-slate-400 font-medium">Analyst Verified Threats</span>
            <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
              {metrics?.verified_threats || 5}
            </div>
          </div>

          <div className="bg-slate-950/70 p-3.5 rounded-xl border border-slate-800">
            <span className="text-[11px] text-slate-400 font-medium">Top Targeted Sector</span>
            <div className="text-lg font-bold text-amber-400 mt-1 truncate">
              Banking & Finance
            </div>
          </div>

          <div className="bg-slate-950/70 p-3.5 rounded-xl border border-slate-800">
            <span className="text-[11px] text-slate-400 font-medium">OASIS Export Standard</span>
            <div className="text-lg font-bold text-emerald-400 mt-1 font-mono">
              STIX 2.1 Ready
            </div>
          </div>
        </div>
      </div>

      {/* Sector Filter Bar */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        <span className="text-xs text-slate-500 flex items-center gap-1 font-semibold uppercase tracking-wider pl-1">
          <Filter className="w-3 h-3" /> Sector:
        </span>
        {sectors.map((sec) => (
          <button
            key={sec}
            onClick={() => setSelectedSector(sec)}
            className={`px-3 py-1.5 rounded-lg text-xs whitespace-nowrap transition-all ${
              selectedSector === sec
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400 font-medium'
                : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {sec}
          </button>
        ))}
      </div>

      {/* Reports Feed Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
              <tr>
                <th className="py-3 px-4">Threat Indicator & URL</th>
                <th className="py-3 px-4">Target Brand / Sector</th>
                <th className="py-3 px-4">Attack Vector</th>
                <th className="py-3 px-4">Risk Index</th>
                <th className="py-3 px-4">Verification</th>
                <th className="py-3 px-4 text-right">Consensus Votes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {reports.map((r) => (
                <tr key={r.id} className="hover:bg-slate-800/20 transition-colors">
                  {/* Indicator / URL */}
                  <td className="py-3.5 px-4">
                    <div className="font-mono text-slate-200 font-semibold truncate max-w-xs sm:max-w-md">
                      {r.url}
                    </div>
                    <div className="text-[11px] text-slate-500 flex items-center gap-2 mt-0.5">
                      <span>Reporter: {r.submitted_by}</span>
                      <span>•</span>
                      <span>{new Date(r.created_at).toLocaleDateString()}</span>
                    </div>
                    {r.evidence_notes && (
                      <p className="text-[11px] text-slate-400 italic mt-1 max-w-md">
                        "{r.evidence_notes}"
                      </p>
                    )}
                  </td>

                  {/* Target Brand / Sector */}
                  <td className="py-3.5 px-4">
                    <div className="font-semibold text-white">{r.target_brand}</div>
                    <span className="inline-block mt-0.5 px-2 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">
                      {r.target_sector}
                    </span>
                  </td>

                  {/* Threat Type */}
                  <td className="py-3.5 px-4">
                    <span className="text-slate-300 font-medium">{r.threat_type}</span>
                  </td>

                  {/* Risk Score */}
                  <td className="py-3.5 px-4">
                    <span className="font-mono font-bold text-rose-400 text-sm">
                      {r.risk_score}<span className="text-[10px] text-slate-500">/100</span>
                    </span>
                  </td>

                  {/* Verification Status */}
                  <td className="py-3.5 px-4">
                    {r.verified_by_analyst ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-semibold text-[10px]">
                        <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                        Analyst Verified
                      </span>
                    ) : (
                      <button
                        onClick={() => handleVerify(r.id)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-all"
                      >
                        <UserCheck className="w-3 h-3 text-slate-400" />
                        Verify Endorsement
                      </button>
                    )}
                  </td>

                  {/* Voting Consensus */}
                  <td className="py-3.5 px-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleVote(r.id, 'up')}
                        className="flex items-center gap-1 px-2 py-1 rounded bg-slate-950 hover:bg-emerald-950/40 border border-slate-800 text-slate-400 hover:text-emerald-400 text-xs transition-all"
                        title="Confirm as Malicious"
                      >
                        <ThumbsUp className="w-3 h-3" />
                        <span className="font-mono">{r.upvotes}</span>
                      </button>
                      <button
                        onClick={() => handleVote(r.id, 'down')}
                        className="flex items-center gap-1 px-2 py-1 rounded bg-slate-950 hover:bg-rose-950/40 border border-slate-800 text-slate-400 hover:text-rose-400 text-xs transition-all"
                        title="Report False Positive"
                      >
                        <ThumbsDown className="w-3 h-3" />
                        <span className="font-mono">{r.downvotes}</span>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Submission Modal */}
      {isSubmitModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setIsSubmitModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
              <Plus className="w-5 h-5 text-cyan-400" />
              Report Malicious Website or Phishing Threat
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Your submission will be immediately correlated and shared across the global threat exchange.
            </p>

            <form onSubmit={handleSubmitReport} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Target Malicious URL / Phishing Address *
                </label>
                <input
                  type="text"
                  required
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  placeholder="https://fake-login-portal.top/auth"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    Targeted Entity / Brand
                  </label>
                  <input
                    type="text"
                    value={formBrand}
                    onChange={(e) => setFormBrand(e.target.value)}
                    placeholder="e.g. JPMorgan Chase"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    Industry Sector
                  </label>
                  <select
                    value={formSector}
                    onChange={(e) => setFormSector(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Banking & Finance">Banking & Finance</option>
                    <option value="Education & Academia">Education & Academia</option>
                    <option value="Government & Public Services">Government & Public Services</option>
                    <option value="Cryptocurrency & Web3">Cryptocurrency & Web3</option>
                    <option value="Recruitment & Professional">Recruitment & Professional</option>
                    <option value="General Web">General Web</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Threat Classification
                </label>
                <select
                  value={formThreatType}
                  onChange={(e) => setFormThreatType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                >
                  <option value="Phishing & Credential Theft">Phishing & Credential Theft</option>
                  <option value="eMudhra CA Anomaly / Rogue Certificate">eMudhra CA Anomaly / Rogue Certificate</option>
                  <option value="Fake Academic / Recruitment Scam">Fake Academic / Recruitment Scam</option>
                  <option value="Government Tax / Subsidy Phishing">Government Tax / Subsidy Phishing</option>
                  <option value="Web3 Wallet Drainer">Web3 Wallet Drainer</option>
                  <option value="Malicious Redirect / Exploit Kit">Malicious Redirect / Exploit Kit</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Observed Evidence / Attack Vector Notes
                </label>
                <textarea
                  value={formNotes}
                  onChange={(e) => setFormNotes(e.target.value)}
                  placeholder="e.g. Received email lure claiming account suspension. Form posts credentials to Discord webhook."
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Your Handle / Analyst Alias
                </label>
                <input
                  type="text"
                  value={formReporter}
                  onChange={(e) => setFormReporter(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsSubmitModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-medium hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition-all disabled:opacity-50"
                >
                  {isSubmitting ? 'Submitting...' : 'Publish to Exchange'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
