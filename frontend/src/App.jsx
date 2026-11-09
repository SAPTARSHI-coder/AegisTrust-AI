import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import ScannerView from './components/ScannerView';
import ThreatIntelView from './components/ThreatIntelView';
import CertificateLabView from './components/CertificateLabView';
import BrowserWarningModal from './components/BrowserWarningModal';
import ApiSandboxView from './components/ApiSandboxView';
import { Shield, Terminal, Globe } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [metrics, setMetrics] = useState(null);
  const [modalScanData, setModalScanData] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchMetrics = async () => {
    try {
      const res = await fetch('/api/threats/metrics');
      const data = await res.json();
      setMetrics(data);
    } catch (err) {
      console.error('Failed to load metrics:', err);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  const handleOpenInterstitial = (data) => {
    setModalScanData(data);
    setIsModalOpen(true);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col cyber-grid">
      {/* Top Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        metrics={metrics}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8">
        {activeTab === 'scanner' && (
          <ScannerView onOpenInterstitial={handleOpenInterstitial} />
        )}

        {activeTab === 'threat-intel' && (
          <ThreatIntelView metrics={metrics} onRefreshMetrics={fetchMetrics} />
        )}

        {activeTab === 'ca-dossier' && (
          <CertificateLabView />
        )}

        {activeTab === 'interstitial' && (
          <BrowserWarningModal
            scanData={modalScanData}
            onClose={() => setActiveTab('scanner')}
          />
        )}

        {activeTab === 'api-docs' && (
          <ApiSandboxView />
        )}
      </main>

      {/* Interactive Modal Overlay for Interstitial (if triggered from scanner button) */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-4">
          <BrowserWarningModal
            scanData={modalScanData}
            onClose={() => setIsModalOpen(false)}
          />
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/90 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-300">AegisTrust AI Platform</span>
            <span>— Intelligent Phishing, Certificate Validation & Threat Intelligence</span>
          </div>

          <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
            <span>STIX 2.1 Compliant</span>
            <span>•</span>
            <span>RFC 5280 X.509</span>
            <span>•</span>
            <span>eMudhra Watchlist Synchronized</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
