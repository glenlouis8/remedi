'use client';

import { useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@clerk/nextjs';
import { ShieldCheck, Eye, EyeOff, ExternalLink, AlertTriangle, Lock, Upload, CheckCircle, ArrowLeft } from 'lucide-react';
import Link from 'next/link';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080';

function parseCredentialsCsv(text: string): { access_key: string; secret_key: string } | null {
  const lines = text.trim().split('\n').map(l => l.trim()).filter(Boolean);
  for (const line of lines) {
    const cols = line.split(',').map(c => c.trim().replace(/^"|"$/g, ''));
    if (cols.length >= 2 && cols[0].startsWith('AKIA') && cols[0].length === 20) {
      return { access_key: cols[0], secret_key: cols[1] };
    }
  }
  return null;
}

export default function OnboardingPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [accountName, setAccountName] = useState('');
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [csvParsed, setCsvParsed] = useState(false);
  const [dragging, setDragging] = useState(false);

  function handleFile(file: File) {
    setError('');
    setCsvParsed(false);
    if (!file.name.endsWith('.csv')) { setError('Please upload a .csv file.'); return; }
    const reader = new FileReader();
    reader.onload = (e) => {
      const result = parseCredentialsCsv(e.target?.result as string);
      if (!result) { setError('Could not read credentials from this file. Make sure it\'s the CSV downloaded from AWS.'); return; }
      setAccessKey(result.access_key);
      setSecretKey(result.secret_key);
      setCsvParsed(true);
    };
    reader.readAsText(file);
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const token = await getToken();
      const res = await fetch(`${API}/api/accounts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ account_name: accountName.trim() || 'Default', access_key: accessKey, secret_key: secretKey }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail ?? 'Failed to connect account');
      }
      router.push('/dashboard');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-white flex flex-col" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');`}</style>

      {/* Top nav */}
      <header className="shrink-0 border-b border-white/6 px-8 h-14 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.25)' }}>
            <ShieldCheck size={15} className="text-violet-400" />
          </div>
          <span className="font-semibold tracking-tight text-white">Remedi</span>
        </Link>
        <Link href="/dashboard" className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors">
          <ArrowLeft size={13} /> Back to dashboard
        </Link>
      </header>

      {/* Two-column layout */}
      <div className="flex-1 grid grid-cols-2 max-w-5xl mx-auto w-full px-8 py-16 gap-16">

        {/* Left: context */}
        <div className="flex flex-col justify-center">
          <h1 className="text-3xl font-bold text-white mb-3 leading-snug">Connect your AWS account</h1>
          <p className="text-slate-400 mb-2 leading-relaxed">
            Remedi creates a dedicated IAM user with least-privilege permissions — only what it needs to scan and fix your account, nothing more.
          </p>
          <p className="text-xs text-amber-500/80 bg-amber-500/8 border border-amber-500/15 rounded-lg px-3 py-2 mb-6">
            You need at least one AWS account connected to access the dashboard.
          </p>
          <div className="space-y-4">
            {[
              { icon: '🔑', title: 'Least-privilege access', desc: 'No AdministratorAccess. A custom policy scoped to only the actions Remedi needs.' },
              { icon: '🗑️', title: 'Revoke anytime', desc: 'Delete the CloudFormation stack to immediately remove all credentials and access.' },
              { icon: '🔒', title: 'Encrypted at rest', desc: 'Credentials are AES-256 encrypted in the database and deleted when you sign out.' },
            ].map(({ icon, title, desc }) => (
              <div key={title} className="flex gap-3">
                <span className="text-lg mt-0.5">{icon}</span>
                <div>
                  <p className="text-sm font-medium text-slate-200">{title}</p>
                  <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: steps */}
        <div className="flex flex-col justify-center space-y-4">

        {/* Step 1: CloudFormation */}
        <div className="rounded-xl border border-white/8 p-4 space-y-3" style={{ background: 'rgba(14,14,18,0.8)' }}>
          <div className="flex items-center gap-2">
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">Step 1 — Create IAM credentials</p>
            <span className="text-xs font-medium px-2 py-0.5 rounded-full" style={{ background: 'rgba(139,92,246,0.15)', color: '#a78bfa', border: '1px solid rgba(139,92,246,0.2)' }}>Recommended</span>
          </div>
          <a
            href="https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://remedi-cloudformation-templates.s3.amazonaws.com/remedi-agent.yaml&stackName=remedi-agent"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between w-full bg-violet-500 hover:bg-violet-400 text-white rounded-lg px-4 py-2.5 font-medium text-sm transition-colors"
          >
            <span>Launch AWS setup</span>
            <ExternalLink size={14} />
          </a>
          <p className="text-xs text-slate-500 leading-relaxed">
            Opens CloudFormation in your AWS account. Copy the <strong className="text-slate-400">Access Key ID</strong> and <strong className="text-slate-400">Secret Access Key</strong> from the <strong className="text-slate-400">Outputs</strong> tab when the stack finishes.
          </p>
          <a
            href="https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks?filteringText=remedi-agent"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-violet-500 hover:text-violet-400 transition-colors"
          >
            Already set up? View your stack <ExternalLink size={10} />
          </a>
        </div>

        {/* Step 2: Enter credentials */}
        <div className="rounded-xl border border-white/8 p-4" style={{ background: 'rgba(14,14,18,0.8)' }}>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-4">Step 2 — Enter credentials</p>

          <form onSubmit={handleSubmit} className="space-y-4" autoComplete="off">

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Account nickname <span className="text-slate-600 font-normal">(optional)</span></label>
              <input
                type="text"
                value={accountName}
                onChange={e => setAccountName(e.target.value)}
                placeholder="e.g. Production, Dev, Personal"
                maxLength={40}
                autoComplete="off"
                className="w-full rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-violet-500/30 transition-colors"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
              />
            </div>

            {/* CSV upload */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Upload credentials CSV</label>
              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={handleDrop}
                className="w-full rounded-xl px-4 py-5 flex flex-col items-center gap-2 cursor-pointer transition-all"
                style={{
                  border: `2px dashed ${csvParsed || dragging ? 'rgba(139,92,246,0.5)' : 'rgba(255,255,255,0.08)'}`,
                  background: csvParsed || dragging ? 'rgba(139,92,246,0.05)' : 'transparent',
                }}
              >
                {csvParsed ? (
                  <>
                    <CheckCircle size={18} className="text-violet-400" />
                    <p className="text-sm text-violet-300 font-medium">Credentials loaded</p>
                    <p className="text-xs text-slate-500" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{accessKey}</p>
                  </>
                ) : (
                  <>
                    <Upload size={18} className="text-slate-600" />
                    <p className="text-sm text-slate-500">Drop <code className="px-1 rounded text-xs text-slate-400" style={{ background: 'rgba(255,255,255,0.05)' }}>credentials.csv</code> here or click to browse</p>
                  </>
                )}
              </div>
              <input ref={fileInputRef} type="file" accept=".csv" className="hidden"
                onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
            </div>

            <div className="flex items-center gap-3">
              <div className="flex-1 h-px bg-white/6" />
              <span className="text-xs text-slate-600">or enter manually</span>
              <div className="flex-1 h-px bg-white/6" />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Access Key ID</label>
              <input
                type="text"
                value={accessKey}
                onChange={(e) => { setAccessKey(e.target.value.trim()); setCsvParsed(false); }}
                placeholder="AKIAIOSFODNN7EXAMPLE"
                autoComplete="off"
                className="w-full rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-violet-500/30 transition-colors"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: "'JetBrains Mono', monospace" }}
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Secret Access Key</label>
              <div className="relative">
                <input
                  type={showSecret ? 'text' : 'password'}
                  value={secretKey}
                  onChange={(e) => { setSecretKey(e.target.value.trim()); setCsvParsed(false); }}
                  placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfi…"
                  autoComplete="new-password"
                  className="w-full rounded-lg px-4 py-2.5 pr-10 text-sm text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-violet-500/30 transition-colors"
                  style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: "'JetBrains Mono', monospace" }}
                  required
                />
                <button type="button" onClick={() => setShowSecret(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors">
                  {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 text-red-400 text-sm rounded-lg px-3 py-2.5" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
                <AlertTriangle size={14} className="shrink-0" />
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !accessKey || !secretKey}
              className="w-full bg-violet-500 hover:bg-violet-400 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors text-sm"
            >
              {loading ? 'Connecting…' : 'Connect account'}
            </button>
          </form>
        </div>

        <div className="flex items-start gap-2 text-xs text-slate-600">
          <Lock size={12} className="shrink-0 mt-0.5" />
          <p>Credentials are encrypted at rest and deleted on sign-out. Delete the IAM user anytime to revoke all access.</p>
        </div>

        </div>{/* end right column */}
      </div>{/* end grid */}
    </div>
  );
}
