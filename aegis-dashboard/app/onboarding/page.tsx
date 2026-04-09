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
    if (!file.name.endsWith('.csv')) {
      setError('Please upload a .csv file.');
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      const result = parseCredentialsCsv(text);
      if (!result) {
        setError('Could not read credentials from this file. Make sure it\'s the CSV downloaded from AWS.');
        return;
      }
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
    <div className="min-h-screen bg-[#09090b] text-white flex flex-col items-center justify-center px-6 py-16" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');`}</style>


      <div className="relative z-10 flex items-center justify-between w-full max-w-md mb-10">
        <Link href="/dashboard" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.25)' }}>
            <ShieldCheck size={15} className="text-violet-400" />
          </div>
          <span className="font-semibold tracking-tight text-white">Remedi</span>
        </Link>
        <Link href="/dashboard" className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors">
          <ArrowLeft size={13} /> Back to dashboard
        </Link>
      </div>

      <div className="relative z-10 w-full max-w-md">
        <h1 className="text-2xl font-bold mb-2 text-white">Connect your AWS account</h1>
        <p className="text-slate-400 text-sm mb-6">
          Create a dedicated IAM user for Remedi — takes 2 minutes and you can delete it anytime to revoke access.
        </p>

        {/* Setup instructions */}
        <div className="border border-white/8 rounded-xl p-4 mb-6 text-sm" style={{ background: 'rgba(14,14,18,0.8)' }}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <p className="text-white font-medium">Quick setup</p>
              <span className="text-xs font-medium px-2 py-0.5 rounded-full" style={{ background: 'rgba(139,92,246,0.15)', color: '#a78bfa', border: '1px solid rgba(139,92,246,0.2)' }}>Recommended</span>
            </div>
            <Link href="/setup-details" className="text-xs text-slate-500 hover:text-violet-400 transition-colors">
              What does this do?
            </Link>
          </div>

          {/* One-click option */}
          <a
            href="https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://remedi-cloudformation-templates.s3.amazonaws.com/remedi-agent.yaml&stackName=remedi-agent"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between w-full bg-violet-500 hover:bg-violet-400 text-white rounded-lg px-4 py-2.5 font-medium transition-colors mb-3"
          >
            <span>Launch AWS setup automatically</span>
            <ExternalLink size={14} />
          </a>
          <p className="text-xs text-slate-400 mb-2">
            Opens AWS CloudFormation — automatically creates a <code className="px-1 rounded text-violet-400" style={{ background: 'rgba(139,92,246,0.1)' }}>remedi-agent</code> IAM user with <strong className="text-slate-300">only the minimum permissions needed</strong>, no AdministratorAccess. Copy the credentials from the <strong className="text-slate-300">Outputs</strong> tab when done. Delete the stack anytime to immediately revoke all access.
          </p>
          <a
            href="https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks?filteringText=remedi-agent"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs text-violet-500 hover:text-violet-400 font-medium transition-colors mb-3"
          >
            Already set up? View your existing stack <ExternalLink size={10} />
          </a>

          {/* Divider */}
          <div className="flex items-center gap-3 mb-3">
            <div className="flex-1 h-px bg-white/8" />
            <span className="text-xs text-slate-600">or set up manually</span>
            <div className="flex-1 h-px bg-white/8" />
          </div>

          <ol className="text-slate-400 space-y-1.5 list-decimal list-inside">
            <li>
              Open{' '}
              <a href="https://console.aws.amazon.com/iam/home#/users/create" target="_blank" rel="noopener noreferrer" className="text-violet-400 hover:underline inline-flex items-center gap-0.5">
                IAM → Users → Create user <ExternalLink size={10} />
              </a>
            </li>
            <li>Name it <code className="px-1 rounded text-xs text-violet-300" style={{ background: 'rgba(139,92,246,0.1)' }}>remedi-agent</code></li>
            <li>Attach the <code className="px-1 rounded text-xs text-slate-300" style={{ background: 'rgba(255,255,255,0.05)' }}>AdministratorAccess</code> policy</li>
            <li>Go to <strong className="text-slate-300">Security credentials</strong> → Create access key</li>
            <li>Download the <strong className="text-slate-300">.csv file</strong> and upload it below</li>
          </ol>
          <div className="mt-3 flex gap-2 rounded-lg border border-amber-500/20 px-3 py-2.5" style={{ background: 'rgba(245,158,11,0.08)' }}>
            <span className="text-amber-400 mt-0.5">⚠</span>
            <p className="text-xs text-amber-300/80 leading-relaxed">
              <strong>Why AdministratorAccess?</strong> Manual setup uses the broadest AWS policy because creating a custom one requires copying a JSON document. If you prefer minimum permissions, use the automatic setup above — it creates a least-privilege policy automatically.
            </p>
          </div>
        </div>

        {/* Already have keys */}
        <div className="flex items-center gap-3 mb-4">
          <div className="flex-1 h-px bg-white/6" />
          <span className="text-xs text-slate-500 shrink-0">Already have keys? Paste them below</span>
          <div className="flex-1 h-px bg-white/6" />
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" autoComplete="off">

          {/* Account name */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">Account nickname</label>
            <input
              type="text"
              value={accountName}
              onChange={e => setAccountName(e.target.value)}
              placeholder="e.g. Production, Dev, Personal"
              maxLength={40}
              autoComplete="off"
              className="w-full rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-500/50 transition-colors"
              style={{ background: 'rgba(14,14,18,0.8)', border: '1px solid rgba(255,255,255,0.08)' }}
            />
            <p className="text-xs text-slate-600 mt-1">Optional — defaults to &quot;Default&quot; if left blank. Max 3 accounts.</p>
          </div>

          {/* CSV upload */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">Upload credentials CSV</label>
            <div
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
              className="w-full rounded-xl px-4 py-6 flex flex-col items-center gap-2 cursor-pointer transition-all"
              style={{
                border: `2px dashed ${csvParsed || dragging ? 'rgba(139,92,246,0.5)' : 'rgba(255,255,255,0.08)'}`,
                background: csvParsed || dragging ? 'rgba(139,92,246,0.05)' : 'rgba(14,14,18,0.5)',
              }}
            >
              {csvParsed ? (
                <>
                  <CheckCircle size={20} className="text-violet-400" />
                  <p className="text-sm text-violet-300 font-medium">Credentials loaded</p>
                  <p className="text-xs text-slate-500" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{accessKey}</p>
                </>
              ) : (
                <>
                  <Upload size={20} className="text-slate-600" />
                  <p className="text-sm text-slate-500">Drop your <code className="px-1 rounded text-xs text-slate-400" style={{ background: 'rgba(255,255,255,0.05)' }}>credentials.csv</code> here</p>
                  <p className="text-xs text-slate-600">or click to browse</p>
                </>
              )}
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv"
              className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
            />
          </div>

          {/* Divider */}
          <div className="flex items-center gap-3">
            <div className="flex-1 h-px bg-white/8" />
            <span className="text-xs text-slate-600">or enter manually</span>
            <div className="flex-1 h-px bg-white/8" />
          </div>

          {/* Manual fields */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">AWS Access Key ID</label>
            <input
              type="text"
              value={accessKey}
              onChange={(e) => { setAccessKey(e.target.value.trim()); setCsvParsed(false); }}
              placeholder="AKIAIOSFODNN7EXAMPLE"
              autoComplete="off"
              className="w-full rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-500/50 transition-colors"
              style={{ background: 'rgba(14,14,18,0.8)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: "'JetBrains Mono', monospace" }}
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">AWS Secret Access Key</label>
            <div className="relative">
              <input
                type={showSecret ? 'text' : 'password'}
                value={secretKey}
                onChange={(e) => { setSecretKey(e.target.value.trim()); setCsvParsed(false); }}
                placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                autoComplete="new-password"
                className="w-full rounded-lg px-4 py-2.5 pr-10 text-sm text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-500/50 transition-colors"
                style={{ background: 'rgba(14,14,18,0.8)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: "'JetBrains Mono', monospace" }}
                required
              />
              <button
                type="button"
                onClick={() => setShowSecret(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
              >
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
            disabled={loading || (!accessKey || !secretKey)}
            className="w-full bg-violet-500 hover:bg-violet-400 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors text-sm"
          >
            {loading ? 'Connecting…' : 'Connect and go to dashboard'}
          </button>
        </form>

        <div className="flex items-start gap-2 mt-5 text-xs text-slate-600">
          <Lock size={12} className="shrink-0 mt-0.5" />
          <p>
            Your credentials are <strong className="text-slate-400">encrypted at rest</strong> using AES-256 and are <strong className="text-slate-400">automatically deleted when you sign out</strong>. Remedi only uses them to scan and fix your account — they are never shared or logged. Delete the IAM user anytime to immediately revoke all access.
          </p>
        </div>
      </div>
    </div>
  );
}
