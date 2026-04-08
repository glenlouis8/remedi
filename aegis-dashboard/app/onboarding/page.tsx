'use client';

import { useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@clerk/nextjs';
import { ShieldCheck, Eye, EyeOff, ExternalLink, AlertTriangle, Lock, Upload, CheckCircle } from 'lucide-react';

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
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col items-center justify-center px-6 py-16">

      <div className="flex items-center gap-2 mb-10">
        <ShieldCheck className="text-emerald-600" size={20} />
        <span className="font-semibold tracking-tight text-slate-900">Remedi</span>
      </div>

      <div className="w-full max-w-md">
        <h1 className="text-2xl font-bold mb-2 text-slate-900">Connect your AWS account</h1>
        <p className="text-slate-500 text-sm mb-6">
          Create a dedicated IAM user for Remedi — takes 2 minutes and you can delete it anytime to revoke access.
        </p>

        {/* Setup instructions */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 mb-6 text-sm shadow-sm">
          <p className="text-slate-700 font-medium mb-2">Quick setup</p>
          <ol className="text-slate-500 space-y-1.5 list-decimal list-inside">
            <li>
              Open{' '}
              <a href="https://console.aws.amazon.com/iam/home#/users/create" target="_blank" rel="noopener noreferrer" className="text-emerald-600 hover:underline inline-flex items-center gap-0.5">
                IAM → Users → Create user <ExternalLink size={10} />
              </a>
            </li>
            <li>Name it <code className="bg-slate-100 px-1 rounded text-xs text-slate-700">remedi-agent</code></li>
            <li>Attach the <code className="bg-slate-100 px-1 rounded text-xs text-slate-700">SecurityAudit</code> policy</li>
            <li>Go to <strong className="text-slate-700">Security credentials</strong> → Create access key</li>
            <li>Download the <strong className="text-slate-700">.csv file</strong> and upload it below</li>
          </ol>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" autoComplete="off">

          {/* Account name */}
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Account nickname</label>
            <input
              type="text"
              value={accountName}
              onChange={e => setAccountName(e.target.value)}
              placeholder="e.g. Production, Dev, Personal"
              maxLength={40}
              autoComplete="off"
              className="w-full bg-white border border-slate-200 rounded-lg px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/30 focus:border-emerald-500"
            />
            <p className="text-xs text-slate-400 mt-1">Optional — defaults to &quot;Default&quot; if left blank. Max 3 accounts.</p>
          </div>

          {/* CSV upload */}
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Upload credentials CSV</label>
            <div
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
              className={`w-full border-2 border-dashed rounded-xl px-4 py-6 flex flex-col items-center gap-2 cursor-pointer transition-colors ${
                csvParsed  ? 'border-emerald-400 bg-emerald-50' :
                dragging   ? 'border-emerald-400 bg-emerald-50' :
                             'border-slate-200 hover:border-slate-300 bg-white'
              }`}
            >
              {csvParsed ? (
                <>
                  <CheckCircle size={20} className="text-emerald-500" />
                  <p className="text-sm text-emerald-700 font-medium">Credentials loaded</p>
                  <p className="text-xs text-slate-400">{accessKey}</p>
                </>
              ) : (
                <>
                  <Upload size={20} className="text-slate-400" />
                  <p className="text-sm text-slate-500">Drop your <code className="bg-slate-100 px-1 rounded text-xs">credentials.csv</code> here</p>
                  <p className="text-xs text-slate-400">or click to browse</p>
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
            <div className="flex-1 h-px bg-slate-200" />
            <span className="text-xs text-slate-400">or enter manually</span>
            <div className="flex-1 h-px bg-slate-200" />
          </div>

          {/* Manual fields */}
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">AWS Access Key ID</label>
            <input
              type="text"
              value={accessKey}
              onChange={(e) => { setAccessKey(e.target.value.trim()); setCsvParsed(false); }}
              placeholder="AKIAIOSFODNN7EXAMPLE"
              autoComplete="off"
              className="w-full bg-white border border-slate-200 rounded-lg px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/30 focus:border-emerald-500 font-mono"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">AWS Secret Access Key</label>
            <div className="relative">
              <input
                type={showSecret ? 'text' : 'password'}
                value={secretKey}
                onChange={(e) => { setSecretKey(e.target.value.trim()); setCsvParsed(false); }}
                placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                autoComplete="new-password"
                className="w-full bg-white border border-slate-200 rounded-lg px-4 py-2.5 pr-10 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/30 focus:border-emerald-500 font-mono"
                required
              />
              <button
                type="button"
                onClick={() => setShowSecret(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
              >
                {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 border border-red-200 rounded-lg px-3 py-2.5">
              <AlertTriangle size={14} className="shrink-0" />
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || (!accessKey || !secretKey)}
            className="w-full bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors text-sm"
          >
            {loading ? 'Connecting…' : 'Connect and go to dashboard'}
          </button>
        </form>

        <div className="flex items-start gap-2 mt-5 text-xs text-slate-400">
          <Lock size={12} className="shrink-0 mt-0.5" />
          <p>
            Your credentials are encrypted before being stored. Remedi only uses them to scan and fix your account. Delete the IAM user anytime to immediately revoke access.
          </p>
        </div>
      </div>
    </div>
  );
}
