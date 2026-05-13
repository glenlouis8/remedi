'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@clerk/nextjs';
import { ShieldCheck, Lock, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080';

function ProtectedUsersInner() {
  const { getToken } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const accountName = searchParams.get('account_name') ?? 'Default';

  const [users, setUsers] = useState<string[]>([]);
  const [credentialUser, setCredentialUser] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const token = await getToken();
        const res = await fetch(`${API}/api/iam/users?account_name=${encodeURIComponent(accountName)}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error('Failed to load IAM users');
        const data = await res.json();
        setUsers(data.users ?? []);
        setCredentialUser(data.credential_user ?? null);
        // Pre-select credential user
        if (data.credential_user) setSelected(new Set([data.credential_user]));
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Could not load IAM users');
      } finally {
        setLoadingUsers(false);
      }
    })();
  }, [accountName, getToken]);

  function toggle(user: string) {
    if (user === credentialUser) return; // locked
    setSelected(prev => {
      const next = new Set(prev);
      next.has(user) ? next.delete(user) : next.add(user);
      return next;
    });
  }

  async function save(skip = false) {
    setSaving(true);
    try {
      const token = await getToken();
      if (!skip) {
        const res = await fetch(`${API}/api/accounts/protected-users`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ account_name: accountName, protected_users: [...selected] }),
        });
        if (!res.ok) throw new Error('Failed to save protected users');
      }
      router.push('/dashboard');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Something went wrong');
      setSaving(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-white flex flex-col" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');`}</style>

      <header className="shrink-0 border-b border-white/6 px-8 h-14 flex items-center">
        <Link href="/" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.25)' }}>
            <ShieldCheck size={15} className="text-violet-400" />
          </div>
          <span className="font-semibold tracking-tight text-white">Remedi</span>
        </Link>
      </header>

      <div className="flex-1 flex items-center justify-center px-8 py-16">
        <div className="w-full max-w-md space-y-6">

          <div>
            <h1 className="text-2xl font-bold text-white mb-2">Protect IAM users</h1>
            <p className="text-slate-400 text-sm leading-relaxed">
              Select IAM users Remedi should <strong className="text-slate-200">never remediate</strong>. Typically your admin accounts. You can change this later from the dashboard.
            </p>
          </div>

          <div className="rounded-xl border border-white/8 overflow-hidden" style={{ background: 'rgba(14,14,18,0.8)' }}>
            {loadingUsers ? (
              <div className="px-5 py-8 flex items-center justify-center">
                <div className="w-5 h-5 rounded-full border-2 border-violet-500/30 border-t-violet-400 animate-spin" />
              </div>
            ) : users.length === 0 ? (
              <div className="px-5 py-6 text-sm text-slate-500 text-center">No IAM users found in this account.</div>
            ) : (
              <ul className="divide-y divide-white/5">
                {users.map(user => {
                  const isCredUser = user === credentialUser;
                  const isChecked = selected.has(user);
                  return (
                    <li
                      key={user}
                      onClick={() => toggle(user)}
                      className={`flex items-center gap-3 px-5 py-3.5 transition-colors ${isCredUser ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer hover:bg-white/3'}`}
                    >
                      <div className={`w-4 h-4 rounded flex items-center justify-center shrink-0 transition-colors ${isChecked ? 'bg-violet-500' : 'border border-white/20'}`}>
                        {isChecked && (
                          <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                            <path d="M1 4L3.5 6.5L9 1" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                          </svg>
                        )}
                      </div>
                      <span className="text-sm text-slate-200 font-mono flex-1">{user}</span>
                      {isCredUser && (
                        <span className="flex items-center gap-1 text-xs text-slate-500">
                          <Lock size={11} /> credential user
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          {error && (
            <div className="flex items-center gap-2 text-red-400 text-sm rounded-lg px-3 py-2.5" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
              <AlertTriangle size={14} className="shrink-0" />
              {error}
            </div>
          )}

          <div className="flex gap-3">
            <button
              onClick={() => save(true)}
              disabled={saving}
              className="flex-1 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:text-slate-200 transition-colors disabled:opacity-40"
              style={{ border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)' }}
            >
              Skip
            </button>
            <button
              onClick={() => save(false)}
              disabled={saving || loadingUsers}
              className="flex-1 flex items-center justify-center gap-2 bg-violet-500 hover:bg-violet-400 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors text-sm"
            >
              {saving ? 'Saving…' : <><span>Save & continue</span><ArrowRight size={14} /></>}
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}

export default function ProtectedUsersPage() {
  return (
    <Suspense>
      <ProtectedUsersInner />
    </Suspense>
  );
}
