'use client';

import { useState, useRef, useEffect } from 'react';
import { useAuth, useClerk, useUser } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldCheck, ShieldAlert, Play, Square, CheckCircle, XCircle,
  AlertTriangle, ChevronRight, Users, HardDrive, Globe, Shield,
  Server, Database, Zap, FileText, Lock, ChevronDown,
  LayoutDashboard, History, LogOut, Clock, AlertOctagon,
  Activity, TrendingUp,
} from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ComplianceCheck { id: string; name: string; description: string; status: 'SAFE' | 'VULNERABLE' }
interface CisScore { score: number; total: number; percentage: number }
interface SecurityMetrics {
  avg_mttr: string;
  avg_ttd: string;
  success_rate: string;
  verification_pass_rate: string;
  total_tokens: number;
  total_scans: number;
}
interface ScanHistoryItem {
  id: string;
  start_time: string;
  findings_count: number;
  remediations_count: number;
  status: string;
  verified: boolean;
  estimated_cost?: number;
}
interface RemediationStep { funcName: string; resource: string; status: 'running' | 'success' | 'error' }

type ScanState = 'idle' | 'scanning' | 'awaiting_approval' | 'remediating' | 'complete'
interface ScanItem { resource: string; status: 'ok' | 'vulnerable'; msg: string }
type ServiceKey = 'iam' | 's3' | 'vpc' | 'sg' | 'ec2' | 'rds' | 'lambda' | 'cloudtrail'

const SERVICE_META: Record<ServiceKey, { label: string; Icon: React.ComponentType<{ size?: number; className?: string }> }> = {
  iam:        { label: 'IAM',        Icon: Users     },
  s3:         { label: 'S3',         Icon: HardDrive },
  vpc:        { label: 'VPC',        Icon: Globe     },
  sg:         { label: 'Sec Groups', Icon: Shield    },
  ec2:        { label: 'EC2',        Icon: Server    },
  rds:        { label: 'RDS',        Icon: Database  },
  lambda:     { label: 'Lambda',     Icon: Zap       },
  cloudtrail: { label: 'CloudTrail', Icon: FileText  },
}

const SERVICE_ORDER: ServiceKey[] = ['iam', 's3', 'vpc', 'sg', 'ec2', 'rds', 'lambda', 'cloudtrail']

const REMEDIATION_INFO: Record<string, { title: string; icon: string; risk: string }> = {
  restrict_iam_user:             { icon: '🔑', title: 'Revoke Admin Privileges',   risk: 'User has full AWS access'                  },
  remediate_s3:                  { icon: '🪣', title: 'Block Public S3 Access',    risk: 'Bucket readable by anyone on the internet' },
  remediate_vpc_flow_logs:       { icon: '🌐', title: 'Enable Network Logging',    risk: 'VPC has no flow logs'                      },
  revoke_security_group_ingress: { icon: '🔒', title: 'Close Open Ports',          risk: 'Ports open to 0.0.0.0/0'                  },
  enforce_imdsv2:                { icon: '💻', title: 'Enforce IMDSv2',            risk: 'EC2 vulnerable to SSRF via IMDSv1'         },
  stop_instance:                 { icon: '⛔', title: 'Quarantine EC2 Instance',   risk: 'Compromised instance posing active threat' },
  remediate_rds_public_access:   { icon: '🗄️', title: 'Make RDS Private',         risk: 'Database reachable from the internet'      },
  remediate_lambda_role:         { icon: '⚡', title: 'Fix Lambda Permissions',    risk: 'Lambda has admin-level AWS access'         },
  remediate_cloudtrail:          { icon: '📋', title: 'Enable CloudTrail Logging', risk: 'No audit log of API activity'              },
};

const parseRemediationItem = (line: string) => {
  const actionMatch = line.match(/ACTION: I will call `?(\w+)`?/);
  if (!actionMatch) return null;
  const toolName = actionMatch[1];
  const patterns = [/\[CRITICAL\] (.*?) (?:is vulnerable|has |allows)/, /\[POLICY VIOLATION\] User `?(.*?)`? /, /\[HIGH\] (.*?) (?:has |is )/];
  let resource = '';
  for (const p of patterns) { const m = line.match(p); if (m) { resource = m[1].trim(); break; } }
  return { toolName, resource: resource || toolName };
};

// ─── CIS Score Gauge ──────────────────────────────────────────────────────────

function ScoreGauge({ score, total, percentage }: { score: number; total: number; percentage: number }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const arcLen = circ * 0.75;
  const filled = (percentage / 100) * arcLen;
  const color = percentage >= 80 ? '#10b981' : percentage >= 50 ? '#f59e0b' : '#ef4444';
  const label = percentage >= 80 ? 'Compliant' : percentage >= 50 ? 'Needs attention' : 'At risk';

  return (
    <div className="flex flex-col items-center justify-center">
      <svg viewBox="0 0 100 100" className="w-32 h-32">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#1a2540" strokeWidth="10"
          strokeDasharray={`${arcLen} ${circ}`} strokeLinecap="round"
          transform="rotate(135 50 50)" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${filled} ${circ}`} strokeLinecap="round"
          transform="rotate(135 50 50)"
          style={{ transition: 'stroke-dasharray 0.8s ease' }} />
        <text x="50" y="47" textAnchor="middle" fontSize="22" fontWeight="700" fill="#e2e8f0">{score}</text>
        <text x="50" y="61" textAnchor="middle" fontSize="11" fill="#475569">/ {total}</text>
      </svg>
      <span className="text-xs font-semibold -mt-2" style={{ color }}>{label}</span>
      <p className="text-xs text-slate-500 mt-1">CIS Score</p>
    </div>
  );
}

// ─── Service Card ─────────────────────────────────────────────────────────────

function ServiceCard({ svc, items, isActive, scanState }: {
  svc: ServiceKey; items: ScanItem[]; isActive: boolean; scanState: ScanState;
}) {
  const { label, Icon } = SERVICE_META[svc];
  const hasData   = items.length > 0;
  const vulnCount = items.filter(i => i.status === 'vulnerable').length;
  const isPending = !hasData && !isActive && scanState === 'scanning';

  let cardClass = 'bg-[#0f1621] border-[#1a2540]';
  if (isActive)                  cardClass = 'bg-emerald-950/30 border-emerald-700/50 shadow-sm shadow-emerald-900/20';
  else if (hasData && vulnCount) cardClass = 'bg-red-950/30 border-red-700/40';
  else if (hasData)              cardClass = 'bg-emerald-950/20 border-emerald-800/40';
  else if (isPending)            cardClass = 'bg-[#0f1621]/60 border-[#1a2540]/50 opacity-40';

  return (
    <div className={`rounded-xl border p-4 transition-all duration-500 ${cardClass}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <Icon size={14} className={
            isActive ? 'text-emerald-400' : hasData && vulnCount ? 'text-red-400' : hasData ? 'text-emerald-400' : 'text-slate-700'
          } />
          <span className={`text-sm font-medium ${isActive || hasData ? 'text-slate-200' : 'text-slate-700'}`}>{label}</span>
        </div>
        {isActive && <span className="flex items-center gap-1 text-xs text-emerald-400"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />scanning</span>}
        {!isActive && hasData && vulnCount > 0 && <span className="text-xs text-red-400 font-medium">{vulnCount} issue{vulnCount !== 1 ? 's' : ''}</span>}
        {!isActive && hasData && vulnCount === 0 && <CheckCircle size={13} className="text-emerald-400" />}
      </div>
      {hasData ? (
        <div className="space-y-1.5 mt-2">
          {items.map((item, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className={`shrink-0 text-xs ${item.status === 'vulnerable' ? 'text-red-400' : 'text-emerald-400'}`}>
                {item.status === 'vulnerable' ? '⚠' : '✓'}
              </span>
              <span className="text-xs text-slate-500 font-mono truncate">{item.resource}</span>
            </div>
          ))}
        </div>
      ) : isActive ? (
        <div className="space-y-1.5 mt-2">
          {[1, 2].map(i => <div key={i} className="h-3 bg-emerald-900/40 rounded animate-pulse" style={{ width: `${50 + i * 20}%` }} />)}
        </div>
      ) : (
        <p className="text-xs text-slate-700 mt-1">—</p>
      )}
    </div>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { getToken } = useAuth();
  const { signOut } = useClerk();
  const { user } = useUser();
  const router = useRouter();

  const [cisScore, setCisScore]       = useState<CisScore | null>(null);
  const [checks, setChecks]           = useState<ComplianceCheck[]>([]);
  const [metrics, setMetrics]         = useState<SecurityMetrics | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);

  const [scanState, setScanState]               = useState<ScanState>('idle');
  const [scanItems, setScanItems]               = useState<Partial<Record<ServiceKey, ScanItem[]>>>({});
  const [activeService, setActiveService]       = useState<ServiceKey | null>(null);
  const [remediationPlan, setRemediationPlan]   = useState<{ toolName: string; resource: string }[]>([]);
  const [remediationSteps, setRemediationSteps] = useState<RemediationStep[]>([]);
  const [showSuccess, setShowSuccess]           = useState(false);

  const [accounts, setAccounts]             = useState<{account_name: string}[]>([]);
  const [selectedAccount, setSelectedAccount] = useState<string>('Default');
  const [iamUsers, setIamUsers]             = useState<string[]>([]);
  const [credentialUser, setCredentialUser] = useState<string | null>(null);
  const [protectedUsers, setProtectedUsers] = useState<string[]>([]);
  const [view, setView]                     = useState<'overview' | 'compliance' | 'history'>('overview');
  const [dropdownOpen, setDropdownOpen]     = useState(false);
  const dropdownRef                         = useRef<HTMLDivElement>(null);
  const abortRef                            = useRef<AbortController | null>(null);

  // Redirect to onboarding if no AWS credentials are connected
  useEffect(() => {
    const checkAccount = async () => {
      try {
        const token = await getToken();
        const res = await fetch(`${API}/api/accounts/status`, { headers: { Authorization: `Bearer ${token}` } });
        if (res.ok) {
          const data = await res.json();
          if (!data.connected) router.replace('/onboarding');
        }
      } catch { /* ignore — backend may not be ready yet */ }
    };
    checkAccount();
  }, [getToken, router]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) setDropdownOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  useEffect(() => {
    const h = async () => ({ Authorization: `Bearer ${await getToken()}` });

    const fetchIamUsers = async (acct: string) => {
      try {
        const res = await fetch(`${API}/api/iam/users?account_name=${encodeURIComponent(acct)}`, { headers: await h() });
        if (res.ok) {
          const data = await res.json();
          setIamUsers(data.users ?? []);
          setCredentialUser(data.credential_user ?? null);
        }
      } catch { /* ignore */ }
    };

    const fetchAccounts = async () => {
      try {
        const res = await fetch(`${API}/api/accounts`, { headers: await h() });
        if (res.ok) {
          const data: {account_name: string}[] = await res.json();
          setAccounts(data);
          // Auto-select the first account if nothing selected yet
          setSelectedAccount(prev => {
            const names = data.map(a => a.account_name);
            return names.includes(prev) ? prev : (names[0] ?? 'Default');
          });
        }
      } catch { /* ignore */ }
    };

    fetchAccounts().then(() => {
      setSelectedAccount(prev => { fetchIamUsers(prev); return prev; });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps

    const poll = async () => {
      try {
        const [s, c, m, hist] = await Promise.all([
          fetch(`${API}/api/status`,          { headers: await h() }).then(r => r.json()),
          fetch(`${API}/api/compliance`,      { headers: await h() }).then(r => r.json()),
          fetch(`${API}/api/metrics`,         { headers: await h() }).then(r => r.json()),
          fetch(`${API}/api/metrics/history`, { headers: await h() }).then(r => r.json()),
        ]);
        if (Array.isArray(s)) setChecks(s);
        if (c?.score !== undefined) setCisScore(c);
        if (m?.total_scans !== undefined) setMetrics(m);
        if (Array.isArray(hist)) setScanHistory(hist);
      } catch { /* ignore */ }
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => clearInterval(id);
  }, [getToken]);

  const startScan = async () => {
    setScanState('scanning');
    setScanItems({});
    setActiveService(null);
    setRemediationPlan([]);
    setRemediationSteps([]);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const token = await getToken();
      const res = await fetch(`${API}/api/run-agent`, {
        method: 'POST',
        signal: controller.signal,
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ account_name: selectedAccount, protected_users: protectedUsers }),
      });

      if (!res.ok || !res.body) { setScanState('idle'); return; }

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const lines = decoder.decode(value).split('\n').filter(Boolean);

        for (const raw of lines) {
          if (raw.startsWith('[SCAN] ')) {
            try {
              const event = JSON.parse(raw.slice(7));
              const svc = event.service as ServiceKey;
              if (SERVICE_META[svc]) {
                setActiveService(svc);
                setScanItems(prev => ({
                  ...prev,
                  [svc]: [...(prev[svc] ?? []), { resource: event.resource, status: event.status, msg: event.msg ?? '' }],
                }));
              }
            } catch { /* malformed */ }
            continue;
          }

          if (raw.includes('[ACTION_REQUIRED] WAITING_FOR_APPROVAL')) {
            setActiveService(null);
            setScanState('awaiting_approval');
          }

          if (raw.includes('[CRITICAL]') || raw.includes('[POLICY VIOLATION]')) {
            const item = parseRemediationItem(raw);
            if (item) setRemediationPlan(prev => {
              const exists = prev.some(p => p.resource === item.resource && p.toolName === item.toolName);
              return exists ? prev : [...prev, item];
            });
          }

          const execMatch = raw.match(/\[EXEC\] Calling (\w+) with \{(.+)\}/);
          if (execMatch) {
            const funcName      = execMatch[1];
            const resourceMatch = execMatch[2].match(/['"]([\w\-\.]+)['"]/);
            setScanState('remediating');
            setRemediationSteps(prev => [...prev, { funcName, resource: resourceMatch?.[1] || funcName, status: 'running' }]);
          }

          if (raw.includes('✅') && raw.includes('SUCCESS') && !raw.includes('[EXEC]')) {
            setRemediationSteps(prev => {
              const updated = [...prev];
              const idx = updated.findLastIndex(s => s.status === 'running');
              if (idx >= 0) updated[idx] = { ...updated[idx], status: 'success' };
              return updated;
            });
          }

          if (raw.includes('❌')) {
            setRemediationSteps(prev => {
              const updated = [...prev];
              const idx = updated.findLastIndex(s => s.status === 'running');
              if (idx >= 0) updated[idx] = { ...updated[idx], status: 'error' };
              return updated;
            });
          }
        }
      }
    } catch (err: unknown) {
      if ((err as Error).name === 'AbortError') return;
    } finally {
      setActiveService(null);
      setScanState('complete');
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 4500);
    }
  };

  const handleDeleteAccount = async (name: string) => {
    const token = await getToken();
    await fetch(`${API}/api/accounts/${encodeURIComponent(name)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    setAccounts(prev => {
      const updated = prev.filter(a => a.account_name !== name);
      if (selectedAccount === name) {
        setSelectedAccount(updated[0]?.account_name ?? 'Default');
      }
      return updated;
    });
    if (accounts.length <= 1) router.replace('/onboarding');
  };

  const handleApprove = async () => {
    setScanState('remediating');
    const token = await getToken();
    await fetch(`${API}/api/approve`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
  };

  const handleStop = async () => {
    abortRef.current?.abort();
    const token = await getToken();
    await fetch(`${API}/api/stop`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
    setScanState('idle');
  };

  const isScanning = scanState === 'scanning' || scanState === 'awaiting_approval' || scanState === 'complete';
  const lastScan   = scanHistory[0];
  const openVulns  = lastScan
    ? String(Math.max(0, (lastScan.findings_count ?? 0) - (lastScan.remediations_count ?? 0)))
    : '—';
  const userInitial = (user?.firstName?.[0] ?? user?.emailAddresses?.[0]?.emailAddress?.[0] ?? 'U').toUpperCase();

  const fixedCount   = remediationSteps.filter(s => s.status === 'success').length;
  const successLabel = fixedCount === 0 ? 'No vulnerabilities found' : 'All threats neutralized';

  return (
    <div className="flex h-screen bg-[#080d18] overflow-hidden">

      {/* ── Success overlay ──────────────────────────────────────────────────── */}
      {showSuccess && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#080d18]/75 backdrop-blur-sm"
          onClick={() => setShowSuccess(false)}
        >
          <div
            className="success-card relative bg-[#0f1621] border border-emerald-500/25 rounded-2xl p-10 shadow-2xl shadow-emerald-900/30 text-center w-80"
            onClick={e => e.stopPropagation()}
          >
            {/* Pulsing rings */}
            <div className="relative flex items-center justify-center mb-7">
              <div className="ring-out absolute w-20 h-20 rounded-full border border-emerald-400/30" />
              <div className="ring-out absolute w-20 h-20 rounded-full border border-emerald-400/20" style={{ animationDelay: '0.7s' }} />

              {/* Shield + checkmark */}
              <svg viewBox="0 0 80 80" className="w-20 h-20 relative z-10">
                <path
                  d="M40 8 L66 19 L66 43 C66 57 54 67 40 72 C26 67 14 57 14 43 L14 19 Z"
                  fill="rgba(16,185,129,0.07)" stroke="#10b981" strokeWidth="2" strokeLinejoin="round"
                />
                <polyline
                  points="27,40 36,50 53,30"
                  fill="none" stroke="#10b981" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"
                  style={{ strokeDasharray: 60, strokeDashoffset: 60, animation: 'draw-check 0.55s ease-out 0.25s forwards' }}
                />
              </svg>
            </div>

            {/* Headline */}
            <h2 className="fade-slide-up text-lg font-bold text-slate-100 mb-1" style={{ animationDelay: '0.45s' }}>
              System Secured
            </h2>
            <p className="fade-slide-up text-sm text-slate-400 mb-7" style={{ animationDelay: '0.55s' }}>
              {successLabel}
            </p>

            {/* Stats */}
            <div className="fade-slide-up flex gap-3 justify-center mb-7" style={{ animationDelay: '0.65s' }}>
              <div className="flex-1 bg-[#080d18] rounded-xl px-4 py-3 border border-[#1a2540]">
                <div className="text-xl font-bold text-emerald-400">{fixedCount}</div>
                <div className="text-xs text-slate-500 mt-0.5">Fixed</div>
              </div>
              <div className="flex-1 bg-[#080d18] rounded-xl px-4 py-3 border border-[#1a2540]">
                <div className="text-xl font-bold text-emerald-400">✓</div>
                <div className="text-xs text-slate-500 mt-0.5">Verified</div>
              </div>
            </div>

            <button
              onClick={() => setShowSuccess(false)}
              className="fade-slide-up text-xs text-slate-600 hover:text-slate-300 transition-colors"
              style={{ animationDelay: '0.75s' }}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* ── Sidebar ─────────────────────────────────────────────────────────── */}
      <aside className="w-56 bg-[#0b1120] border-r border-[#1a2540] flex flex-col shrink-0">
        <div className="px-5 py-5 border-b border-[#1a2540]">
          <Link href="/" className="flex items-center gap-2">
            <ShieldCheck className="text-emerald-400" size={18} />
            <span className="font-semibold tracking-tight text-slate-100">Remedi</span>
          </Link>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-0.5">
          {([
            { key: 'overview',    label: 'Overview',    Icon: LayoutDashboard },
            { key: 'compliance',  label: 'Compliance',  Icon: Shield          },
            { key: 'history',     label: 'History',     Icon: History         },
          ] as const).map(({ key, label, Icon }) => (
            <button key={key} onClick={() => setView(key)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors text-left ${
                view === key
                  ? 'bg-emerald-500/10 text-emerald-400 font-medium'
                  : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
              }`}>
              <Icon size={15} />
              {label}
            </button>
          ))}
        </nav>

        <div className="px-4 py-4 border-t border-[#1a2540]">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center shrink-0">
              <span className="text-xs font-semibold text-emerald-400">{userInitial}</span>
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-slate-200 truncate">{user?.firstName ?? 'User'}</p>
              <p className="text-xs text-slate-600 truncate">{user?.emailAddresses?.[0]?.emailAddress ?? ''}</p>
            </div>
          </div>
          <button
            onClick={async () => {
              const token = await getToken();
              await fetch(`${API}/api/accounts`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }).catch(console.error);
              signOut({ redirectUrl: '/' });
            }}
            className="flex items-center gap-2 text-xs text-slate-600 hover:text-slate-300 transition-colors"
          >
            <LogOut size={13} /> Sign out
          </button>
        </div>
      </aside>

      {/* ── Main ────────────────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-5xl mx-auto px-6 py-7 space-y-6">

          {/* Page header */}
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-xl font-bold text-slate-100">
                {view === 'overview' ? 'Security Dashboard' : view === 'compliance' ? 'Compliance' : 'Scan History'}
              </h1>
              <p className="text-sm text-slate-500 mt-0.5">
                {credentialUser
                  ? <>Connected as <span className="font-mono text-slate-400">{credentialUser}</span></>
                  : 'No AWS account connected'}
              </p>
            </div>
            {view === 'overview' && (
              <div className="flex items-center gap-3">
                {(scanState === 'scanning' || scanState === 'remediating') ? (
                  <button onClick={handleStop}
                    className="flex items-center gap-2 text-sm text-red-400 border border-red-800/60 bg-red-950/30 px-4 py-2 rounded-lg hover:bg-red-950/50 transition-colors">
                    <Square size={12} className="fill-current" /> Stop
                  </button>
                ) : (
                  <button onClick={startScan} disabled={scanState === 'awaiting_approval'}
                    className="flex items-center gap-2 text-sm bg-emerald-500 hover:bg-emerald-400 disabled:opacity-40 text-white font-semibold px-5 py-2 rounded-lg transition-colors shadow-lg shadow-emerald-900/30">
                    <Play size={12} className="fill-current" />
                    {scanState === 'complete' ? 'Scan again' : 'Run scan'}
                  </button>
                )}
              </div>
            )}
          </div>

          {/* ── Account selector ─────────────────────────────────────────────── */}
          {accounts.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap">
              {accounts.map(a => (
                <div key={a.account_name} className={`flex items-center gap-1.5 rounded-lg border text-xs font-medium transition-colors ${
                  selectedAccount === a.account_name
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-[#0f1621] border-[#1a2540] text-slate-400 hover:text-slate-200'
                }`}>
                  <button
                    onClick={() => {
                      setSelectedAccount(a.account_name);
                      getToken().then(token => {
                        fetch(`${API}/api/iam/users?account_name=${encodeURIComponent(a.account_name)}`, {
                          headers: { Authorization: `Bearer ${token}` },
                        }).then(r => r.ok ? r.json() : null).then(data => {
                          if (data) { setIamUsers(data.users ?? []); setCredentialUser(data.credential_user ?? null); }
                        }).catch(() => {});
                      });
                    }}
                    disabled={scanState === 'scanning' || scanState === 'remediating'}
                    className="px-3 py-1.5 disabled:opacity-40"
                  >
                    {a.account_name}
                  </button>
                  <button
                    onClick={() => handleDeleteAccount(a.account_name)}
                    disabled={scanState === 'scanning' || scanState === 'remediating'}
                    className="pr-2 text-slate-600 hover:text-red-400 transition-colors disabled:opacity-40"
                    title={`Remove ${a.account_name}`}
                  >
                    ×
                  </button>
                </div>
              ))}
              {accounts.length < 3 && (
                <Link
                  href="/onboarding"
                  className="flex items-center gap-1 text-xs text-slate-600 hover:text-emerald-400 border border-dashed border-[#1a2540] hover:border-emerald-500/30 rounded-lg px-3 py-1.5 transition-colors"
                >
                  + Add account
                  <span className="text-slate-700 ml-1">{accounts.length}/3</span>
                </Link>
              )}
            </div>
          )}

          {/* ── Overview ──────────────────────────────────────────────────────── */}
          {view === 'overview' && (<>

            {/* Stats + gauge */}
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-[#0f1621] border border-[#1a2540] rounded-xl p-5 shadow-sm flex items-center justify-center">
                {cisScore
                  ? <ScoreGauge score={cisScore.score} total={cisScore.total} percentage={cisScore.percentage} />
                  : <div className="w-32 h-32 rounded-full border-8 border-[#1a2540] flex items-center justify-center">
                      <span className="text-slate-700 text-xs">Loading…</span>
                    </div>
                }
              </div>
              <div className="col-span-2 grid grid-cols-2 gap-4">
                {[
                  { label: 'Total scans',  value: metrics?.total_scans  ?? '—', sub: 'all time',          Icon: Activity,     color: 'text-slate-100'   },
                  { label: 'Success rate', value: metrics?.success_rate ?? '—', sub: 'fixes applied',     Icon: TrendingUp,   color: 'text-emerald-400' },
                  { label: 'Avg fix time', value: metrics?.avg_mttr     ?? '—', sub: 'after approval',    Icon: Clock,        color: 'text-slate-100'   },
                  { label: 'Open vulns',   value: openVulns,                    sub: 'unresolved issues', Icon: AlertOctagon, color: openVulns === '0' ? 'text-emerald-400' : 'text-red-400' },
                ].map(({ label, value, sub, Icon, color }) => (
                  <div key={label} className="bg-[#0f1621] border border-[#1a2540] rounded-xl p-5 shadow-sm">
                    <div className="flex items-center justify-between mb-3">
                      <p className="text-xs text-slate-500 font-medium">{label}</p>
                      <Icon size={14} className="text-slate-700" />
                    </div>
                    <p className={`text-2xl font-bold ${color}`}>{value}</p>
                    <p className="text-xs text-slate-600 mt-1">{sub}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Last scan banner */}
            {lastScan && (
              <div className={`rounded-xl border p-4 flex items-center justify-between ${
                lastScan.verified               ? 'bg-emerald-950/30 border-emerald-700/40' :
                lastScan.status === 'COMPLETED' ? 'bg-blue-950/30 border-blue-700/40'       :
                'bg-[#0f1621] border-[#1a2540]'
              }`}>
                <div className="flex items-center gap-3">
                  {lastScan.verified
                    ? <CheckCircle size={16} className="text-emerald-400" />
                    : <Activity    size={16} className="text-blue-400" />}
                  <div>
                    <p className="text-sm font-medium text-slate-200">
                      Last scan: <span className="font-mono text-slate-400">{lastScan.id}</span>
                    </p>
                    <p className="text-xs text-slate-500 mt-0.5">
                      {new Date(lastScan.start_time).toLocaleString()}
                      {' · '}{lastScan.findings_count ?? 0} findings
                      {' · '}{lastScan.remediations_count ?? 0} fixed
                      {lastScan.estimated_cost ? ` · $${lastScan.estimated_cost.toFixed(4)}` : ''}
                    </p>
                  </div>
                </div>
                <span className={`text-xs px-2.5 py-1 rounded-full font-medium border ${
                  lastScan.verified               ? 'bg-emerald-500/15 text-emerald-400 border-emerald-700/40' :
                  lastScan.status === 'COMPLETED' ? 'bg-blue-500/15 text-blue-400 border-blue-700/40'         :
                  'bg-slate-800 text-slate-400 border-slate-700'
                }`}>
                  {lastScan.verified ? '✓ Verified' : lastScan.status}
                </span>
              </div>
            )}

            {/* Protected users */}
            {(scanState === 'idle' || scanState === 'complete') && iamUsers.length > 0 && (
              <div className="bg-[#0f1621] border border-[#1a2540] rounded-xl p-5 shadow-sm">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold text-slate-200 mb-0.5">Protected IAM users</p>
                    <p className="text-xs text-slate-500">
                      These users will be audited but never modified.
                      {credentialUser && <> <span className="font-mono text-slate-400">{credentialUser}</span> is always protected.</>}
                    </p>
                  </div>
                  <div className="relative shrink-0" ref={dropdownRef}>
                    <button onClick={() => setDropdownOpen(v => !v)}
                      className="flex items-center gap-2 text-sm border border-[#1a2540] bg-[#080d18] hover:bg-[#0b1120] rounded-lg px-3 py-2 transition-colors min-w-[160px] justify-between">
                      <span className="text-slate-300">
                        {protectedUsers.length === 0 ? 'Select users…' : `${protectedUsers.length} protected`}
                      </span>
                      <ChevronDown size={14} className={`text-slate-500 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
                    </button>
                    {dropdownOpen && (
                      <div className="absolute right-0 top-full mt-1 w-64 bg-[#0f1621] border border-[#1a2540] rounded-xl shadow-2xl shadow-black/50 z-10 overflow-hidden">
                        {credentialUser && (
                          <div className="flex items-center gap-3 px-4 py-2.5 bg-[#080d18] border-b border-[#1a2540]">
                            <Lock size={12} className="text-slate-600 shrink-0" />
                            <span className="text-sm font-mono text-slate-500 flex-1 truncate">{credentialUser}</span>
                            <span className="text-xs text-slate-600">auto</span>
                          </div>
                        )}
                        <div className="max-h-52 overflow-y-auto">
                          {iamUsers.filter(u => u !== credentialUser).map(u => {
                            const checked = protectedUsers.includes(u);
                            return (
                              <label key={u} className="flex items-center gap-3 px-4 py-2.5 hover:bg-[#0b1120] cursor-pointer transition-colors">
                                <input type="checkbox" checked={checked}
                                  onChange={() => setProtectedUsers(prev => checked ? prev.filter(x => x !== u) : [...prev, u])}
                                  className="accent-emerald-500" />
                                <span className="text-sm font-mono text-slate-300 truncate">{u}</span>
                              </label>
                            );
                          })}
                          {iamUsers.filter(u => u !== credentialUser).length === 0 && (
                            <p className="text-xs text-slate-600 px-4 py-3">No other IAM users found.</p>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Idle CTA */}
            {scanState === 'idle' && (
              <div className="bg-[#0f1621] border border-[#1a2540] rounded-xl p-10 flex flex-col items-center text-center shadow-sm">
                <div className="w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mb-4">
                  <ShieldCheck className="text-emerald-400" size={28} />
                </div>
                <h2 className="text-lg font-semibold text-slate-100 mb-2">Ready to scan</h2>
                <p className="text-slate-500 text-sm mb-6 max-w-sm">
                  Remedi audits your AWS account across 8 services in parallel — then shows you exactly what to fix.
                </p>
                <button onClick={startScan}
                  className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 text-white font-semibold px-6 py-2.5 rounded-lg transition-colors text-sm shadow-lg shadow-emerald-900/30">
                  <Play size={13} className="fill-current" /> Start scan
                </button>
              </div>
            )}

            {/* Service cards */}
            {isScanning && (
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-xs font-semibold text-slate-600 uppercase tracking-widest">
                    {scanState === 'complete' ? 'Scan results' : 'Live scan'}
                  </h2>
                  {scanState === 'scanning' && (
                    <span className="flex items-center gap-2 text-xs text-emerald-400 font-medium">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Scanning…
                    </span>
                  )}
                  {scanState === 'complete' && (
                    <button onClick={startScan} className="text-xs text-slate-600 hover:text-slate-300 flex items-center gap-1 transition-colors">
                      Scan again <ChevronRight size={12} />
                    </button>
                  )}
                </div>
                {scanState === 'scanning' && (
                  <div className="w-full h-0.5 rounded-full bg-emerald-950 overflow-hidden mb-4">
                    <div className="h-full shimmer-bar rounded-full" />
                  </div>
                )}
                <div className="relative rounded-2xl overflow-hidden">
                  {scanState === 'scanning' && (
                    <div className="scan-beam pointer-events-none absolute inset-x-0 z-10"
                      style={{
                        height: '2px',
                        background: 'linear-gradient(90deg, transparent 0%, #6ee7b7 20%, #10b981 50%, #6ee7b7 80%, transparent 100%)',
                        boxShadow: '0 0 12px 4px rgba(16, 185, 129, 0.35), 0 0 40px 8px rgba(16, 185, 129, 0.12)',
                      }} />
                  )}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-0.5">
                    {SERVICE_ORDER.map(svc => (
                      <ServiceCard key={svc} svc={svc} items={scanItems[svc] ?? []} isActive={activeService === svc} scanState={scanState} />
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Approval gate */}
            {scanState === 'awaiting_approval' && (
              <div className="bg-[#0f1621] border border-amber-700/40 rounded-xl overflow-hidden shadow-sm">
                <div className="flex items-center justify-between px-6 py-4 border-b border-amber-800/30 bg-amber-950/20">
                  <div className="flex items-center gap-3">
                    <AlertTriangle className="text-amber-400" size={18} />
                    <div>
                      <h2 className="font-semibold text-sm text-amber-300">Approval required</h2>
                      <p className="text-xs text-amber-500/80">{remediationPlan.length} issue{remediationPlan.length !== 1 ? 's' : ''} found — review and approve fixes</p>
                    </div>
                  </div>
                  <button onClick={handleApprove}
                    className="bg-amber-500 hover:bg-amber-400 text-black font-semibold text-sm px-5 py-2 rounded-lg transition-colors">
                    Approve all fixes
                  </button>
                </div>
                <div className="divide-y divide-[#1a2540]">
                  {remediationPlan.map((item, i) => {
                    const info = REMEDIATION_INFO[item.toolName];
                    return (
                      <div key={i} className="flex items-center gap-4 px-6 py-3">
                        <span className="text-xl">{info?.icon ?? '🔧'}</span>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-slate-200">{info?.title ?? item.toolName}</p>
                          <p className="text-xs text-slate-500">{info?.risk}</p>
                        </div>
                        <span className="text-xs font-mono text-red-400 bg-red-950/40 border border-red-800/40 px-2 py-0.5 rounded shrink-0">{item.resource}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Remediating */}
            {scanState === 'remediating' && (
              <div className="bg-[#0f1621] border border-[#1a2540] rounded-xl p-6 shadow-sm">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="font-semibold text-sm text-slate-200">Applying fixes…</h2>
                  <span className="text-xs text-slate-500">
                    {remediationSteps.filter(s => s.status === 'success').length}/{remediationSteps.length} done
                  </span>
                </div>
                <div className="space-y-2">
                  {remediationSteps.map((step, i) => {
                    const info = REMEDIATION_INFO[step.funcName];
                    return (
                      <div key={i} className={`flex items-center gap-3 px-4 py-3 rounded-lg border text-sm transition-all ${
                        step.status === 'success' ? 'border-emerald-700/40 bg-emerald-950/20' :
                        step.status === 'error'   ? 'border-red-700/40 bg-red-950/20'         :
                                                    'border-amber-700/40 bg-amber-950/20'
                      }`}>
                        <span className="text-base">{info?.icon ?? '🔧'}</span>
                        <span className="flex-1 text-slate-300">{info?.title ?? step.funcName}</span>
                        <span className="text-xs font-mono text-slate-500">{step.resource}</span>
                        {step.status === 'success' && <CheckCircle size={14} className="text-emerald-400 shrink-0" />}
                        {step.status === 'error'   && <XCircle    size={14} className="text-red-400 shrink-0" />}
                        {step.status === 'running' && <span className="w-3 h-3 rounded-full border-2 border-amber-400 border-t-transparent animate-spin shrink-0" />}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

          </>)}

          {/* ── Compliance ────────────────────────────────────────────────────── */}
          {view === 'compliance' && (<>

            {/* Score banner */}
            <div className="bg-[#0f1621] border border-[#1a2540] rounded-xl p-6 flex items-center gap-8 shadow-sm">
              {cisScore
                ? <ScoreGauge score={cisScore.score} total={cisScore.total} percentage={cisScore.percentage} />
                : <div className="w-32 h-32 rounded-full border-8 border-[#1a2540] flex items-center justify-center">
                    <span className="text-slate-700 text-xs">Loading…</span>
                  </div>
              }
              <div>
                <h2 className="text-base font-semibold text-slate-100 mb-1">CIS AWS Foundations Benchmark</h2>
                <p className="text-sm text-slate-500 mb-3">
                  {cisScore
                    ? `${cisScore.score} of ${cisScore.total} controls are currently passing.`
                    : 'Run a scan to evaluate your compliance posture.'}
                </p>
                {cisScore && (
                  <div className="flex gap-4 text-xs">
                    <span className="flex items-center gap-1.5 text-emerald-400">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />{cisScore.score} passing
                    </span>
                    <span className="flex items-center gap-1.5 text-red-400">
                      <span className="w-2 h-2 rounded-full bg-red-400" />{cisScore.total - cisScore.score} failing
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Controls grid */}
            <div>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xs font-semibold text-slate-600 uppercase tracking-widest">Controls</h2>
                {cisScore && <span className="text-xs text-slate-500">{cisScore.score}/{cisScore.total} passing</span>}
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {checks.map(check => (
                  <div key={check.id} className={`rounded-xl border p-4 shadow-sm ${
                    check.status === 'VULNERABLE'
                      ? 'bg-red-950/20 border-red-800/40'
                      : 'bg-[#0f1621] border-[#1a2540]'
                  }`}>
                    <div className="flex items-center justify-between mb-3">
                      <ShieldAlert size={14} className={check.status === 'VULNERABLE' ? 'text-red-400' : 'text-emerald-400'} />
                      <span className={`text-xs font-medium ${check.status === 'VULNERABLE' ? 'text-red-400' : 'text-emerald-400'}`}>
                        {check.status === 'VULNERABLE' ? 'Vulnerable' : 'Secure'}
                      </span>
                    </div>
                    <p className="text-sm font-medium text-slate-200 leading-tight mb-1">{check.name}</p>
                    <p className="text-xs text-slate-500 leading-tight line-clamp-2">{check.description}</p>
                  </div>
                ))}
                {checks.length === 0 && [1,2,3,4,5,6,7,8].map(i => (
                  <div key={i} className="h-24 bg-[#0f1621] border border-[#1a2540] rounded-xl animate-pulse" />
                ))}
              </div>
            </div>

          </>)}

          {/* ── History ───────────────────────────────────────────────────────── */}
          {view === 'history' && (<>

            {/* Summary stats */}
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: 'Total scans',  value: metrics?.total_scans  ?? '—', sub: 'all time',      Icon: Activity,   color: 'text-slate-100'   },
                { label: 'Success rate', value: metrics?.success_rate ?? '—', sub: 'fixes applied', Icon: TrendingUp, color: 'text-emerald-400' },
                { label: 'Avg fix time', value: metrics?.avg_mttr     ?? '—', sub: 'per scan',      Icon: Clock,      color: 'text-slate-100'   },
              ].map(({ label, value, sub, Icon, color }) => (
                <div key={label} className="bg-[#0f1621] border border-[#1a2540] rounded-xl p-5 shadow-sm">
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-xs text-slate-500 font-medium">{label}</p>
                    <Icon size={14} className="text-slate-700" />
                  </div>
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-xs text-slate-600 mt-1">{sub}</p>
                </div>
              ))}
            </div>

            {/* History table */}
            {scanHistory.length > 0 ? (
              <div className="bg-[#0f1621] border border-[#1a2540] rounded-xl overflow-hidden shadow-sm">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1a2540] bg-[#080d18]">
                      <th className="text-left px-5 py-3 text-xs font-medium text-slate-600">Scan ID</th>
                      <th className="text-left px-5 py-3 text-xs font-medium text-slate-600">Time</th>
                      <th className="text-right px-5 py-3 text-xs font-medium text-slate-600">Findings</th>
                      <th className="text-right px-5 py-3 text-xs font-medium text-slate-600">Fixed</th>
                      <th className="text-right px-5 py-3 text-xs font-medium text-slate-600">Cost</th>
                      <th className="text-right px-5 py-3 text-xs font-medium text-slate-600">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1a2540]">
                    {scanHistory.map(scan => (
                      <tr key={scan.id} className="hover:bg-[#0b1120] transition-colors">
                        <td className="px-5 py-3 font-mono text-xs text-slate-400">{scan.id}</td>
                        <td className="px-5 py-3 text-xs text-slate-500">{new Date(scan.start_time).toLocaleString()}</td>
                        <td className="px-5 py-3 text-right text-xs text-slate-400">{scan.findings_count ?? 0}</td>
                        <td className="px-5 py-3 text-right text-xs text-emerald-400 font-medium">
                          {Math.min(scan.remediations_count ?? 0, scan.findings_count ?? 0)}
                        </td>
                        <td className="px-5 py-3 text-right text-xs text-slate-500 font-mono">
                          {scan.estimated_cost != null ? `$${scan.estimated_cost.toFixed(4)}` : '—'}
                        </td>
                        <td className="px-5 py-3 text-right">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${
                            scan.verified               ? 'bg-emerald-500/10 text-emerald-400 border-emerald-700/40' :
                            scan.status === 'COMPLETED' ? 'bg-blue-500/10 text-blue-400 border-blue-700/40'         :
                            scan.status === 'ABORTED'   ? 'bg-slate-800 text-slate-400 border-slate-700'            :
                            'bg-red-500/10 text-red-400 border-red-700/40'
                          }`}>
                            {scan.verified ? '✓ Verified' : scan.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="bg-[#0f1621] border border-[#1a2540] rounded-xl p-10 flex flex-col items-center text-center">
                <History size={28} className="text-slate-700 mb-3" />
                <p className="text-sm text-slate-500">No scans yet. Run your first scan from the Overview tab.</p>
              </div>
            )}

          </>)}

        </div>
      </main>
    </div>
  );
}
