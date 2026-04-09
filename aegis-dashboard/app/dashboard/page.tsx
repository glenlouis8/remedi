'use client';

import { useState, useRef, useEffect } from 'react';
import { useAuth, useClerk, useUser } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldCheck, ShieldAlert, Play, Square, CheckCircle, XCircle,
  AlertTriangle, Users, HardDrive, Globe, Shield,
  Server, Database, Zap, FileText, Lock, ChevronDown, ChevronRight,
  LayoutDashboard, History, LogOut, Clock,
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
}
interface RemediationLog { resource_name: string; action: string; status: string; duration: number; timestamp: string }
interface ScanDetail {
  id: string;
  start_time: string;
  end_time?: string;
  findings_count: number;
  remediations_count: number;
  status: string;
  verified: boolean;
  audit_summary?: string;
  remediations: RemediationLog[];
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

function ScoreGauge({ score, total, percentage, large = false }: {
  score: number; total: number; percentage: number; large?: boolean
}) {
  const color = percentage >= 80 ? '#8b5cf6' : percentage >= 50 ? '#f59e0b' : '#ef4444';
  const label = percentage >= 80 ? 'Compliant' : percentage >= 50 ? 'Needs attention' : 'At risk';

  if (large) {
    const r = 60; const circ = 2 * Math.PI * r; const arcLen = circ * 0.75;
    const filled = (percentage / 100) * arcLen;
    return (
      <div className="flex flex-col items-center">
        <svg viewBox="0 0 160 160" className="w-52 h-52">
          <circle cx="80" cy="80" r={r} fill="none" stroke="#222228" strokeWidth="10"
            strokeDasharray={`${arcLen} ${circ}`} strokeLinecap="round" transform="rotate(135 80 80)" />
          <circle cx="80" cy="80" r={r} fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={`${filled} ${circ}`} strokeLinecap="round" transform="rotate(135 80 80)"
            style={{ transition: 'stroke-dasharray 1s ease' }} />
          <text x="80" y="74" textAnchor="middle" fontSize="36" fontWeight="700" fill="#e2e8f0" fontFamily="JetBrains Mono, monospace">{percentage}%</text>
          <text x="80" y="95" textAnchor="middle" fontSize="12" fill="#475569">{score} / {total} controls</text>
        </svg>
        <span className="text-sm font-semibold -mt-5" style={{ color }}>{label}</span>
      </div>
    );
  }

  const r = 36; const circ = 2 * Math.PI * r; const arcLen = circ * 0.75;
  const filled = (percentage / 100) * arcLen;
  return (
    <div className="flex flex-col items-center justify-center">
      <svg viewBox="0 0 100 100" className="w-32 h-32">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#222228" strokeWidth="10"
          strokeDasharray={`${arcLen} ${circ}`} strokeLinecap="round" transform="rotate(135 50 50)" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${filled} ${circ}`} strokeLinecap="round" transform="rotate(135 50 50)"
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

  let cardClass = 'bg-[#111116] border-white/8';
  if (isActive)                  cardClass = 'bg-violet-950/30 border-violet-700/50 shadow-sm shadow-violet-900/20';
  else if (hasData && vulnCount) cardClass = 'bg-red-950/30 border-red-700/40';
  else if (hasData)              cardClass = 'bg-violet-950/20 border-violet-800/40';
  else if (isPending)            cardClass = 'bg-[#111116]/60 border-white/8/50 opacity-40';

  return (
    <div className={`rounded-xl border p-4 transition-all duration-500 ${cardClass}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <Icon size={14} className={
            isActive ? 'text-violet-400' : hasData && vulnCount ? 'text-red-400' : hasData ? 'text-violet-400' : 'text-slate-700'
          } />
          <span className={`text-sm font-medium ${isActive || hasData ? 'text-slate-200' : 'text-slate-700'}`}>{label}</span>
        </div>
        {isActive && <span className="flex items-center gap-1 text-xs text-violet-400"><span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />scanning</span>}
        {!isActive && hasData && vulnCount > 0 && <span className="text-xs text-red-400 font-medium">{vulnCount} issue{vulnCount !== 1 ? 's' : ''}</span>}
        {!isActive && hasData && vulnCount === 0 && <CheckCircle size={13} className="text-violet-400" />}
      </div>
      {hasData ? (
        <div className="space-y-1.5 mt-2">
          {items.map((item, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className={`shrink-0 text-xs ${item.status === 'vulnerable' ? 'text-red-400' : 'text-violet-400'}`}>
                {item.status === 'vulnerable' ? '⚠' : '✓'}
              </span>
              <span className="text-xs text-slate-500 font-mono truncate">{item.resource}</span>
            </div>
          ))}
        </div>
      ) : isActive ? (
        <div className="space-y-1.5 mt-2">
          {[1, 2].map(i => <div key={i} className="h-3 bg-violet-900/40 rounded animate-pulse" style={{ width: `${50 + i * 20}%` }} />)}
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
  const [approvedItems, setApprovedItems]       = useState<Set<string>>(new Set());
  const [showSuccess, setShowSuccess]           = useState(false);

  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [scanDetail, setScanDetail]         = useState<ScanDetail | null>(null);
  const [detailLoading, setDetailLoading]   = useState(false);

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
    let wasAborted = false;
    let hadVulns   = false;
    const tracker: { resource: string; status: 'running' | 'success' | 'error' }[] = [];
    // Local accumulator for scan items — avoids React batching causing old state
    // to leak into new scans when using the functional updater (prev => ...).
    const localItems: Partial<Record<ServiceKey, ScanItem[]>> = {};

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
                if (!localItems[svc]) localItems[svc] = [];
                const alreadyHas = localItems[svc]!.some(i => i.resource === event.resource);
                if (!alreadyHas) {
                  localItems[svc]!.push({ resource: event.resource, status: event.status, msg: event.msg ?? '' });
                  setScanItems({ ...localItems });
                }
              }
            } catch { /* malformed */ }
            continue;
          }

          if (raw.includes('[ACTION_REQUIRED] WAITING_FOR_APPROVAL')) {
            setActiveService(null);
            setScanState('awaiting_approval');
            // Default: all findings approved
            setRemediationPlan(prev => {
              setApprovedItems(new Set(prev.map(p => p.resource)));
              return prev;
            });
          }

          if (raw.includes('[CRITICAL]') || raw.includes('[POLICY VIOLATION]') || raw.includes('[HIGH]')) {
            const item = parseRemediationItem(raw);
            if (item) {
              hadVulns = true;
              setRemediationPlan(prev => {
                const exists = prev.some(p => p.resource === item.resource && p.toolName === item.toolName);
                return exists ? prev : [...prev, item];
              });
            }
          }

          const execMatch = raw.match(/\[EXEC\] Calling (\w+) with \{(.+)\}/);
          if (execMatch) {
            const funcName      = execMatch[1];
            const resourceMatch = execMatch[2].match(/['"]([\w\-\.]+)['"]/);
            const resource      = resourceMatch?.[1] || funcName;
            tracker.push({ resource, status: 'running' });
            setScanState('remediating');
            setRemediationSteps(prev => [...prev, { funcName, resource, status: 'running' }]);
          }

          if (raw.includes('✅') && raw.includes('SUCCESS') && !raw.includes('[EXEC]')) {
            const idx = tracker.findLastIndex(s => s.status === 'running');
            if (idx >= 0) tracker[idx].status = 'success';
            setRemediationSteps(prev => {
              const updated = [...prev];
              const i = updated.findLastIndex(s => s.status === 'running');
              if (i >= 0) updated[i] = { ...updated[i], status: 'success' };
              return updated;
            });
          }

          if (raw.includes('❌')) {
            const idx = tracker.findLastIndex(s => s.status === 'running');
            if (idx >= 0) tracker[idx].status = 'error';
            setRemediationSteps(prev => {
              const updated = [...prev];
              const i = updated.findLastIndex(s => s.status === 'running');
              if (i >= 0) updated[i] = { ...updated[i], status: 'error' };
              return updated;
            });
          }
        }
      }
    } catch (err: unknown) {
      if ((err as Error).name === 'AbortError') wasAborted = true;
    } finally {
      setActiveService(null);
      if (wasAborted) {
        setScanState('idle');
      } else {
        setScanState('complete');
        if (!hadVulns) {
          setShowSuccess(true);
          setTimeout(() => setShowSuccess(false), 4500);
        }
        // Flip fixed resources from vulnerable → ok in the service cards.
        // Uses the local tracker (not React state) to avoid async batching issues.
        const fixed = new Set(tracker.filter(s => s.status === 'success').map(s => s.resource));
        if (fixed.size > 0) {
          for (const svc of Object.keys(localItems) as ServiceKey[]) {
            localItems[svc] = localItems[svc]!.map(item =>
              fixed.has(item.resource) ? { ...item, status: 'ok' } : item
            );
          }
          setScanItems({ ...localItems });
        }
      }
    }
  };

  const toggleScanDetail = async (scanId: string) => {
    if (expandedScanId === scanId) {
      setExpandedScanId(null);
      setScanDetail(null);
      return;
    }
    setExpandedScanId(scanId);
    setScanDetail(null);
    setDetailLoading(true);
    try {
      const token = await getToken();
      const res = await fetch(`${API}/api/metrics/history/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) setScanDetail(await res.json());
    } finally {
      setDetailLoading(false);
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
    const approved = Array.from(approvedItems);
    await fetch(`${API}/api/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved_resources: approved }),
    });
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
    <div className="flex flex-col h-screen bg-[#09090b] overflow-hidden" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');`}</style>

      {/* ── Success overlay ──────────────────────────────────────────────────── */}
      {showSuccess && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#09090b]/75 backdrop-blur-sm"
          onClick={() => setShowSuccess(false)}
        >
          <div
            className="success-card relative bg-[#111116] border border-violet-500/25 rounded-2xl p-10 shadow-2xl shadow-violet-900/30 text-center w-80"
            onClick={e => e.stopPropagation()}
          >
            {/* Pulsing rings */}
            <div className="relative flex items-center justify-center mb-7">
              <div className="ring-out absolute w-20 h-20 rounded-full border border-violet-400/30" />
              <div className="ring-out absolute w-20 h-20 rounded-full border border-violet-400/20" style={{ animationDelay: '0.7s' }} />

              {/* Shield + checkmark */}
              <svg viewBox="0 0 80 80" className="w-20 h-20 relative z-10">
                <path
                  d="M40 8 L66 19 L66 43 C66 57 54 67 40 72 C26 67 14 57 14 43 L14 19 Z"
                  fill="rgba(139,92,246,0.07)" stroke="#8b5cf6" strokeWidth="2" strokeLinejoin="round"
                />
                <polyline
                  points="27,40 36,50 53,30"
                  fill="none" stroke="#8b5cf6" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"
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
              <div className="flex-1 bg-[#09090b] rounded-xl px-4 py-3 border border-white/8">
                <div className="text-xl font-bold text-violet-400">{fixedCount}</div>
                <div className="text-xs text-slate-500 mt-0.5">Fixed</div>
              </div>
              <div className="flex-1 bg-[#09090b] rounded-xl px-4 py-3 border border-white/8">
                <div className="text-xl font-bold text-violet-400">✓</div>
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

      {/* ── Top nav ─────────────────────────────────────────────────────────── */}
      <header className="shrink-0 border-b border-white/6" style={{ background: '#09090b' }}>
        <div className="flex items-center justify-between px-6 h-14 gap-4">

          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 shrink-0">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.25)' }}>
              <ShieldCheck size={15} className="text-violet-400" />
            </div>
            <span className="font-semibold tracking-tight text-white">Remedi</span>
          </Link>

          {/* Tab nav */}
          <nav className="flex items-center gap-1">
            {([
              { key: 'overview',   label: 'Overview',   Icon: LayoutDashboard },
              { key: 'compliance', label: 'Compliance', Icon: Shield          },
              { key: 'history',    label: 'History',    Icon: History         },
            ] as const).map(({ key, label, Icon }) => (
              <button key={key} onClick={() => setView(key)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors ${
                  view === key
                    ? 'bg-violet-500/10 text-violet-400 font-medium'
                    : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
                }`}>
                <Icon size={14} />
                {label}
              </button>
            ))}
          </nav>

          {/* Right: account pills + user */}
          <div className="flex items-center gap-2 shrink-0">

            {/* Account pills */}
            {accounts.map(a => (
              <button
                key={a.account_name}
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
                className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors disabled:opacity-40 ${
                  selectedAccount === a.account_name
                    ? 'bg-violet-500/10 border-violet-500/30 text-violet-400'
                    : 'border-white/8 text-slate-500 hover:text-slate-300 hover:border-white/15'
                }`}
              >
                {a.account_name}
              </button>
            ))}
            {accounts.length < 3 && (
              <Link href="/onboarding" className="text-xs text-slate-600 hover:text-slate-400 px-2 py-1.5 transition-colors">
                + Add
              </Link>
            )}

            {/* User avatar */}
            <div className="relative ml-1" ref={dropdownRef}>
              <button
                onClick={() => setDropdownOpen(v => !v)}
                className="w-8 h-8 rounded-full bg-violet-500/15 border border-violet-500/25 flex items-center justify-center hover:bg-violet-500/25 transition-colors"
              >
                <span className="text-xs font-semibold text-violet-400">{userInitial}</span>
              </button>
              {dropdownOpen && (
                <div className="absolute right-0 top-full mt-2 w-52 bg-[#111116] border border-white/8 rounded-xl shadow-2xl shadow-black/50 z-20 overflow-hidden">
                  <div className="px-4 py-3 border-b border-white/6">
                    <p className="text-xs font-medium text-slate-200 truncate">{user?.firstName ?? 'User'}</p>
                    <p className="text-xs text-slate-600 truncate">{user?.emailAddresses?.[0]?.emailAddress ?? ''}</p>
                  </div>
                  {credentialUser && (
                    <div className="px-4 py-2.5 border-b border-white/6">
                      <p className="text-xs text-slate-600 mb-0.5">Connected as</p>
                      <p className="text-xs font-mono text-slate-400 truncate">{credentialUser}</p>
                    </div>
                  )}
                  <button
                    onClick={async () => {
                      const token = await getToken();
                      await fetch(`${API}/api/accounts`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }).catch(console.error);
                      signOut({ redirectUrl: '/' });
                    }}
                    className="w-full flex items-center gap-2 px-4 py-2.5 text-xs text-slate-500 hover:text-slate-200 hover:bg-white/5 transition-colors text-left"
                  >
                    <LogOut size={12} /> Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* ── Main ────────────────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-5xl mx-auto px-6 py-7 space-y-6">

          {/* ── Overview ──────────────────────────────────────────────────────── */}
          {view === 'overview' && (<>

            {/* ── IDLE: hero card ── */}
            {scanState === 'idle' && (
              <div className="rounded-2xl border border-white/8 bg-[#111116] overflow-hidden">
                <div className="flex flex-col items-center text-center px-8 pt-12 pb-10">
                  {cisScore ? (
                    <ScoreGauge large score={cisScore.score} total={cisScore.total} percentage={cisScore.percentage} />
                  ) : (
                    <div className="w-52 h-52 flex items-center justify-center">
                      <div className="w-36 h-36 rounded-full border-8 border-white/6 flex items-center justify-center animate-pulse">
                        <span className="text-slate-700 text-xs">Loading…</span>
                      </div>
                    </div>
                  )}
                  <button onClick={startScan}
                    className="mt-6 flex items-center gap-2.5 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-8 py-3 rounded-xl transition-colors text-sm shadow-lg shadow-violet-900/20">
                    <Play size={14} className="fill-current" /> Run security scan
                  </button>
                  {credentialUser && (
                    <p className="text-xs text-slate-600 mt-3">
                      Scanning <span className="font-mono text-slate-500">{credentialUser}</span>
                    </p>
                  )}
                </div>
                <div className="grid grid-cols-4 border-t" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                  {[
                    { label: 'Total scans',  value: String(metrics?.total_scans ?? '—') },
                    { label: 'Success rate', value: metrics?.success_rate ?? '—'         },
                    { label: 'Avg fix time', value: metrics?.avg_mttr ?? '—'             },
                    { label: 'Open vulns',   value: openVulns                            },
                  ].map(({ label, value }, idx) => (
                    <div key={label} className="px-6 py-4 text-center" style={{ borderLeft: idx > 0 ? '1px solid rgba(255,255,255,0.06)' : 'none' }}>
                      <p className="text-xl font-bold text-slate-100" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{value}</p>
                      <p className="text-xs text-slate-600 mt-0.5">{label}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── SCANNING ── */}
            {scanState === 'scanning' && (
              <div className="rounded-2xl border border-white/8 bg-[#111116] overflow-hidden">
                {/* Header */}
                <div className="flex items-center justify-between px-5 py-4 border-b border-white/6">
                  <div className="flex items-center gap-3">
                    <div className="relative flex items-center justify-center w-6 h-6">
                      <span className="absolute w-full h-full rounded-full bg-violet-500/20 animate-ping" />
                      <span className="w-2 h-2 rounded-full bg-violet-400 relative z-10" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-slate-100">
                        {activeService ? `Scanning ${SERVICE_META[activeService].label}` : 'Initializing…'}
                      </p>
                      <p className="text-xs text-slate-600 mt-0.5">
                        {Object.keys(scanItems).length} of {SERVICE_ORDER.length} services complete
                      </p>
                    </div>
                  </div>
                  <button onClick={handleStop}
                    className="flex items-center gap-1.5 text-xs text-red-400 border border-red-900/50 bg-red-950/20 px-3 py-1.5 rounded-lg hover:bg-red-950/40 transition-colors">
                    <Square size={10} className="fill-current" /> Stop
                  </button>
                </div>

                {/* Progress bar */}
                <div className="h-px w-full" style={{ background: 'rgba(255,255,255,0.04)' }}>
                  <div className="h-full bg-violet-500/60 transition-all duration-700"
                    style={{ width: `${(Object.keys(scanItems).length / SERVICE_ORDER.length) * 100}%` }} />
                </div>

                {/* Service rows */}
                <div className="divide-y divide-white/4">
                  {SERVICE_ORDER.map(svc => {
                    const { label, Icon } = SERVICE_META[svc];
                    const items    = scanItems[svc];
                    const isActive = activeService === svc;
                    const isDone   = !!items;
                    const vulns    = items?.filter(i => i.status === 'vulnerable') ?? [];

                    return (
                      <div key={svc} className={`flex items-center gap-4 px-5 py-3 transition-colors ${isActive ? 'bg-violet-950/20' : ''}`}>
                        <Icon size={13} className={isActive ? 'text-violet-400' : isDone ? 'text-slate-500' : 'text-slate-700'} />
                        <span className={`text-sm flex-1 ${isActive ? 'text-slate-100' : isDone ? 'text-slate-400' : 'text-slate-700'}`}
                          style={{ fontFamily: "'JetBrains Mono', monospace" }}>{label}</span>

                        {isActive && (
                          <span className="flex items-center gap-1.5 text-xs text-violet-400">
                            <span className="w-3 h-3 rounded-full border-2 border-violet-400 border-t-transparent animate-spin" />
                            scanning
                          </span>
                        )}
                        {isDone && vulns.length > 0 && (
                          <span className="text-xs font-medium text-red-400 bg-red-950/40 border border-red-800/30 px-2 py-0.5 rounded">
                            {vulns.length} {vulns.length === 1 ? 'issue' : 'issues'}
                          </span>
                        )}
                        {isDone && vulns.length === 0 && (
                          <span className="flex items-center gap-1 text-xs text-slate-600">
                            <CheckCircle size={11} className="text-slate-600" /> clean
                          </span>
                        )}
                        {!isDone && !isActive && (
                          <span className="text-xs text-slate-800">—</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ── AWAITING APPROVAL ── */}
            {scanState === 'awaiting_approval' && (
              <div className="space-y-3">

                {/* Header */}
                <div className="flex items-center justify-between px-5 py-4 rounded-2xl border border-amber-700/30 bg-amber-950/10">
                  <div className="flex items-center gap-3">
                    <AlertTriangle size={15} className="text-amber-400 shrink-0" />
                    <div>
                      <p className="text-sm font-semibold text-slate-100">
                        {remediationPlan.length} {remediationPlan.length === 1 ? 'vulnerability' : 'vulnerabilities'} detected
                      </p>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {approvedItems.size} of {remediationPlan.length} selected for remediation
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={handleStop}
                      className="text-xs text-slate-500 hover:text-slate-300 border border-white/8 hover:border-white/15 px-3 py-2 rounded-lg transition-colors">
                      Cancel
                    </button>
                    <button
                      onClick={handleApprove}
                      disabled={approvedItems.size === 0}
                      className="flex items-center gap-2 text-sm font-semibold bg-violet-500 hover:bg-violet-400 disabled:opacity-40 disabled:cursor-not-allowed text-white px-5 py-2 rounded-lg transition-colors">
                      Apply {approvedItems.size} {approvedItems.size === 1 ? 'fix' : 'fixes'}
                    </button>
                  </div>
                </div>

                {/* Per-finding cards */}
                <div className="space-y-2">
                  {remediationPlan.map((item, i) => {
                    const info      = REMEDIATION_INFO[item.toolName];
                    const isApproved = approvedItems.has(item.resource);
                    return (
                      <div key={i} className={`rounded-xl border transition-all duration-200 overflow-hidden ${
                        isApproved ? 'border-violet-700/40 bg-[#111116]' : 'border-white/6 bg-[#0d0d10] opacity-50'
                      }`}>
                        <div className="flex items-start gap-4 px-5 py-4">
                          {/* Icon */}
                          <div className={`w-9 h-9 rounded-lg border flex items-center justify-center text-base shrink-0 mt-0.5 ${
                            isApproved ? 'bg-violet-500/10 border-violet-500/20' : 'bg-white/4 border-white/8'
                          }`}>
                            {info?.icon ?? '🔧'}
                          </div>

                          {/* Details */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <p className="text-sm font-semibold text-slate-100">{info?.title ?? item.toolName}</p>
                              <span className="text-xs font-mono text-slate-500 bg-white/4 border border-white/8 px-2 py-0.5 rounded">
                                {item.resource}
                              </span>
                            </div>
                            <p className="text-xs text-slate-500 mt-1 leading-relaxed">{info?.risk ?? 'Vulnerability detected'}</p>
                            <p className="text-xs text-slate-700 mt-1">
                              Fix: <span className="text-slate-500 font-mono">{item.toolName}</span>
                            </p>
                          </div>

                          {/* Toggle */}
                          <button
                            onClick={() => setApprovedItems(prev => {
                              const next = new Set(prev);
                              if (next.has(item.resource)) next.delete(item.resource);
                              else next.add(item.resource);
                              return next;
                            })}
                            className={`shrink-0 text-xs font-medium px-3 py-1.5 rounded-lg border transition-colors ${
                              isApproved
                                ? 'bg-violet-500/15 border-violet-500/30 text-violet-300 hover:bg-red-950/20 hover:border-red-700/30 hover:text-red-400'
                                : 'bg-white/4 border-white/8 text-slate-500 hover:bg-violet-500/10 hover:border-violet-500/20 hover:text-violet-400'
                            }`}
                          >
                            {isApproved ? 'Approved' : 'Skipped'}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ── REMEDIATING ── */}
            {scanState === 'remediating' && (
              <div className="rounded-2xl border border-white/8 bg-[#111116] p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <span className="w-2 h-2 rounded-full bg-violet-400 animate-pulse" />
                    <h2 className="font-semibold text-slate-100 text-sm">Applying fixes</h2>
                  </div>
                  <span className="text-xs text-slate-500">
                    {remediationSteps.filter(s => s.status === 'success').length} / {remediationSteps.length} done
                  </span>
                </div>
                {remediationSteps.length > 0 && (
                  <div className="w-full h-1 rounded-full mb-5 overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
                    <div className="h-full rounded-full bg-violet-500 transition-all duration-500"
                      style={{ width: `${(remediationSteps.filter(s => s.status === 'success').length / remediationSteps.length) * 100}%` }} />
                  </div>
                )}
                <div className="space-y-2">
                  {remediationSteps.map((step, i) => {
                    const info = REMEDIATION_INFO[step.funcName];
                    return (
                      <div key={i} className={`flex items-center gap-3 px-4 py-3 rounded-lg border text-sm transition-all ${
                        step.status === 'success' ? 'border-violet-700/40 bg-violet-950/20' :
                        step.status === 'error'   ? 'border-red-700/40 bg-red-950/20'       :
                                                    'border-white/6 bg-white/2'
                      }`}>
                        <span className="text-base w-5 text-center shrink-0">{info?.icon ?? '🔧'}</span>
                        <span className="flex-1 text-slate-300">{info?.title ?? step.funcName}</span>
                        <span className="text-xs font-mono text-slate-600">{step.resource}</span>
                        {step.status === 'success' && <CheckCircle size={14} className="text-violet-400 shrink-0" />}
                        {step.status === 'error'   && <XCircle    size={14} className="text-red-400 shrink-0" />}
                        {step.status === 'running' && <span className="w-3 h-3 rounded-full border-2 border-amber-400 border-t-transparent animate-spin shrink-0" />}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ── COMPLETE ── */}
            {scanState === 'complete' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between px-6 py-4 rounded-2xl border border-violet-700/30 bg-violet-950/20">
                  <div className="flex items-center gap-4">
                    <div className="w-9 h-9 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
                      <CheckCircle size={16} className="text-violet-400" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-slate-100">Scan complete</p>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {fixedCount > 0 ? `${fixedCount} ${fixedCount === 1 ? 'fix' : 'fixes'} applied and verified` : 'No vulnerabilities found'}
                      </p>
                    </div>
                  </div>
                  <button onClick={startScan}
                    className="flex items-center gap-2 text-sm bg-violet-500 hover:bg-violet-400 text-white font-semibold px-4 py-2 rounded-lg transition-colors">
                    <Play size={11} className="fill-current" /> Scan again
                  </button>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {SERVICE_ORDER.map(svc => (
                    <ServiceCard key={svc} svc={svc} items={scanItems[svc] ?? []} isActive={false} scanState={scanState} />
                  ))}
                </div>
                {lastScan && (
                  <div className="flex items-center justify-between px-5 py-3 rounded-xl border border-white/6 text-xs text-slate-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    <span>{lastScan.id}</span>
                    <span>{new Date(lastScan.start_time).toLocaleString()}</span>
                    <span>{lastScan.findings_count ?? 0} findings · {lastScan.remediations_count ?? 0} fixed</span>
                  </div>
                )}
              </div>
            )}

            {/* ── Protected users: compact pill row ── */}
            {(scanState === 'idle' || scanState === 'complete') && iamUsers.length > 0 && (
              <div className="flex items-center justify-between px-5 py-3.5 rounded-xl border border-white/6">
                <div className="flex items-center gap-3">
                  <Lock size={13} className="text-slate-600 shrink-0" />
                  <div>
                    <p className="text-xs font-medium text-slate-400">Protected IAM users</p>
                    <p className="text-xs text-slate-600 mt-0.5">
                      {credentialUser && <><span className="font-mono">{credentialUser}</span> always protected · </>}
                      {protectedUsers.length > 0 ? `${protectedUsers.length} additional selected` : 'none additional'}
                    </p>
                  </div>
                </div>
                <div className="relative shrink-0" ref={dropdownRef}>
                  <button onClick={() => setDropdownOpen(v => !v)}
                    className="flex items-center gap-2 text-xs border border-white/8 bg-[#09090b] hover:bg-white/4 rounded-lg px-3 py-2 transition-colors">
                    <span className="text-slate-400">
                      {protectedUsers.length === 0 ? 'Add users…' : `${protectedUsers.length} selected`}
                    </span>
                    <ChevronDown size={12} className={`text-slate-500 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
                  </button>
                  {dropdownOpen && (
                    <div className="absolute right-0 top-full mt-1 w-60 bg-[#111116] border border-white/8 rounded-xl shadow-2xl shadow-black/50 z-10 overflow-hidden">
                      {credentialUser && (
                        <div className="flex items-center gap-3 px-4 py-2.5 bg-[#09090b] border-b border-white/6">
                          <Lock size={11} className="text-slate-600 shrink-0" />
                          <span className="text-xs font-mono text-slate-500 flex-1 truncate">{credentialUser}</span>
                          <span className="text-xs text-slate-700">auto</span>
                        </div>
                      )}
                      <div className="max-h-52 overflow-y-auto">
                        {iamUsers.filter(u => u !== credentialUser).map(u => {
                          const checked = protectedUsers.includes(u);
                          return (
                            <label key={u} className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/3 cursor-pointer transition-colors">
                              <input type="checkbox" checked={checked}
                                onChange={() => setProtectedUsers(prev => checked ? prev.filter(x => x !== u) : [...prev, u])}
                                className="accent-violet-500" />
                              <span className="text-xs font-mono text-slate-300 truncate">{u}</span>
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
            )}

          </>)}

          {/* ── Compliance ────────────────────────────────────────────────────── */}
          {view === 'compliance' && (<>

            {/* Score banner */}
            <div className="bg-[#111116] border border-white/8 rounded-xl p-6 flex items-center gap-8 shadow-sm">
              {cisScore
                ? <ScoreGauge score={cisScore.score} total={cisScore.total} percentage={cisScore.percentage} />
                : <div className="w-32 h-32 rounded-full border-8 border-white/8 flex items-center justify-center">
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
                    <span className="flex items-center gap-1.5 text-violet-400">
                      <span className="w-2 h-2 rounded-full bg-violet-400" />{cisScore.score} passing
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
                      : 'bg-[#111116] border-white/8'
                  }`}>
                    <div className="flex items-center justify-between mb-3">
                      <ShieldAlert size={14} className={check.status === 'VULNERABLE' ? 'text-red-400' : 'text-violet-400'} />
                      <span className={`text-xs font-medium ${check.status === 'VULNERABLE' ? 'text-red-400' : 'text-violet-400'}`}>
                        {check.status === 'VULNERABLE' ? 'Vulnerable' : 'Secure'}
                      </span>
                    </div>
                    <p className="text-sm font-medium text-slate-200 leading-tight mb-1">{check.name}</p>
                    <p className="text-xs text-slate-500 leading-tight line-clamp-2">{check.description}</p>
                  </div>
                ))}
                {checks.length === 0 && [1,2,3,4,5,6,7,8].map(i => (
                  <div key={i} className="h-24 bg-[#111116] border border-white/8 rounded-xl animate-pulse" />
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
                { label: 'Success rate', value: metrics?.success_rate ?? '—', sub: 'fixes applied', Icon: TrendingUp, color: 'text-violet-400' },
                { label: 'Avg fix time', value: metrics?.avg_mttr     ?? '—', sub: 'per scan',      Icon: Clock,      color: 'text-slate-100'   },
              ].map(({ label, value, sub, Icon, color }) => (
                <div key={label} className="bg-[#111116] border border-white/8 rounded-xl p-5 shadow-sm">
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-xs text-slate-500 font-medium">{label}</p>
                    <Icon size={14} className="text-slate-700" />
                  </div>
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-xs text-slate-600 mt-1">{sub}</p>
                </div>
              ))}
            </div>

            {/* History list */}
            {scanHistory.length > 0 ? (
              <div className="space-y-2">
                {scanHistory.map(scan => {
                  const isExpanded = expandedScanId === scan.id;
                  const isLoading  = isExpanded && detailLoading;
                  const detail     = isExpanded && !detailLoading ? scanDetail : null;

                  // Parse findings from audit_summary (🔴 lines)
                  const findingLines = detail?.audit_summary
                    ? detail.audit_summary.split('\n').filter(l => l.includes('🔴') || l.includes('⚠️'))
                    : [];

                  const TOOL_LABEL: Record<string, string> = {
                    restrict_iam_user:             'Revoke Admin Privileges',
                    remediate_s3:                  'Block Public S3 Access',
                    remediate_vpc_flow_logs:        'Enable VPC Flow Logs',
                    revoke_security_group_ingress:  'Close Open Ports',
                    enforce_imdsv2:                 'Enforce IMDSv2',
                    stop_instance:                  'Quarantine EC2 Instance',
                    remediate_rds_public_access:    'Make RDS Private',
                    remediate_lambda_role:          'Fix Lambda Permissions',
                    remediate_cloudtrail:            'Enable CloudTrail',
                  };

                  return (
                    <div key={scan.id} className="bg-[#111116] border border-white/8 rounded-xl overflow-hidden">
                      {/* Row */}
                      <button
                        onClick={() => toggleScanDetail(scan.id)}
                        className="w-full flex items-center gap-4 px-5 py-4 hover:bg-white/2 transition-colors text-left"
                      >
                        <ChevronRight size={14} className={`text-slate-600 shrink-0 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                        <div className="flex-1 min-w-0 grid grid-cols-5 gap-4 items-center">
                          <div className="col-span-2">
                            <p className="text-xs text-slate-400">{new Date(scan.start_time).toLocaleString()}</p>
                            <p className="text-xs text-slate-600 font-mono mt-0.5">{scan.id}</p>
                          </div>
                          <div className="text-center">
                            <p className="text-sm font-semibold text-slate-200">{scan.findings_count ?? 0}</p>
                            <p className="text-xs text-slate-600">findings</p>
                          </div>
                          <div className="text-center">
                            <p className="text-sm font-semibold text-violet-400">{Math.min(scan.remediations_count ?? 0, scan.findings_count ?? 0)}</p>
                            <p className="text-xs text-slate-600">fixed</p>
                          </div>
                          <div className="text-right">
                            <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${
                              scan.verified               ? 'bg-violet-500/10 text-violet-400 border-violet-700/40' :
                              scan.status === 'SECURE'    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-700/40' :
                              scan.status === 'COMPLETED' ? 'bg-blue-500/10 text-blue-400 border-blue-700/40'      :
                              scan.status === 'ABORTED'   ? 'bg-slate-800 text-slate-400 border-slate-700'         :
                              'bg-red-500/10 text-red-400 border-red-700/40'
                            }`}>
                              {scan.verified ? '✓ Verified' : scan.status === 'SECURE' ? '✓ Secure' : scan.status}
                            </span>
                          </div>
                        </div>
                      </button>

                      {/* Expanded detail */}
                      {isExpanded && (
                        <div className="border-t border-white/6 bg-[#0d0d10] px-5 py-4 space-y-5">
                          {isLoading ? (
                            <p className="text-xs text-slate-600 py-4 text-center">Loading scan details…</p>
                          ) : detail ? (
                            <>
                              {/* Meta row */}
                              {detail.end_time && (
                                <div className="flex items-center gap-6 text-xs text-slate-500">
                                  <span>Duration: <span className="text-slate-300">{
                                    Math.round((new Date(detail.end_time).getTime() - new Date(detail.start_time).getTime()) / 1000)
                                  }s</span></span>
                                </div>
                              )}

                              {/* Findings */}
                              {findingLines.length > 0 && (
                                <div>
                                  <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Findings</p>
                                  <div className="space-y-1">
                                    {findingLines.map((line, i) => {
                                      const isCritical = line.includes('CRITICAL') || line.includes('🔴');
                                      const resourceMatch = line.match(/\] (.+?) is vulnerable/);
                                      const resource = resourceMatch?.[1] ?? line.replace(/^[🔴⚠️\s\[\w\]]+/, '').trim();
                                      const actionMatch = line.match(/call `?(\w+)`?/);
                                      const action = actionMatch ? (TOOL_LABEL[actionMatch[1]] ?? actionMatch[1]) : '';
                                      return (
                                        <div key={i} className="flex items-start gap-2.5 text-xs py-1.5">
                                          {isCritical
                                            ? <XCircle size={12} className="text-red-400 shrink-0 mt-0.5" />
                                            : <AlertTriangle size={12} className="text-amber-400 shrink-0 mt-0.5" />}
                                          <span className="text-slate-300 font-mono">{resource}</span>
                                          {action && <span className="text-slate-600">→ {action}</span>}
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              )}

                              {/* Remediations */}
                              {detail.remediations.length > 0 && (
                                <div>
                                  <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Remediations</p>
                                  <div className="space-y-1">
                                    {detail.remediations.map((r, i) => (
                                      <div key={i} className="flex items-center gap-2.5 text-xs py-1">
                                        {r.status === 'SUCCESS'
                                          ? <CheckCircle size={12} className="text-violet-400 shrink-0" />
                                          : <XCircle size={12} className="text-red-400 shrink-0" />}
                                        <span className="text-slate-300 font-mono">{r.resource_name}</span>
                                        <span className="text-slate-600">{TOOL_LABEL[r.action] ?? r.action}</span>
                                        <span className="ml-auto text-slate-700">{r.duration.toFixed(1)}s</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {detail.remediations.length === 0 && findingLines.length === 0 && (
                                <div className="flex items-center gap-2 text-xs text-emerald-400 py-2">
                                  <CheckCircle size={13} className="shrink-0" />
                                  No vulnerabilities found — account was clean at time of scan.
                                </div>
                              )}
                            </>
                          ) : null}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="bg-[#111116] border border-white/8 rounded-xl p-10 flex flex-col items-center text-center">
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
