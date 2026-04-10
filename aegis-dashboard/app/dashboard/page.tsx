'use client';

import { useState, useRef, useEffect } from 'react';
import { useAuth, useClerk, useUser } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldCheck, Play, Square, CheckCircle, XCircle,
  AlertTriangle, Users, HardDrive, Globe, Shield,
  Server, Database, Zap, FileText, Lock, ChevronDown, ChevronRight,
  LayoutDashboard, History, LogOut, Clock, Trash2,
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
  account_name: string;
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
  const [resourceReasons, setResourceReasons]   = useState<Record<string, string>>({});
  const [showSuccess, setShowSuccess]           = useState(false);

  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [scanDetail, setScanDetail]         = useState<ScanDetail | null>(null);
  const [detailLoading, setDetailLoading]   = useState(false);

  const [accounts, setAccounts]             = useState<{account_name: string}[]>([]);
  const [selectedAccount, setSelectedAccount] = useState<string>('Default');
  const [iamUsers, setIamUsers]             = useState<string[]>([]);
  const [credentialUser, setCredentialUser] = useState<string | null>(null);
  const [protectedUsers, setProtectedUsers] = useState<string[]>([]);
  const [view, setView]                     = useState<'overview' | 'history' | 'settings'>('overview');
  const [confirmDelete, setConfirmDelete]   = useState(false);
  const [scansRemaining, setScansRemaining] = useState<number | null>(null);
  const [scanError, setScanError]           = useState<string | null>(null);
  const [dropdownOpen, setDropdownOpen]     = useState(false);
  const [iamPickerOpen, setIamPickerOpen]   = useState(false);
  const [iamLoading, setIamLoading]         = useState(false);
  const [feedbackRating, setFeedbackRating]     = useState(0);
  const [feedbackHover, setFeedbackHover]       = useState(0);
  const [feedbackMessage, setFeedbackMessage]   = useState('');
  const [feedbackScanId, setFeedbackScanId]     = useState<string | null>(null);
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);
  const [showDisclaimer, setShowDisclaimer]     = useState(false);
  const dropdownRef                         = useRef<HTMLDivElement>(null);
  const iamPickerRef                        = useRef<HTMLDivElement>(null);
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
      if (iamPickerRef.current && !iamPickerRef.current.contains(e.target as Node)) setIamPickerOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  useEffect(() => {
    const h = async () => ({ Authorization: `Bearer ${await getToken()}` });

    const fetchIamUsers = async (acct: string) => {
      setIamLoading(true);
      try {
        const res = await fetch(`${API}/api/iam/users?account_name=${encodeURIComponent(acct)}`, { headers: await h() });
        if (res.ok) {
          const data = await res.json();
          setIamUsers(data.users ?? []);
          setCredentialUser(data.credential_user ?? null);
        }
      } catch { /* ignore */ }
      finally { setIamLoading(false); }
    };

    const fetchScansRemaining = async (acct: string) => {
      try {
        const res = await fetch(`${API}/api/scans/remaining?account_name=${encodeURIComponent(acct)}`, { headers: await h() });
        if (res.ok) {
          const data = await res.json();
          setScansRemaining(data.remaining ?? null);
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
      setSelectedAccount(prev => { fetchIamUsers(prev); fetchScansRemaining(prev); return prev; });
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
    setScanError(null);
    setScanItems({});
    setFeedbackRating(0);
    setFeedbackHover(0);
    setFeedbackMessage('');
    setFeedbackScanId(null);
    setFeedbackSubmitted(false);
    setActiveService(null);
    setRemediationPlan([]);
    setRemediationSteps([]);
    setResourceReasons({});

    const controller = new AbortController();
    abortRef.current = controller;
    let wasAborted = false;
    let hadVulns   = false;
    const tracker: { resource: string; status: 'running' | 'success' | 'error' }[] = [];
    // Local accumulators — avoids React batching causing old state to leak into new scans.
    const localItems: Partial<Record<ServiceKey, ScanItem[]>> = {};
    const localReasons: Record<string, string> = {};

    try {
      const token = await getToken();
      const res = await fetch(`${API}/api/run-agent`, {
        method: 'POST',
        signal: controller.signal,
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ account_name: selectedAccount, protected_users: protectedUsers }),
      });

      if (!res.ok || !res.body) {
        if (res.status === 429) {
          const data = await res.json().catch(() => ({}));
          setScanError(data.detail ?? 'Scan limit reached. Try again tomorrow.');
          setScansRemaining(0);
        }
        setScanState('idle');
        return;
      }

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
                if (event.status === 'vulnerable' && event.msg) {
                  localReasons[event.resource] = event.msg;
                }
              }
            } catch { /* malformed */ }
            continue;
          }

          if (raw.includes('[ACTION_REQUIRED] WAITING_FOR_APPROVAL')) {
            setActiveService(null);
            setScanState('awaiting_approval');
            // Flush reasons; start with nothing approved — user must explicitly approve
            setResourceReasons({ ...localReasons });
            setApprovedItems(new Set());
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
        // Refresh remaining scans count
        getToken().then(tok =>
          fetch(`${API}/api/scans/remaining?account_name=${encodeURIComponent(selectedAccount)}`, {
            headers: { Authorization: `Bearer ${tok}` },
          }).then(r => r.ok ? r.json() : null).then(d => { if (d) setScansRemaining(d.remaining); }).catch(() => {})
        );
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

      {/* ── Pre-scan disclaimer modal ───────────────────────────────────────── */}
      {showDisclaimer && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#09090b]/80 backdrop-blur-sm px-4">
          <div className="bg-[#111116] border border-white/10 rounded-2xl shadow-2xl shadow-black/60 w-full max-w-lg overflow-hidden">
            {/* Header */}
            <div className="px-6 py-5 border-b border-white/6">
              <div className="flex items-center gap-2 mb-1">
                <AlertTriangle size={15} className="text-amber-400 shrink-0" />
                <h2 className="text-sm font-semibold text-white">Before you scan</h2>
                <span className="ml-auto text-xs bg-amber-500/10 border border-amber-500/20 text-amber-400 px-2 py-0.5 rounded-full">Beta</span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Remedi will make the following changes to your AWS account if vulnerabilities are found and you approve them. Review carefully.
              </p>
            </div>

            {/* Changes list */}
            <div className="px-6 py-4 space-y-3 max-h-72 overflow-y-auto">
              {[
                { icon: '🔑', service: 'IAM', change: 'Overprivileged users will have all policies detached and ReadOnlyAccess applied.' },
                { icon: '🪣', service: 'S3', change: 'Publicly accessible buckets will have all four public access block settings enabled.' },
                { icon: '🌐', service: 'VPC', change: 'An IAM role (AegisFlowLogRole) and CloudWatch log group will be created. Both persist in your account permanently — they\'re required for flow logs to keep working.' },
                { icon: '🔒', service: 'Security Groups', change: 'Inbound rules allowing 0.0.0.0/0 on any port will be revoked. All other rules are left intact.' },
                { icon: '💻', service: 'EC2', change: 'IMDSv2 will be enforced on vulnerable instances. Instances with unencrypted root volumes will be stopped — running workloads will be interrupted.' },
                { icon: '🗄️', service: 'RDS', change: 'Publicly accessible databases will be set to private. No data is touched.' },
                { icon: '⚡', service: 'Lambda', change: 'Over-permissioned execution role policies will be detached.' },
                { icon: '📋', service: 'CloudTrail', change: 'A trail (remedi-audit-trail) and an S3 bucket for log delivery will be created. Both persist in your account and the S3 bucket will accumulate log data over time.' },
              ].map(({ icon, service, change }) => (
                <div key={service} className="flex gap-3">
                  <span className="text-sm shrink-0 mt-0.5">{icon}</span>
                  <div>
                    <p className="text-xs font-medium text-slate-300">{service}</p>
                    <p className="text-xs text-slate-500 leading-relaxed mt-0.5">{change}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Region + beta notices */}
            <div className="mx-6 mb-1 flex items-start gap-2 bg-white/3 border border-white/8 rounded-lg px-4 py-3">
              <Globe size={12} className="text-slate-500 shrink-0 mt-0.5" />
              <p className="text-xs text-slate-500 leading-relaxed">
                <strong className="text-slate-400">Single-region scan.</strong> Only resources in the region configured with your AWS credentials are visible. Resources in other regions will not be found or remediated.
              </p>
            </div>
            <div className="mx-6 mb-4 mt-3 flex items-start gap-2 bg-amber-500/5 border border-amber-500/15 rounded-lg px-4 py-3">
              <AlertTriangle size={12} className="text-amber-500 shrink-0 mt-0.5" />
              <p className="text-xs text-amber-500/80 leading-relaxed">
                Remedi is in <strong className="text-amber-400">beta</strong>. Only scan accounts you control and understand. Always review each finding before approving a fix. Use a dedicated IAM user with least-privilege access.
              </p>
            </div>

            {/* Actions */}
            <div className="px-6 pb-5 flex items-center gap-3 justify-end">
              <button
                onClick={() => setShowDisclaimer(false)}
                className="text-xs text-slate-500 hover:text-slate-300 px-4 py-2 rounded-lg hover:bg-white/5 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => { setShowDisclaimer(false); startScan(); }}
                className="flex items-center gap-2 text-xs font-semibold bg-violet-500 hover:bg-violet-400 text-white px-4 py-2 rounded-lg transition-colors"
              >
                <Play size={11} className="fill-current" /> I understand, run scan
              </button>
            </div>
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
            <span className="text-xs font-medium px-1.5 py-0.5 rounded-full border" style={{ color: '#f59e0b', borderColor: 'rgba(245,158,11,0.25)', background: 'rgba(245,158,11,0.08)', fontFamily: "'JetBrains Mono', monospace" }}>beta</span>
          </Link>

          {/* Tab nav */}
          <nav className="flex items-center gap-1">
            {([
              { key: 'overview',  label: 'Overview',  Icon: LayoutDashboard },
              { key: 'history',   label: 'History',   Icon: History         },
              { key: 'settings',  label: 'Settings',  Icon: Lock            },
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
                  setIamLoading(true);
                  getToken().then(token => {
                    fetch(`${API}/api/iam/users?account_name=${encodeURIComponent(a.account_name)}`, {
                      headers: { Authorization: `Bearer ${token}` },
                    }).then(r => r.ok ? r.json() : null).then(data => {
                      if (data) { setIamUsers(data.users ?? []); setCredentialUser(data.credential_user ?? null); }
                    }).catch(() => {}).finally(() => setIamLoading(false));
                    fetch(`${API}/api/scans/remaining?account_name=${encodeURIComponent(a.account_name)}`, {
                      headers: { Authorization: `Bearer ${token}` },
                    }).then(r => r.ok ? r.json() : null).then(d => { if (d) setScansRemaining(d.remaining); }).catch(() => {});
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
              <Link href="/onboarding" className="flex items-center gap-1 text-xs font-medium border border-violet-500/30 text-violet-400 hover:bg-violet-500/10 px-3 py-1.5 rounded-lg transition-colors">
                + Add account
              </Link>
            )}

            {/* User avatar */}
            <div className="relative ml-1" ref={dropdownRef}>
              <button
                onClick={() => setDropdownOpen(v => !v)}
                className="flex items-center gap-1.5 pl-1 pr-2 py-1 rounded-lg border border-white/8 hover:border-white/15 hover:bg-white/4 transition-colors"
              >
                <div className="w-6 h-6 rounded-full bg-violet-500/15 border border-violet-500/25 flex items-center justify-center">
                  <span className="text-xs font-semibold text-violet-400">{userInitial}</span>
                </div>
                <ChevronRight size={11} className={`text-slate-600 transition-transform ${dropdownOpen ? 'rotate-90' : 'rotate-0'}`} />
              </button>
              {dropdownOpen && (
                <div className="absolute right-0 top-full mt-2 w-56 bg-[#111116] border border-white/8 rounded-xl shadow-2xl shadow-black/50 z-20 overflow-hidden">
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
                  {selectedAccount && (
                    <button
                      onClick={() => { setDropdownOpen(false); handleDeleteAccount(selectedAccount); }}
                      disabled={scanState === 'scanning' || scanState === 'remediating'}
                      className="w-full flex items-center gap-2 px-4 py-2.5 text-xs text-slate-500 hover:text-red-400 hover:bg-red-500/5 transition-colors text-left disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <Trash2 size={12} /> Disconnect <span className="font-medium text-slate-400">{selectedAccount}</span>
                    </button>
                  )}
                  <div className="border-t border-white/6">
                    <a
                      href="mailto:glen.louis08@gmail.com"
                      className="w-full flex items-center gap-2 px-4 py-2.5 text-xs text-slate-500 hover:text-slate-200 hover:bg-white/5 transition-colors"
                    >
                      <span>✉</span> Contact developer
                    </a>
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

            {/* ── IDLE ── */}
            {scanState === 'idle' && (
              <div className="space-y-4">

                {/* Action bar */}
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-semibold text-slate-100">Security Overview</h2>
                    {lastScan ? (
                      <p className="text-xs text-slate-600 mt-0.5 font-mono">
                        Last scan {new Date(lastScan.start_time).toLocaleString()} · {lastScan.findings_count ?? 0} findings · {lastScan.remediations_count ?? 0} fixed
                      </p>
                    ) : (
                      <p className="text-xs text-slate-600 mt-0.5">No scans run yet</p>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {/* Protect users button */}
                    <div className="relative" ref={iamPickerRef}>
                      <button
                        onClick={() => setIamPickerOpen(v => !v)}
                        className="flex items-center gap-1.5 text-xs border border-white/8 hover:border-white/15 hover:bg-white/4 text-slate-400 px-3 py-2 rounded-lg transition-colors"
                      >
                        <Lock size={12} />
                        Protect users
                        {protectedUsers.length > 0 && (
                          <span className="ml-0.5 bg-violet-500/20 text-violet-400 text-xs px-1.5 py-0.5 rounded-full font-medium">{protectedUsers.length}</span>
                        )}
                      </button>
                      {iamPickerOpen && (
                        <div className="absolute right-0 top-full mt-1 w-64 bg-[#111116] border border-white/8 rounded-xl shadow-2xl shadow-black/50 z-20 overflow-hidden">
                          <div className="px-4 py-2.5 border-b border-white/6">
                            <p className="text-xs font-medium text-slate-400">Protected IAM users</p>
                            <p className="text-xs text-slate-600 mt-0.5">These users won't be touched during remediation.</p>
                          </div>
                          {credentialUser && (
                            <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/4 bg-white/2">
                              <Lock size={11} className="text-slate-600 shrink-0" />
                              <span className="text-xs font-mono text-slate-500 flex-1 truncate">{credentialUser}</span>
                              <span className="text-xs text-slate-700">auto</span>
                            </div>
                          )}
                          <div className="max-h-52 overflow-y-auto">
                            {iamLoading ? (
                              <p className="text-xs text-slate-600 px-4 py-3 animate-pulse">Loading IAM users…</p>
                            ) : iamUsers.filter(u => u !== credentialUser).length === 0 ? (
                              <p className="text-xs text-slate-600 px-4 py-3">No other IAM users found in this account.</p>
                            ) : (
                              iamUsers.filter(u => u !== credentialUser).map(u => {
                                const checked = protectedUsers.includes(u);
                                return (
                                  <label key={u} className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/3 cursor-pointer transition-colors">
                                    <input type="checkbox" checked={checked}
                                      onChange={() => setProtectedUsers(prev => checked ? prev.filter(x => x !== u) : [...prev, u])}
                                      className="accent-violet-500" />
                                    <span className="text-xs font-mono text-slate-300 truncate">{u}</span>
                                  </label>
                                );
                              })
                            )}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Scan limit + Run scan */}
                    <div className="flex flex-col items-end gap-1">
                      <button
                        onClick={() => setShowDisclaimer(true)}
                        disabled={scansRemaining === 0}
                        className="flex items-center gap-2 bg-violet-500 hover:bg-violet-400 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold px-4 py-2 rounded-lg transition-colors text-sm"
                      >
                        <Play size={12} className="fill-current" />
                        {scansRemaining === 0 ? 'Limit reached' : 'Run scan'}
                      </button>
                      {scansRemaining !== null && (
                        <p className="text-xs text-slate-600 text-right">
                          {scansRemaining === 0
                            ? 'Limit reached · resets at midnight'
                            : `${scansRemaining} of 3 remaining today`}
                        </p>
                      )}
                      <p className="text-xs text-slate-700">Scans are compute-intensive · 3/account/day</p>
                    </div>
                  </div>
                </div>

                {/* Scan error banner */}
                {scanError && (
                  <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/8 border border-red-500/20 rounded-lg px-4 py-2.5">
                    <AlertTriangle size={13} className="shrink-0" />
                    {scanError}
                  </div>
                )}

                {/* Main grid */}
                <div>

                  {/* Environment table */}
                  <div className="rounded-xl border border-white/8 bg-[#111116] overflow-hidden">
                    <div className="px-4 py-3 border-b border-white/6 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-medium text-slate-400">Environment</p>
                        <p className="text-xs text-slate-700 mt-0.5">Single-region only · resources in other regions are not scanned</p>
                      </div>
                      <p className="text-xs text-slate-600">
                        {scanHistory.length === 0 ? 'No scan data yet' : `${checks.filter(c => c.status === 'VULNERABLE').length} issues · ${checks.filter(c => c.status === 'SAFE').length} passing`}
                      </p>
                    </div>
                    <div className="divide-y divide-white/4">
                      {SERVICE_ORDER.map(svc => {
                        const { label, Icon } = SERVICE_META[svc];
                        const checkId = `check_${svc === 'sg' ? 'ssh' : svc}`;
                        const check = checks.find(c => c.id === checkId);
                        const isVuln = check?.status === 'VULNERABLE';
                        const isSafe = check?.status === 'SAFE';
                        return (
                          <div key={svc} className={`flex items-center gap-3 px-4 py-3 transition-colors ${isVuln && scanHistory.length > 0 ? 'bg-red-950/10' : ''}`}>
                            <Icon size={13} className={isVuln && scanHistory.length > 0 ? 'text-red-400' : 'text-slate-700'} />
                            <span className={`text-sm flex-1 ${isVuln && scanHistory.length > 0 ? 'text-slate-200' : 'text-slate-600'}`}>{label}</span>
                            <p className="text-xs text-slate-600 flex-1 truncate">{scanHistory.length > 0 ? (check?.description ?? '') : ''}</p>
                            {isVuln && scanHistory.length > 0 && (
                              <span className="flex items-center gap-1.5 text-xs font-medium text-red-400">
                                <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" /> Vulnerable
                              </span>
                            )}
                            {scanHistory.length === 0 && (
                              <span className="text-xs text-slate-700">—</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>

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
                        {approvedItems.size} of {remediationPlan.length} approved for remediation
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={handleStop}
                      className="text-xs text-slate-500 hover:text-slate-300 border border-white/8 hover:border-white/15 px-3 py-2 rounded-lg transition-colors">
                      Cancel
                    </button>
                    {approvedItems.size < remediationPlan.length ? (
                      <button
                        onClick={() => setApprovedItems(new Set(remediationPlan.map(p => p.resource)))}
                        className="text-xs text-slate-400 hover:text-violet-300 border border-white/8 hover:border-violet-500/30 hover:bg-violet-500/5 px-3 py-2 rounded-lg transition-colors">
                        Approve all
                      </button>
                    ) : (
                      <button
                        onClick={() => setApprovedItems(new Set())}
                        className="text-xs text-slate-400 hover:text-red-400 border border-white/8 hover:border-red-700/30 px-3 py-2 rounded-lg transition-colors">
                        Clear all
                      </button>
                    )}
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
                    const info       = REMEDIATION_INFO[item.toolName];
                    const isApproved = approvedItems.has(item.resource);
                    const whyText    = resourceReasons[item.resource] || info?.risk || 'Vulnerability detected';
                    return (
                      <div key={i} className={`rounded-xl border transition-all duration-200 overflow-hidden ${
                        isApproved ? 'border-violet-700/40 bg-violet-950/10' : 'border-white/8 bg-[#111116]'
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
                            <p className="text-xs text-slate-400 mt-1 leading-relaxed">{whyText}</p>
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
                            {isApproved ? 'Approved ✓' : 'Approve'}
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

                {/* Action bar */}
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-semibold text-slate-100">Security Overview</h2>
                    {lastScan && (
                      <p className="text-xs text-slate-600 mt-0.5 font-mono">
                        {lastScan.id} · {new Date(lastScan.start_time).toLocaleString()}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg border ${
                      fixedCount > 0
                        ? 'text-violet-400 border-violet-700/40 bg-violet-950/20'
                        : 'text-emerald-400 border-emerald-700/40 bg-emerald-950/20'
                    }`}>
                      <CheckCircle size={11} />
                      {fixedCount > 0 ? `${fixedCount} ${fixedCount === 1 ? 'fix' : 'fixes'} applied` : 'No vulnerabilities found'}
                    </span>
                    <button onClick={startScan}
                      className="flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-4 py-2 rounded-lg transition-colors text-sm">
                      <Play size={12} className="fill-current" /> Scan again
                    </button>
                  </div>
                </div>

                {/* Results table */}
                <div className="rounded-xl border border-white/8 bg-[#111116] overflow-hidden">
                  <div className="px-4 py-3 border-b border-white/6">
                    <p className="text-xs font-medium text-slate-400">Scan results</p>
                  </div>
                  <div className="divide-y divide-white/4">
                    {SERVICE_ORDER.map(svc => {
                      const { label, Icon } = SERVICE_META[svc];
                      const items    = scanItems[svc] ?? [];
                      const vulns    = items.filter(i => i.status === 'vulnerable');
                      const hasData  = items.length > 0;
                      return (
                        <div key={svc} className={`flex items-center gap-3 px-4 py-3 ${hasData && vulns.length > 0 ? 'bg-red-950/10' : ''}`}>
                          <Icon size={13} className={hasData && vulns.length > 0 ? 'text-red-400' : hasData ? 'text-slate-400' : 'text-slate-700'} />
                          <span className="text-sm text-slate-300 w-28 shrink-0">{label}</span>
                          <div className="flex-1 flex flex-wrap gap-1.5">
                            {items.map((item, i) => (
                              <span key={i} className={`text-xs font-mono px-2 py-0.5 rounded border ${
                                item.status === 'vulnerable'
                                  ? 'text-red-400 border-red-800/40 bg-red-950/20'
                                  : 'text-slate-500 border-white/6 bg-white/2'
                              }`}>
                                {item.status === 'vulnerable' ? '⚠ ' : '✓ '}{item.resource}
                              </span>
                            ))}
                            {!hasData && <span className="text-xs text-slate-700">—</span>}
                          </div>
                          {hasData && vulns.length > 0 && (
                            <span className="text-xs text-red-400 font-medium shrink-0">{vulns.length} issue{vulns.length !== 1 ? 's' : ''}</span>
                          )}
                          {hasData && vulns.length === 0 && (
                            <span className="text-xs text-slate-600 shrink-0">Clean</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* ── Post-scan feedback ── */}
            {scanState === 'complete' && lastScan && feedbackScanId !== lastScan.id && (
              <div className="rounded-xl border border-white/8 bg-[#111116] p-5">
                {feedbackSubmitted ? (
                  <div className="flex items-center gap-2 text-sm text-slate-400">
                    <CheckCircle size={15} className="text-violet-400 shrink-0" />
                    Thanks for your feedback!
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between mb-4">
                      <p className="text-sm font-medium text-slate-300">How was this scan?</p>
                      <button onClick={() => setFeedbackScanId(lastScan.id)} className="text-xs text-slate-600 hover:text-slate-400 transition-colors">Skip</button>
                    </div>
                    <div className="flex items-center gap-1 mb-4">
                      {[1, 2, 3, 4, 5].map(star => (
                        <button
                          key={star}
                          onClick={() => setFeedbackRating(star)}
                          onMouseEnter={() => setFeedbackHover(star)}
                          onMouseLeave={() => setFeedbackHover(0)}
                          className="text-2xl transition-colors leading-none"
                        >
                          <span className={(feedbackHover || feedbackRating) >= star ? 'text-yellow-400' : 'text-slate-700'}>★</span>
                        </button>
                      ))}
                    </div>
                    {feedbackRating > 0 && (
                      <>
                        <textarea
                          value={feedbackMessage}
                          onChange={e => setFeedbackMessage(e.target.value)}
                          placeholder="Anything else to share? (optional)"
                          rows={2}
                          className="w-full rounded-lg px-3 py-2 text-sm text-slate-300 placeholder-slate-600 resize-none focus:outline-none focus:ring-2 focus:ring-violet-500/30 transition-colors mb-3"
                          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
                        />
                        <button
                          onClick={async () => {
                            const token = await getToken();
                            await fetch(`${API}/api/feedback`, {
                              method: 'POST',
                              headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                              body: JSON.stringify({ scan_id: lastScan.id, account_name: selectedAccount, rating: feedbackRating, message: feedbackMessage }),
                            }).catch(() => {});
                            setFeedbackSubmitted(true);
                            setFeedbackScanId(lastScan.id);
                          }}
                          className="text-xs bg-violet-500 hover:bg-violet-400 text-white font-medium px-4 py-2 rounded-lg transition-colors"
                        >
                          Submit feedback
                        </button>
                      </>
                    )}
                  </>
                )}
              </div>
            )}

          </>)}


          {/* ── History ───────────────────────────────────────────────────────── */}
          {view === 'history' && (<>

            {/* Summary stats */}
            <div className="grid grid-cols-4 gap-4">
              {[
                { label: 'Total scans',         value: String(metrics?.total_scans ?? '—'), sub: 'all time',        Icon: Activity,   color: 'text-slate-100'  },
                { label: 'Success rate',        value: metrics?.success_rate ?? '—',        sub: 'scans completed',   Icon: TrendingUp, color: 'text-violet-400' },
                { label: 'Avg fix time',        value: metrics?.avg_mttr ?? '—',            sub: 'per scan',        Icon: Clock,      color: 'text-slate-100'  },
                { label: 'Verification rate',   value: metrics?.verification_pass_rate ?? 'N/A', sub: 'fixes confirmed', Icon: ShieldCheck, color: 'text-violet-400' },
              ].map(({ label, value, sub, Icon, color }) => (
                <div key={label} className="bg-[#111116] border border-white/8 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-xs text-slate-500 font-medium">{label}</p>
                    <Icon size={14} className="text-slate-700" />
                  </div>
                  <p className={`text-2xl font-bold tabular-nums ${color}`} style={{ fontFamily: "'JetBrains Mono', monospace" }}>{value}</p>
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
                            <div className="flex items-center gap-2">
                              <p className="text-xs text-slate-400">{new Date(scan.start_time).toLocaleString()}</p>
                              <span className="text-xs px-1.5 py-0.5 rounded font-medium text-slate-400 border border-white/8 bg-white/4">{scan.account_name || 'Default'}</span>
                            </div>
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

          {/* ── SETTINGS ─────────────────────────────────────────────────────── */}
          {view === 'settings' && (
            <div className="space-y-6 max-w-2xl">

              {/* Connected accounts */}
              <div className="rounded-xl border border-white/8 bg-[#111116] overflow-hidden">
                <div className="px-5 py-4 border-b border-white/6">
                  <p className="text-sm font-semibold text-slate-100">Connected AWS accounts</p>
                  <p className="text-xs text-slate-600 mt-0.5">Disconnecting removes the credentials from Remedi immediately.</p>
                </div>
                <div className="divide-y divide-white/4">
                  {accounts.length === 0 ? (
                    <div className="px-5 py-6 flex flex-col items-center gap-2">
                      <p className="text-sm text-slate-600">No AWS accounts connected.</p>
                      <Link href="/onboarding" className="text-xs text-violet-400 hover:text-violet-300 transition-colors">Connect an account →</Link>
                    </div>
                  ) : (
                    accounts.map(a => (
                      <div key={a.account_name} className="flex items-center justify-between px-5 py-3.5">
                        <div>
                          <p className="text-sm font-medium text-slate-200">{a.account_name}</p>
                          {a.account_name === selectedAccount && credentialUser && (
                            <p className="text-xs text-slate-600 font-mono mt-0.5">{credentialUser}</p>
                          )}
                        </div>
                        <button
                          onClick={() => handleDeleteAccount(a.account_name)}
                          disabled={scanState === 'scanning' || scanState === 'remediating'}
                          className="text-xs text-slate-500 hover:text-red-400 border border-white/8 hover:border-red-500/30 hover:bg-red-500/5 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          Disconnect
                        </button>
                      </div>
                    ))
                  )}
                </div>
                {accounts.length > 0 && accounts.length < 3 && (
                  <div className="px-5 py-3 border-t border-white/6">
                    <Link href="/onboarding" className="text-xs text-violet-400 hover:text-violet-300 transition-colors">+ Connect another account</Link>
                  </div>
                )}
              </div>

              {/* Protected IAM users */}
              <div className="rounded-xl border border-white/8 bg-[#111116] overflow-hidden">
                <div className="px-5 py-4 border-b border-white/6">
                  <p className="text-sm font-semibold text-slate-100">Protected IAM users</p>
                  <p className="text-xs text-slate-600 mt-0.5">These users will never be modified or removed by Remedi during remediation.</p>
                </div>
                <div className="divide-y divide-white/4">
                  {/* Auto-protected credential user */}
                  {credentialUser && (
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div className="flex items-center gap-3">
                        <Lock size={12} className="text-slate-600 shrink-0" />
                        <span className="text-sm font-mono text-slate-400">{credentialUser}</span>
                      </div>
                      <span className="text-xs text-slate-600 border border-white/6 px-2 py-0.5 rounded-full">auto-protected</span>
                    </div>
                  )}
                  {/* Selectable users */}
                  {iamUsers.filter(u => u !== credentialUser).length === 0 ? (
                    <div className="px-5 py-4">
                      <p className="text-xs text-slate-600">{iamUsers.length === 0 ? 'Connect an AWS account to load IAM users.' : 'No other IAM users in this account.'}</p>
                    </div>
                  ) : (
                    iamUsers.filter(u => u !== credentialUser).map(u => {
                      const checked = protectedUsers.includes(u);
                      return (
                        <label key={u} className="flex items-center justify-between px-5 py-3.5 cursor-pointer hover:bg-white/2 transition-colors">
                          <span className="text-sm font-mono text-slate-300">{u}</span>
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => setProtectedUsers(prev => checked ? prev.filter(x => x !== u) : [...prev, u])}
                            className="accent-violet-500 w-4 h-4"
                          />
                        </label>
                      );
                    })
                  )}
                </div>
                {protectedUsers.length > 0 && (
                  <div className="px-5 py-3 border-t border-white/6 bg-violet-500/5">
                    <p className="text-xs text-violet-400">{protectedUsers.length} user{protectedUsers.length > 1 ? 's' : ''} protected · applied to next scan</p>
                  </div>
                )}
              </div>

              {/* Danger zone */}
              <div className="rounded-xl border border-red-500/20 bg-red-950/5 overflow-hidden">
                <div className="px-5 py-4 border-b border-red-500/10">
                  <p className="text-sm font-semibold text-red-400">Danger zone</p>
                </div>
                <div className="px-5 py-4 flex items-start justify-between gap-6">
                  <div>
                    <p className="text-sm font-medium text-slate-200">Delete account</p>
                    <p className="text-xs text-slate-600 mt-0.5">Permanently deletes your Remedi account and all connected AWS credentials. This cannot be undone.</p>
                  </div>
                  {confirmDelete ? (
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-xs text-slate-500">Are you sure?</span>
                      <button
                        onClick={async () => {
                          const token = await getToken();
                          await fetch(`${API}/api/user`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
                          signOut({ redirectUrl: '/' });
                        }}
                        className="text-xs bg-red-500 hover:bg-red-400 text-white px-3 py-1.5 rounded-lg transition-colors font-medium"
                      >
                        Yes, delete
                      </button>
                      <button
                        onClick={() => setConfirmDelete(false)}
                        className="text-xs text-slate-500 hover:text-slate-300 px-3 py-1.5 rounded-lg border border-white/8 transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setConfirmDelete(true)}
                      className="shrink-0 text-xs text-red-400 hover:text-red-300 border border-red-500/25 hover:border-red-500/50 hover:bg-red-500/5 px-3 py-1.5 rounded-lg transition-colors"
                    >
                      Delete account
                    </button>
                  )}
                </div>
              </div>

              {/* Support / Contact */}
              <div className="rounded-xl border border-white/8 bg-[#111116] overflow-hidden">
                <div className="px-5 py-4 border-b border-white/6 flex items-center justify-between">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">Get in touch</p>
                    <p className="text-xs text-slate-600 mt-0.5">Questions, bugs, or ideas? Reach out directly.</p>
                  </div>
                  <Link href="/developer" className="text-xs text-violet-400 hover:text-violet-300 transition-colors">Developer page →</Link>
                </div>
                <div className="px-5 py-4 flex flex-col gap-3">
                  <a href="mailto:glen.louis08@gmail.com" target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-3 text-sm text-slate-400 hover:text-violet-400 transition-colors group">
                    <span className="w-7 h-7 rounded-lg flex items-center justify-center border border-white/8 group-hover:border-violet-500/30 transition-colors text-xs">✉</span>
                    glen.louis08@gmail.com
                  </a>
                  <a href="https://www.linkedin.com/in/marian-glen-louis" target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-3 text-sm text-slate-400 hover:text-violet-400 transition-colors group">
                    <span className="w-7 h-7 rounded-lg flex items-center justify-center border border-white/8 group-hover:border-violet-500/30 transition-colors text-xs">in</span>
                    LinkedIn
                  </a>
                  <a href="https://github.com/glenlouis8" target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-3 text-sm text-slate-400 hover:text-violet-400 transition-colors group">
                    <span className="w-7 h-7 rounded-lg flex items-center justify-center border border-white/8 group-hover:border-violet-500/30 transition-colors text-xs">⌥</span>
                    GitHub
                  </a>
                </div>
              </div>

            </div>
          )}

        </div>
      </main>
    </div>
  );
}
