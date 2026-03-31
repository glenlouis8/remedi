'use client';

import { useState, useRef, useEffect } from 'react';
import { useAuth, useClerk } from '@clerk/nextjs';
import Link from 'next/link';
import {
  ShieldCheck, ShieldAlert, Play, Square, CheckCircle, XCircle,
  AlertTriangle, ChevronRight, Users, HardDrive, Globe, Shield,
  Server, Database, Zap, FileText, Lock, ChevronDown,
} from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ComplianceCheck { id: string; name: string; description: string; status: 'SAFE' | 'VULNERABLE' }
interface CisScore { score: number; total: number; percentage: number }
interface SecurityMetrics { avg_mttr: string; success_rate: string; total_scans: number }
interface ScanHistoryItem { id: string; start_time: string; findings_count: number; remediations_count: number; status: string; verified: boolean }
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

// ─── Remediation metadata ─────────────────────────────────────────────────────

const REMEDIATION_INFO: Record<string, { title: string; icon: string; risk: string }> = {
  restrict_iam_user:             { icon: '🔑', title: 'Revoke Admin Privileges',   risk: 'User has full AWS access'                   },
  remediate_s3:                  { icon: '🪣', title: 'Block Public S3 Access',    risk: 'Bucket readable by anyone on the internet'  },
  remediate_vpc_flow_logs:       { icon: '🌐', title: 'Enable Network Logging',    risk: 'VPC has no flow logs'                       },
  revoke_security_group_ingress: { icon: '🔒', title: 'Close Port 22 to Internet', risk: 'SSH open to 0.0.0.0/0'                     },
  enforce_imdsv2:                { icon: '💻', title: 'Enforce IMDSv2',            risk: 'EC2 vulnerable to SSRF via IMDSv1'          },
  stop_instance:                 { icon: '⛔', title: 'Quarantine EC2 Instance',   risk: 'Compromised instance posing active threat'  },
  remediate_rds_public_access:   { icon: '🗄️', title: 'Make RDS Private',         risk: 'Database reachable from the internet'       },
  remediate_lambda_role:         { icon: '⚡', title: 'Fix Lambda Permissions',    risk: 'Lambda has admin-level AWS access'          },
  remediate_cloudtrail:          { icon: '📋', title: 'Enable CloudTrail Logging', risk: 'No audit log of API activity'               },
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

// ─── Service card ─────────────────────────────────────────────────────────────

function ServiceCard({ svc, items, isActive, scanState }: {
  svc: ServiceKey;
  items: ScanItem[];
  isActive: boolean;
  scanState: ScanState;
}) {
  const { label, Icon } = SERVICE_META[svc];
  const hasData   = items.length > 0;
  const vulnCount = items.filter(i => i.status === 'vulnerable').length;
  const isPending = !hasData && !isActive && scanState === 'scanning';

  let cardClass = 'bg-white border-slate-200';
  if (isActive)                  cardClass = 'bg-emerald-50 border-emerald-300 shadow-sm';
  else if (hasData && vulnCount) cardClass = 'bg-red-50 border-red-200';
  else if (hasData)              cardClass = 'bg-emerald-50 border-emerald-200';
  else if (isPending)            cardClass = 'bg-slate-50 border-slate-100 opacity-40';

  return (
    <div className={`rounded-xl border p-4 transition-all duration-500 ${cardClass}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <Icon size={14} className={
            isActive           ? 'text-emerald-600' :
            hasData && vulnCount ? 'text-red-500' :
            hasData            ? 'text-emerald-600' :
            'text-slate-300'
          } />
          <span className={`text-sm font-medium ${
            isActive || hasData ? 'text-slate-900' : 'text-slate-300'
          }`}>{label}</span>
        </div>

        {isActive && (
          <span className="flex items-center gap-1 text-xs text-emerald-600">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            scanning
          </span>
        )}
        {!isActive && hasData && vulnCount > 0 && (
          <span className="text-xs text-red-600 font-medium">{vulnCount} issue{vulnCount !== 1 ? 's' : ''}</span>
        )}
        {!isActive && hasData && vulnCount === 0 && (
          <CheckCircle size={13} className="text-emerald-500" />
        )}
      </div>

      {hasData ? (
        <div className="space-y-1.5 mt-2">
          {items.map((item, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className={`shrink-0 text-xs ${item.status === 'vulnerable' ? 'text-red-500' : 'text-emerald-600'}`}>
                {item.status === 'vulnerable' ? '⚠' : '✓'}
              </span>
              <span className="text-xs text-slate-500 font-mono truncate">{item.resource}</span>
            </div>
          ))}
        </div>
      ) : isActive ? (
        <div className="space-y-1.5 mt-2">
          {[1, 2].map(i => (
            <div key={i} className="h-3 bg-emerald-200/60 rounded animate-pulse" style={{ width: `${50 + i * 20}%` }} />
          ))}
        </div>
      ) : (
        <p className="text-xs text-slate-300 mt-1">—</p>
      )}
    </div>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { getToken } = useAuth();
  const { signOut } = useClerk();

  const [cisScore, setCisScore]       = useState<CisScore | null>(null);
  const [checks, setChecks]           = useState<ComplianceCheck[]>([]);
  const [metrics, setMetrics]         = useState<SecurityMetrics | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);

  const [scanState, setScanState]               = useState<ScanState>('idle');
  const [scanItems, setScanItems]               = useState<Partial<Record<ServiceKey, ScanItem[]>>>({});
  const [activeService, setActiveService]       = useState<ServiceKey | null>(null);
  const [remediationPlan, setRemediationPlan]   = useState<{ toolName: string; resource: string }[]>([]);
  const [remediationSteps, setRemediationSteps] = useState<RemediationStep[]>([]);

  // Protected IAM users
  const [iamUsers, setIamUsers]               = useState<string[]>([]);
  const [credentialUser, setCredentialUser]   = useState<string | null>(null);
  const [protectedUsers, setProtectedUsers]   = useState<string[]>([]);
  const [dropdownOpen, setDropdownOpen]       = useState(false);
  const dropdownRef                           = useRef<HTMLDivElement>(null);

  const abortRef = useRef<AbortController | null>(null);

  // ── Click outside dropdown ─────────────────────────────────────────────────

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // ── Polling ────────────────────────────────────────────────────────────────

  useEffect(() => {
    const h = async () => ({ Authorization: `Bearer ${await getToken()}` });

    // Fetch IAM users once on mount
    const fetchIamUsers = async () => {
      try {
        const res = await fetch(`${API}/api/iam/users`, { headers: await h() });
        if (res.ok) {
          const data = await res.json();
          setIamUsers(data.users ?? []);
          setCredentialUser(data.credential_user ?? null);
        }
      } catch { /* ignore */ }
    };
    fetchIamUsers();

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

  // ── Scan ───────────────────────────────────────────────────────────────────

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
        body: JSON.stringify({ protected_users: protectedUsers }),
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

          if (raw.includes('❌ Error executing')) {
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
    }
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

  const scoreColor = cisScore
    ? cisScore.percentage >= 80 ? 'text-emerald-600' : cisScore.percentage >= 50 ? 'text-amber-600' : 'text-red-600'
    : 'text-slate-300';
  const scoreLabel = cisScore
    ? cisScore.percentage >= 80 ? 'Compliant' : cisScore.percentage >= 50 ? 'Needs attention' : 'At risk'
    : '—';

  const isScanning = scanState === 'scanning' || scanState === 'awaiting_approval' || scanState === 'complete';

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">

      {/* Nav */}
      <nav className="flex items-center justify-between px-8 py-4 bg-white border-b border-slate-200">
        <Link href="/" className="flex items-center gap-2">
          <ShieldCheck className="text-emerald-600" size={18} />
          <span className="font-semibold tracking-tight text-slate-900">Remedi</span>
        </Link>
        <div className="flex items-center gap-4">
          {(scanState === 'scanning' || scanState === 'remediating') ? (
            <button onClick={handleStop} className="flex items-center gap-2 text-sm text-red-600 border border-red-200 bg-red-50 px-4 py-2 rounded-lg hover:bg-red-100 transition-colors">
              <Square size={12} className="fill-current" /> Stop
            </button>
          ) : (
            <button
              onClick={startScan}
              disabled={scanState === 'awaiting_approval'}
              className="flex items-center gap-2 text-sm bg-emerald-500 hover:bg-emerald-600 disabled:opacity-40 text-white font-semibold px-4 py-2 rounded-lg transition-colors"
            >
              <Play size={12} className="fill-current" />
              {scanState === 'complete' ? 'Scan again' : 'Run scan'}
            </button>
          )}
          <button
            onClick={() => signOut({ redirectUrl: '/' })}
            className="text-sm text-slate-400 hover:text-slate-700 transition-colors"
          >
            Sign out
          </button>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">

        {/* ── Stats row ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <p className="text-xs text-slate-400 font-medium mb-3">CIS Score</p>
            <div className="flex items-end gap-2">
              <span className={`text-4xl font-bold ${scoreColor}`}>{cisScore?.score ?? '—'}</span>
              <span className="text-slate-400 text-lg mb-1">/{cisScore?.total ?? 8}</span>
            </div>
            <p className={`text-xs mt-1 font-medium ${scoreColor}`}>{scoreLabel}</p>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <p className="text-xs text-slate-400 font-medium mb-3">Total scans</p>
            <p className="text-3xl font-bold text-slate-900">{metrics?.total_scans ?? '—'}</p>
            <p className="text-xs text-slate-400 mt-1">all time</p>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <p className="text-xs text-slate-400 font-medium mb-3">Success rate</p>
            <p className="text-3xl font-bold text-slate-900">{metrics?.success_rate ?? '—'}</p>
            <p className="text-xs text-slate-400 mt-1">fixes applied</p>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <p className="text-xs text-slate-400 font-medium mb-3">Avg. time to fix</p>
            <p className="text-3xl font-bold text-slate-900">{metrics?.avg_mttr ?? '—'}</p>
            <p className="text-xs text-slate-400 mt-1">after approval</p>
          </div>
        </div>

        {/* ── Protected users dropdown ── always visible when idle or complete ── */}
        {(scanState === 'idle' || scanState === 'complete') && iamUsers.length > 0 && (
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-slate-900 mb-0.5">Protected IAM users</p>
                <p className="text-xs text-slate-400">
                  Selected users will be audited but never modified.
                  {credentialUser && <> <span className="font-mono text-slate-500">{credentialUser}</span> is always protected (your Remedi credentials).</>}
                </p>
              </div>

              {/* Dropdown */}
              <div className="relative shrink-0" ref={dropdownRef}>
                <button
                  onClick={() => setDropdownOpen(v => !v)}
                  className="flex items-center gap-2 text-sm border border-slate-200 bg-slate-50 hover:bg-slate-100 rounded-lg px-3 py-2 transition-colors min-w-[160px] justify-between"
                >
                  <span className="text-slate-700">
                    {protectedUsers.length === 0 ? 'Select users…' : `${protectedUsers.length} protected`}
                  </span>
                  <ChevronDown size={14} className={`text-slate-400 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
                </button>

                {dropdownOpen && (
                  <div className="absolute right-0 top-full mt-1 w-64 bg-white border border-slate-200 rounded-xl shadow-lg z-10 overflow-hidden">
                    {/* Auto-protected credential user */}
                    {credentialUser && (
                      <div className="flex items-center gap-3 px-4 py-2.5 bg-slate-50 border-b border-slate-100">
                        <Lock size={12} className="text-slate-400 shrink-0" />
                        <span className="text-sm font-mono text-slate-500 flex-1 truncate">{credentialUser}</span>
                        <span className="text-xs text-slate-400">auto</span>
                      </div>
                    )}
                    {/* Selectable users */}
                    <div className="max-h-52 overflow-y-auto">
                      {iamUsers.filter(u => u !== credentialUser).map(u => {
                        const checked = protectedUsers.includes(u);
                        return (
                          <label key={u} className="flex items-center gap-3 px-4 py-2.5 hover:bg-slate-50 cursor-pointer transition-colors">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => setProtectedUsers(prev =>
                                checked ? prev.filter(x => x !== u) : [...prev, u]
                              )}
                              className="accent-emerald-500"
                            />
                            <span className="text-sm font-mono text-slate-700 truncate">{u}</span>
                          </label>
                        );
                      })}
                      {iamUsers.filter(u => u !== credentialUser).length === 0 && (
                        <p className="text-xs text-slate-400 px-4 py-3">No other IAM users found.</p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ── Idle call-to-action ── */}
        {scanState === 'idle' && (
          <div className="bg-white border border-slate-200 rounded-xl p-10 flex flex-col items-center text-center shadow-sm">
            <ShieldCheck className="text-emerald-500 mb-4" size={36} />
            <h2 className="text-lg font-semibold text-slate-900 mb-2">Ready to scan</h2>
            <p className="text-slate-500 text-sm mb-6 max-w-sm">
              Remedi will audit your AWS account across IAM, S3, EC2, VPC, RDS, Lambda, and CloudTrail — then show you exactly what to fix.
            </p>
            <button
              onClick={startScan}
              className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-600 text-white font-semibold px-6 py-2.5 rounded-lg transition-colors text-sm"
            >
              <Play size={13} className="fill-current" /> Start scan
            </button>
          </div>
        )}

        {/* ── Service cards ── */}
        {isScanning && (
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                {scanState === 'complete' ? 'Scan results' : 'Live scan'}
              </h2>
              {scanState === 'scanning' && (
                <span className="flex items-center gap-2 text-xs text-emerald-600 font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  Scanning…
                </span>
              )}
              {scanState === 'complete' && (
                <button onClick={startScan} className="text-xs text-slate-400 hover:text-slate-700 flex items-center gap-1 transition-colors">
                  Scan again <ChevronRight size={12} />
                </button>
              )}
            </div>

            {/* Shimmer progress bar */}
            {scanState === 'scanning' && (
              <div className="w-full h-0.5 rounded-full bg-emerald-100 overflow-hidden mb-4">
                <div className="h-full shimmer-bar rounded-full" />
              </div>
            )}

            {/* Cards with scanning beam overlay */}
            <div className="relative rounded-2xl overflow-hidden">
              {/* Beam */}
              {scanState === 'scanning' && (
                <div
                  className="scan-beam pointer-events-none absolute inset-x-0 z-10"
                  style={{
                    height: '2px',
                    background: 'linear-gradient(90deg, transparent 0%, #6ee7b7 20%, #10b981 50%, #6ee7b7 80%, transparent 100%)',
                    boxShadow: '0 0 12px 4px rgba(16, 185, 129, 0.35), 0 0 40px 8px rgba(16, 185, 129, 0.12)',
                  }}
                />
              )}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-0.5">
                {SERVICE_ORDER.map(svc => (
                  <ServiceCard
                    key={svc}
                    svc={svc}
                    items={scanItems[svc] ?? []}
                    isActive={activeService === svc}
                    scanState={scanState}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Awaiting approval ── */}
        {scanState === 'awaiting_approval' && (
          <div className="bg-white border border-amber-200 rounded-xl overflow-hidden shadow-sm">
            <div className="flex items-center justify-between px-6 py-4 border-b border-amber-100 bg-amber-50">
              <div className="flex items-center gap-3">
                <AlertTriangle className="text-amber-500" size={18} />
                <div>
                  <h2 className="font-semibold text-sm text-amber-800">Approval required</h2>
                  <p className="text-xs text-amber-600">{remediationPlan.length} issue{remediationPlan.length !== 1 ? 's' : ''} found — review and approve fixes</p>
                </div>
              </div>
              <button
                onClick={handleApprove}
                className="bg-amber-500 hover:bg-amber-600 text-white font-semibold text-sm px-5 py-2 rounded-lg transition-colors"
              >
                Approve all fixes
              </button>
            </div>
            <div className="divide-y divide-slate-100">
              {remediationPlan.map((item, i) => {
                const info = REMEDIATION_INFO[item.toolName];
                return (
                  <div key={i} className="flex items-center gap-4 px-6 py-3">
                    <span className="text-xl">{info?.icon ?? '🔧'}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-slate-900">{info?.title ?? item.toolName}</p>
                      <p className="text-xs text-slate-400 truncate">{info?.risk}</p>
                    </div>
                    <span className="text-xs font-mono text-red-600 bg-red-50 border border-red-200 px-2 py-0.5 rounded shrink-0">{item.resource}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Remediating ── */}
        {scanState === 'remediating' && (
          <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-sm text-slate-900">Applying fixes…</h2>
              <span className="text-xs text-slate-400">
                {remediationSteps.filter(s => s.status === 'success').length}/{remediationSteps.length} done
              </span>
            </div>
            <div className="space-y-2">
              {remediationSteps.map((step, i) => {
                const info = REMEDIATION_INFO[step.funcName];
                return (
                  <div key={i} className={`flex items-center gap-3 px-4 py-3 rounded-lg border text-sm transition-all ${
                    step.status === 'success' ? 'border-emerald-200 bg-emerald-50' :
                    step.status === 'error'   ? 'border-red-200 bg-red-50' :
                                                'border-amber-200 bg-amber-50'
                  }`}>
                    <span className="text-base">{info?.icon ?? '🔧'}</span>
                    <span className="flex-1 text-slate-700">{info?.title ?? step.funcName}</span>
                    <span className="text-xs font-mono text-slate-400">{step.resource}</span>
                    {step.status === 'success' && <CheckCircle size={14} className="text-emerald-500 shrink-0" />}
                    {step.status === 'error'   && <XCircle    size={14} className="text-red-500 shrink-0" />}
                    {step.status === 'running' && <span className="w-3 h-3 rounded-full border-2 border-amber-500 border-t-transparent animate-spin shrink-0" />}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── CIS Controls ── */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">CIS AWS Foundations Benchmark</h2>
            {cisScore && (
              <span className={`text-xs font-medium ${scoreColor}`}>{cisScore.score}/{cisScore.total} controls passing</span>
            )}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {checks.map(check => (
              <div key={check.id} className={`rounded-xl border p-4 transition-all shadow-sm ${
                check.status === 'VULNERABLE'
                  ? 'bg-red-50 border-red-200'
                  : 'bg-white border-slate-200'
              }`}>
                <div className="flex items-center justify-between mb-3">
                  <ShieldAlert size={14} className={check.status === 'VULNERABLE' ? 'text-red-500' : 'text-emerald-500'} />
                  <span className={`text-xs font-medium ${check.status === 'VULNERABLE' ? 'text-red-600' : 'text-emerald-600'}`}>
                    {check.status === 'VULNERABLE' ? 'Vulnerable' : 'Secure'}
                  </span>
                </div>
                <p className="text-sm font-medium text-slate-900 leading-tight mb-1">{check.name}</p>
                <p className="text-xs text-slate-500 leading-tight line-clamp-2">{check.description}</p>
              </div>
            ))}
            {checks.length === 0 && [1,2,3,4,5,6,7,8].map(i => (
              <div key={i} className="h-24 bg-slate-100 border border-slate-200 rounded-xl animate-pulse" />
            ))}
          </div>
        </div>

        {/* ── Scan history ── */}
        {scanHistory.length > 0 && (
          <div>
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-4">Recent scans</h2>
            <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 overflow-hidden shadow-sm">
              {scanHistory.map(scan => (
                <div key={scan.id} className="flex items-center justify-between px-5 py-3">
                  <div>
                    <p className="text-sm text-slate-700 font-mono">{scan.id}</p>
                    <p className="text-xs text-slate-400 mt-0.5">{new Date(scan.start_time).toLocaleString()}</p>
                  </div>
                  <div className="flex items-center gap-6 text-sm">
                    <span className="text-slate-500">{scan.findings_count ?? 0} findings</span>
                    <span className="text-emerald-600 font-medium">{Math.min(scan.remediations_count ?? 0, scan.findings_count ?? 0)} fixed</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                      scan.verified ? 'bg-emerald-100 text-emerald-700' :
                      scan.status === 'COMPLETED' ? 'bg-blue-100 text-blue-700' :
                      'bg-slate-100 text-slate-500'
                    }`}>
                      {scan.verified ? '✓ Verified' : scan.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </main>
    </div>
  );
}
