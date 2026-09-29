'use client';

// Public demo: replays a recorded run of the real pipeline (see replay.ts and
// scripts/record_demo.py). No backend, no credentials, no AWS.
//
// Line parsing and the icon/title tables mirror app/dashboard/page.tsx, which
// reads the same line format live. If that format changes, re-record the demo
// and update both.

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import {
  ShieldCheck, Play, CheckCircle, XCircle, AlertTriangle, Users, HardDrive,
  Globe, Shield, Server, Database, Zap, FileText, ArrowLeft, ExternalLink, Terminal,
} from 'lucide-react';
import { GATE_LINE, loadRecording, replay } from './replay';

const REPO = 'https://github.com/glenlouis8/remedi';

// ─── Types and lookup tables ─────────────────────────────────────────────────

type ScanState = 'idle' | 'scanning' | 'awaiting_approval' | 'remediating' | 'complete';
type ServiceKey = 'iam' | 's3' | 'vpc' | 'sg' | 'ec2' | 'rds' | 'lambda' | 'cloudtrail';
interface ScanItem { resource: string; status: 'ok' | 'vulnerable'; msg: string }
interface PlanItem { resource: string; toolName: string }
interface Step { funcName: string; resource: string; status: 'running' | 'success' | 'error' }

const SERVICE_META: Record<ServiceKey, { label: string; Icon: React.ComponentType<{ size?: number; className?: string }> }> = {
  iam:        { label: 'IAM',        Icon: Users     },
  s3:         { label: 'S3',         Icon: HardDrive },
  vpc:        { label: 'VPC',        Icon: Globe     },
  sg:         { label: 'Sec Groups', Icon: Shield    },
  ec2:        { label: 'EC2',        Icon: Server    },
  rds:        { label: 'RDS',        Icon: Database  },
  lambda:     { label: 'Lambda',     Icon: Zap       },
  cloudtrail: { label: 'CloudTrail', Icon: FileText  },
};
const SERVICE_ORDER: ServiceKey[] = ['iam', 's3', 'vpc', 'sg', 'ec2', 'rds', 'lambda', 'cloudtrail'];

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

const parseRemediationItem = (line: string): PlanItem | null => {
  const actionMatch = line.match(/ACTION: I will call `?(\w+)`?/);
  if (!actionMatch) return null;
  const toolName = actionMatch[1];
  const patterns = [/\[CRITICAL\] (.*?) (?:is vulnerable|has |allows)/, /\[POLICY VIOLATION\] User `?(.*?)`? /, /\[HIGH\] (.*?) (?:has |is )/];
  let resource = '';
  for (const p of patterns) { const m = line.match(p); if (m) { resource = m[1].trim(); break; } }
  return { toolName, resource: resource || toolName };
};

const RAW_LOG_LIMIT = 80;

// ─── Page ────────────────────────────────────────────────────────────────────

export default function DemoPage() {
  const [scanState, setScanState] = useState<ScanState>('idle');
  const [scanItems, setScanItems] = useState<Partial<Record<ServiceKey, ScanItem[]>>>({});
  const [activeService, setActiveService] = useState<ServiceKey | null>(null);
  const [plan, setPlan] = useState<PlanItem[]>([]);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [steps, setSteps] = useState<Step[]>([]);
  const [verdict, setVerdict] = useState<'verified' | 'failed' | null>(null);
  const [rawLines, setRawLines] = useState<string[]>([]);
  const [showRaw, setShowRaw] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSuccess, setShowSuccess] = useState(false);

  const abortRef = useRef<AbortController | null>(null);
  const approveRef = useRef<(() => void) | null>(null);
  const itemsRef = useRef<Partial<Record<ServiceKey, ScanItem[]>>>({});
  const rawRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);
  useEffect(() => {
    if (showRaw && rawRef.current) rawRef.current.scrollTop = rawRef.current.scrollHeight;
  }, [rawLines, showRaw]);

  const handleLine = (raw: string) => {
    setRawLines(prev => [...prev.slice(-(RAW_LOG_LIMIT - 1)), raw]);

    if (raw.startsWith('[SCAN] ')) {
      try {
        const ev = JSON.parse(raw.slice(7));
        const svc = ev.service as ServiceKey;
        if (!SERVICE_META[svc]) return;
        setActiveService(svc);
        const list = itemsRef.current[svc] ?? (itemsRef.current[svc] = []);
        const existing = list.find(i => i.resource === ev.resource);
        if (existing) {
          existing.status = ev.status;
          if (ev.msg) existing.msg = ev.msg;
        } else {
          list.push({ resource: ev.resource, status: ev.status, msg: ev.msg ?? '' });
        }
        setScanItems({ ...itemsRef.current });
        if (ev.status === 'vulnerable' && ev.msg) setReasons(prev => ({ ...prev, [ev.resource]: ev.msg }));
      } catch { /* malformed line */ }
      return;
    }

    if (raw.includes(GATE_LINE)) {
      setActiveService(null);
      setScanState('awaiting_approval');
      return;
    }

    if (raw.includes('[CRITICAL]') || raw.includes('[POLICY VIOLATION]') || raw.includes('[HIGH]')) {
      const item = parseRemediationItem(raw);
      if (item) {
        setPlan(prev => prev.some(p => p.resource === item.resource && p.toolName === item.toolName) ? prev : [...prev, item]);
      }
    }

    const exec = raw.match(/\[EXEC\] Calling (\w+) with \{(.+)\}/);
    if (exec) {
      // args look like {'user_name': 'dev-intern'}: the resource is the value, not the key
      const quoted = [...exec[2].matchAll(/['"]([\w\-.]+)['"]/g)];
      const resource = quoted[quoted.length - 1]?.[1] || exec[1];
      setScanState('remediating');
      setSteps(prev => [...prev, { funcName: exec[1], resource, status: 'running' }]);
    }

    // Fixes run in parallel and report in completion order; the log lines don't
    // reliably carry the resource name, so results tick steps off top to bottom.
    if ((raw.includes('✅') && raw.includes('SUCCESS')) || raw.includes('❌')) {
      const status = raw.includes('❌') ? 'error' : 'success';
      setSteps(prev => {
        const i = prev.findIndex(s => s.status === 'running');
        if (i < 0) return prev;
        const next = [...prev];
        next[i] = { ...next[i], status };
        return next;
      });
    }

    if (raw.includes('MISSION ACCOMPLISHED')) setVerdict('verified');
    else if (raw.includes('VERIFICATION FAILURE')) setVerdict('failed');
  };

  const startDemo = async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    itemsRef.current = {};
    setScanItems({}); setActiveService(null); setPlan([]); setReasons({}); setSteps([]);
    setVerdict(null); setRawLines([]); setError(null); setShowSuccess(false);
    setScanState('scanning');

    try {
      const rec = await loadRecording(undefined, ac.signal);
      for await (const line of replay(rec, {
        signal: ac.signal,
        waitForApproval: () => new Promise<void>(resolve => { approveRef.current = resolve; }),
      })) {
        handleLine(line);
      }
      if (ac.signal.aborted) return;
      setScanState('complete');
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 4500);
    } catch (err) {
      if (ac.signal.aborted) return;
      setError(err instanceof Error ? err.message : 'Something went wrong loading the demo.');
      setScanState('idle');
    }
  };

  const approve = () => {
    setScanState('remediating');
    approveRef.current?.();
    approveRef.current = null;
  };

  const cancel = () => {
    abortRef.current?.abort();
    approveRef.current?.();
    approveRef.current = null;
    setScanState('idle');
  };

  const fixedCount = steps.filter(s => s.status === 'success').length;
  const totalItems = SERVICE_ORDER.reduce((n, s) => n + (scanItems[s]?.length ?? 0), 0);
  const doneServices = Object.keys(scanItems).length;
  const busy = scanState === 'scanning' || scanState === 'remediating';

  return (
    <div className="min-h-screen bg-[#09090b] text-slate-200" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');`}</style>

      {/* Success overlay */}
      {showSuccess && verdict === 'verified' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#09090b]/75 backdrop-blur-sm px-4" onClick={() => setShowSuccess(false)}>
          <div className="success-card relative bg-[#111116] border border-violet-500/25 rounded-2xl p-10 shadow-2xl shadow-violet-900/30 text-center w-80 max-w-full" onClick={e => e.stopPropagation()}>
            <div className="relative flex items-center justify-center mb-7">
              <div className="ring-out absolute w-20 h-20 rounded-full border border-violet-400/30" />
              <div className="ring-out absolute w-20 h-20 rounded-full border border-violet-400/20" style={{ animationDelay: '0.7s' }} />
              <svg viewBox="0 0 80 80" className="w-20 h-20 relative z-10">
                <path d="M40 8 L66 19 L66 43 C66 57 54 67 40 72 C26 67 14 57 14 43 L14 19 Z" fill="rgba(139,92,246,0.07)" stroke="#8b5cf6" strokeWidth="2" strokeLinejoin="round" />
                <polyline points="27,40 36,50 53,30" fill="none" stroke="#8b5cf6" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"
                  style={{ strokeDasharray: 60, strokeDashoffset: 60, animation: 'draw-check 0.55s ease-out 0.25s forwards' }} />
              </svg>
            </div>
            <h2 className="fade-slide-up text-lg font-bold text-slate-100 mb-1" style={{ animationDelay: '0.45s' }}>System Secured</h2>
            <p className="fade-slide-up text-sm text-slate-400" style={{ animationDelay: '0.55s' }}>
              {fixedCount} {fixedCount === 1 ? 'fix' : 'fixes'} applied and verified
            </p>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="border-b border-white/6">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors">
            <ArrowLeft size={14} /> <ShieldCheck size={16} className="text-violet-400" />
            <span className="font-semibold text-slate-100">Remedi</span>
          </Link>
          <a href={REPO} target="_blank" rel="noreferrer" className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors">
            GitHub <ExternalLink size={11} />
          </a>
        </div>
      </header>

      {/* Replay disclosure: always visible */}
      <div className="border-b border-amber-700/20 bg-amber-950/10">
        <p className="max-w-4xl mx-auto px-4 sm:px-6 py-2.5 text-xs text-amber-200/80 leading-relaxed">
          <span className="font-semibold text-amber-300">Recorded replay.</span>{' '}
          This replays a real Remedi run against a simulated AWS account: no credentials, no live AWS calls, no LLM cost per click.
          The agents, prompts and approval gate are the real ones; the AWS responses come from a fake account.{' '}
          <a href={`${REPO}#try-it`} target="_blank" rel="noreferrer" className="underline underline-offset-2 hover:text-amber-100">Run it live yourself</a>.
        </p>
      </div>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-8 space-y-4">

        {error && (
          <div className="flex items-center gap-2 rounded-xl border border-red-700/40 bg-red-950/20 px-4 py-3 text-sm text-red-300">
            <XCircle size={14} className="shrink-0" /> {error}
          </div>
        )}

        {/* ── IDLE ── */}
        {scanState === 'idle' && (
          <div className="rounded-2xl border border-white/8 bg-[#111116] p-8 sm:p-10 text-center">
            <div className="mx-auto mb-5 w-12 h-12 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
              <ShieldCheck size={22} className="text-violet-400" />
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-100">Watch Remedi secure an AWS account</h1>
            <p className="mt-3 text-sm text-slate-400 max-w-xl mx-auto leading-relaxed">
              Eight specialist agents audit IAM, S3, VPC, security groups, EC2, RDS, Lambda and CloudTrail in parallel.
              You review the findings and approve. Remedi fixes them, then re-audits to confirm the fixes held.
            </p>
            <ol className="mt-6 flex flex-wrap justify-center gap-x-6 gap-y-2 text-xs text-slate-500">
              {['Scan', 'Review', 'Approve', 'Fix', 'Verify'].map((s, i) => (
                <li key={s} className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full border border-white/10 text-slate-400 flex items-center justify-center text-[10px]">{i + 1}</span>{s}
                </li>
              ))}
            </ol>
            <button onClick={startDemo}
              className="mt-8 inline-flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-6 py-3 rounded-lg transition-colors text-sm">
              <Play size={13} className="fill-current" /> Run demo scan
            </button>
            <p className="mt-3 text-xs text-slate-600">About 30 seconds. No signup, no AWS keys.</p>
          </div>
        )}

        {/* ── SCANNING ── */}
        {scanState === 'scanning' && (
          <div className="rounded-2xl border border-white/8 bg-[#111116] overflow-hidden">
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
                  <p className="text-xs text-slate-600 mt-0.5">{doneServices} of {SERVICE_ORDER.length} services complete</p>
                </div>
              </div>
              <button onClick={cancel} className="text-xs text-slate-500 hover:text-slate-300 border border-white/8 px-3 py-1.5 rounded-lg transition-colors">Stop</button>
            </div>
            <div className="h-px w-full" style={{ background: 'rgba(255,255,255,0.04)' }}>
              <div className="h-full bg-violet-500/60 transition-all duration-700" style={{ width: `${(doneServices / SERVICE_ORDER.length) * 100}%` }} />
            </div>
            <ServiceRows scanItems={scanItems} activeService={activeService} />
          </div>
        )}

        {/* ── AWAITING APPROVAL ── */}
        {scanState === 'awaiting_approval' && (
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between px-5 py-4 rounded-2xl border border-amber-700/30 bg-amber-950/10 gap-3">
              <div className="flex items-center gap-3">
                <AlertTriangle size={15} className="text-amber-400 shrink-0" />
                <div>
                  <p className="text-sm font-semibold text-slate-100">
                    {plan.length} {plan.length === 1 ? 'vulnerability' : 'vulnerabilities'} detected
                  </p>
                  <p className="text-xs text-slate-500 mt-0.5">Remedi never changes anything until you approve.</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={cancel} className="text-xs text-slate-500 hover:text-slate-300 border border-white/8 hover:border-white/15 px-3 py-2 rounded-lg transition-colors">Cancel</button>
                <button onClick={approve}
                  className="flex items-center gap-2 text-sm font-semibold bg-violet-500 hover:bg-violet-400 text-white px-5 py-2 rounded-lg transition-colors">
                  Approve &amp; apply {plan.length} {plan.length === 1 ? 'fix' : 'fixes'}
                </button>
              </div>
            </div>
            <p className="text-xs text-slate-600 px-1">
              In a real scan you approve findings one by one. This replay applies all of the recorded fixes.
            </p>
            <div className="space-y-2">
              {plan.map((item, i) => {
                const info = REMEDIATION_INFO[item.toolName];
                return (
                  <div key={i} className="rounded-xl border border-white/8 bg-[#111116] flex items-start gap-4 px-5 py-4">
                    <div className="w-9 h-9 rounded-lg border bg-white/4 border-white/8 flex items-center justify-center text-base shrink-0 mt-0.5">{info?.icon ?? '🔧'}</div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-semibold text-slate-100">{info?.title ?? item.toolName}</p>
                        <span className="text-xs font-mono text-slate-500 bg-white/4 border border-white/8 px-2 py-0.5 rounded">{item.resource}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1 leading-relaxed">{reasons[item.resource] || info?.risk || 'Vulnerability detected'}</p>
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
                <h2 className="font-semibold text-slate-100 text-sm">{steps.length > 0 && fixedCount === steps.length ? 'Verifying fixes' : 'Applying fixes'}</h2>
              </div>
              <span className="text-xs text-slate-500">{fixedCount} / {steps.length} done</span>
            </div>
            {steps.length > 0 && (
              <div className="w-full h-1 rounded-full mb-5 overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
                <div className="h-full rounded-full bg-violet-500 transition-all duration-500" style={{ width: `${(fixedCount / steps.length) * 100}%` }} />
              </div>
            )}
            <div className="space-y-2">
              {steps.map((step, i) => {
                const info = REMEDIATION_INFO[step.funcName];
                return (
                  <div key={i} className={`flex items-center gap-3 px-4 py-3 rounded-lg border text-sm transition-all ${
                    step.status === 'success' ? 'border-violet-700/40 bg-violet-950/20' :
                    step.status === 'error'   ? 'border-red-700/40 bg-red-950/20' : 'border-white/6 bg-white/2'
                  }`}>
                    <span className="text-base w-5 text-center shrink-0">{info?.icon ?? '🔧'}</span>
                    <span className="flex-1 text-slate-300">{info?.title ?? step.funcName}</span>
                    <span className="text-xs font-mono text-slate-600 hidden sm:inline">{step.resource}</span>
                    {step.status === 'success' && <CheckCircle size={14} className="text-violet-400 shrink-0" />}
                    {step.status === 'error'   && <XCircle size={14} className="text-red-400 shrink-0" />}
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
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">Scan complete</h2>
                <p className="text-xs text-slate-600 mt-0.5">{totalItems} resources audited across {doneServices} services</p>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <span className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg border ${
                  verdict === 'verified' ? 'text-violet-400 border-violet-700/40 bg-violet-950/20' : 'text-red-400 border-red-700/40 bg-red-950/20'
                }`}>
                  {verdict === 'verified' ? <CheckCircle size={11} /> : <XCircle size={11} />}
                  {verdict === 'verified' ? `${fixedCount} fixes applied · verified` : 'Verification did not confirm every fix'}
                </span>
                <button onClick={startDemo}
                  className="flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-4 py-2 rounded-lg transition-colors text-sm">
                  <Play size={12} className="fill-current" /> Replay
                </button>
              </div>
            </div>

            <div className="rounded-xl border border-white/8 bg-[#111116] overflow-hidden">
              <div className="px-4 py-3 border-b border-white/6"><p className="text-xs font-medium text-slate-400">Scan results after fixes</p></div>
              <div className="divide-y divide-white/4">
                {SERVICE_ORDER.map(svc => {
                  const { label, Icon } = SERVICE_META[svc];
                  const items = scanItems[svc] ?? [];
                  const vulns = items.filter(i => i.status === 'vulnerable');
                  return (
                    <div key={svc} className={`flex items-center gap-3 px-4 py-3 ${vulns.length ? 'bg-red-950/10' : ''}`}>
                      <Icon size={13} className={vulns.length ? 'text-red-400' : 'text-slate-400'} />
                      <span className="text-sm text-slate-300 w-24 sm:w-28 shrink-0">{label}</span>
                      <div className="flex-1 flex flex-wrap gap-1.5">
                        {items.map((item, i) => (
                          <span key={i} className={`text-xs font-mono px-2 py-0.5 rounded border ${
                            item.status === 'vulnerable' ? 'text-red-400 border-red-800/40 bg-red-950/20' : 'text-slate-500 border-white/6 bg-white/2'
                          }`}>{item.status === 'vulnerable' ? '⚠ ' : '✓ '}{item.resource}</span>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="rounded-xl border border-white/8 bg-[#111116] p-5 text-sm text-slate-400 leading-relaxed">
              <p className="text-slate-200 font-medium mb-1">What you just watched</p>
              A recording of one real run: eight LLM agents, a human approval gate, parallel fixes, and a verifier that re-audits
              the fixed resources instead of trusting the fix report. Only the AWS side was simulated.
              <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs">
                <a className="text-violet-400 hover:text-violet-300" href="/demo_run.json" target="_blank" rel="noreferrer">Raw recording</a>
                <a className="text-violet-400 hover:text-violet-300" href={`${REPO}/blob/main/mcp_server/demo_fixtures.py`} target="_blank" rel="noreferrer">Simulated AWS account</a>
                <a className="text-violet-400 hover:text-violet-300" href={REPO} target="_blank" rel="noreferrer">Source on GitHub</a>
              </div>
            </div>
          </div>
        )}

        {/* Raw stream: shows this is the real pipeline output */}
        {scanState !== 'idle' && (
          <div className="rounded-xl border border-white/8 bg-[#0d0d10] overflow-hidden">
            <button onClick={() => setShowRaw(v => !v)}
              className="w-full flex items-center gap-2 px-4 py-2.5 text-xs text-slate-500 hover:text-slate-300 transition-colors">
              <Terminal size={12} /> {showRaw ? 'Hide' : 'Show'} raw agent output
              {busy && <span className="ml-1 w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />}
            </button>
            {showRaw && (
              <pre ref={rawRef} className="max-h-64 overflow-auto px-4 pb-4 text-[11px] leading-relaxed text-slate-500 whitespace-pre-wrap break-words"
                style={{ fontFamily: "'JetBrains Mono', monospace" }}>{rawLines.join('\n')}</pre>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

// ─── Service rows (scanning view) ────────────────────────────────────────────

function ServiceRows({ scanItems, activeService }: {
  scanItems: Partial<Record<ServiceKey, ScanItem[]>>; activeService: ServiceKey | null;
}) {
  return (
    <div className="divide-y divide-white/4">
      {SERVICE_ORDER.map(svc => {
        const { label, Icon } = SERVICE_META[svc];
        const items = scanItems[svc];
        const isActive = activeService === svc;
        const isDone = !!items;
        const vulns = items?.filter(i => i.status === 'vulnerable') ?? [];
        return (
          <div key={svc} className={`flex items-center gap-4 px-5 py-3 transition-colors ${isActive ? 'bg-violet-950/20' : ''}`}>
            <Icon size={13} className={isActive ? 'text-violet-400' : isDone ? 'text-slate-500' : 'text-slate-700'} />
            <span className={`text-sm flex-1 ${isActive ? 'text-slate-100' : isDone ? 'text-slate-400' : 'text-slate-700'}`}
              style={{ fontFamily: "'JetBrains Mono', monospace" }}>{label}</span>
            {isActive && (
              <span className="flex items-center gap-1.5 text-xs text-violet-400">
                <span className="w-3 h-3 rounded-full border-2 border-violet-400 border-t-transparent animate-spin" /> scanning
              </span>
            )}
            {isDone && vulns.length > 0 && (
              <span className="text-xs font-medium text-red-400 bg-red-950/40 border border-red-800/30 px-2 py-0.5 rounded">
                {vulns.length} {vulns.length === 1 ? 'issue' : 'issues'}
              </span>
            )}
            {isDone && vulns.length === 0 && (
              <span className="flex items-center gap-1 text-xs text-slate-600"><CheckCircle size={11} /> clean</span>
            )}
            {!isDone && !isActive && <span className="text-xs text-slate-800">—</span>}
          </div>
        );
      })}
    </div>
  );
}
