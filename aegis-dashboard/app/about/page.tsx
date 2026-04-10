'use client';

import Link from 'next/link';
import { useAuth, useClerk } from '@clerk/nextjs';
import {
  ShieldCheck, ArrowRight, Users, HardDrive, Globe, Shield,
  Server, Database, Zap, FileText, CheckCircle, Lock, Eye,
  GitBranch, Cpu, Terminal,
} from 'lucide-react';

export default function AboutPage() {
  const { isSignedIn } = useAuth();
  const { signOut } = useClerk();

  return (
    <div className="min-h-screen bg-[#09090b] text-white flex flex-col" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');`}</style>

      {/* Nav */}
      <nav className="relative z-10 flex items-center justify-between px-8 py-5 border-b border-white/5">
        <Link href="/" className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.25)' }}>
            <ShieldCheck size={15} className="text-violet-400" />
          </div>
          <span className="font-semibold tracking-tight text-white">Remedi</span>
        </Link>
        <div className="flex items-center gap-6">
          <Link href="/about" className="text-sm text-violet-400 font-medium">About</Link>
          <Link href="/developer" className="text-sm text-slate-400 hover:text-white transition-colors">Developer</Link>
          {isSignedIn ? (
            <>
              <Link href="/dashboard" className="text-sm bg-violet-500 hover:bg-violet-400 text-white font-semibold px-4 py-2 rounded-lg transition-colors">
                Dashboard
              </Link>
              <button onClick={() => signOut({ redirectUrl: '/' })} className="text-sm text-slate-400 hover:text-white transition-colors">
                Sign out
              </button>
            </>
          ) : (
            <>
              <Link href="/sign-in" className="text-sm text-slate-400 hover:text-white transition-colors">Sign in</Link>
              <Link href="/sign-up" className="text-sm bg-violet-500 hover:bg-violet-400 text-white font-semibold px-4 py-2 rounded-lg transition-colors">
                Try free
              </Link>
            </>
          )}
        </div>
      </nav>

      <main className="relative z-10 flex-1 w-full">

        {/* ── Hero ── */}
        <section className="max-w-4xl mx-auto px-8 pt-24 pb-20 text-center">
          <div className="inline-flex items-center gap-2 text-xs font-medium text-violet-400 border border-violet-500/20 bg-violet-500/8 px-3 py-1.5 rounded-full mb-8">
            <span className="w-1.5 h-1.5 rounded-full bg-violet-400" />
            AI-powered AWS security
          </div>
          <h1 className="text-5xl font-bold text-white leading-tight mb-6">
            Scan. Understand. Fix.
            <br />
            <span className="text-violet-400">In minutes, not days.</span>
          </h1>
          <p className="text-lg text-slate-400 leading-relaxed max-w-2xl mx-auto mb-10">
            Remedi is an autonomous security agent that audits your AWS account across 8 services, explains every finding in plain English, and fixes everything automatically — after you approve.
          </p>
          <div className="flex items-center justify-center gap-4">
            <Link
              href={isSignedIn ? '/dashboard' : '/sign-up'}
              className="inline-flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-6 py-3 rounded-xl transition-colors"
            >
              {isSignedIn ? 'Go to dashboard' : 'Get started free'} <ArrowRight size={15} />
            </Link>
          </div>
        </section>

        {/* ── The problem ── */}
        <section className="border-t border-white/5">
          <div className="max-w-4xl mx-auto px-8 py-20">
            <div className="grid grid-cols-2 gap-16 items-center">
              <div>
                <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-4">The problem</p>
                <h2 className="text-2xl font-bold text-white mb-5 leading-snug">
                  Most AWS accounts are misconfigured from day one
                </h2>
                <p className="text-slate-400 leading-relaxed mb-4">
                  IAM users with admin access, public S3 buckets, security groups open to the world, databases reachable from the internet — these aren&apos;t rare edge cases. They&apos;re the default state of accounts that grew without a security process.
                </p>
                <p className="text-slate-400 leading-relaxed">
                  Security audits are expensive, slow, and produce reports that sit unread. Remedi replaces that cycle with a fully automated agent that finds issues and fixes them in a single session.
                </p>
              </div>
              <div className="space-y-3">
                {[
                  { stat: '80%', label: 'of cloud breaches involve misconfiguration', color: 'text-red-400' },
                  { stat: '197', label: 'average days to identify a cloud breach', color: 'text-amber-400' },
                  { stat: '$4.5M', label: 'average cost of a cloud data breach in 2024', color: 'text-red-400' },
                  { stat: '< 5 min', label: 'time for Remedi to audit and fix your account', color: 'text-violet-400' },
                ].map(({ stat, label, color }) => (
                  <div key={label} className="flex items-center gap-4 rounded-xl border border-white/6 px-5 py-4" style={{ background: 'rgba(14,14,18,0.6)' }}>
                    <span className={`text-2xl font-bold tabular-nums shrink-0 ${color}`} style={{ fontFamily: "'JetBrains Mono', monospace" }}>{stat}</span>
                    <p className="text-sm text-slate-400">{label}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* ── How it works ── */}
        <section className="border-t border-white/5 bg-[#0a0a0f]">
          <div className="max-w-4xl mx-auto px-8 py-20">
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">How it works</p>
            <h2 className="text-2xl font-bold text-white mb-12">Five stages, fully automated</h2>

            <div className="relative">
              {/* Vertical line */}
              <div className="absolute left-5 top-6 bottom-6 w-px bg-white/6" />

              <div className="space-y-0">
                {[
                  {
                    step: '01',
                    title: 'Parallel discovery',
                    body: 'Eight specialist sub-agents fire simultaneously — one per AWS service. Each runs its own tool-call loop against live AWS APIs via boto3. They complete in parallel, not sequentially, so the full audit takes the same time as the slowest single service.',
                    tag: 'LangGraph + ThreadPoolExecutor',
                  },
                  {
                    step: '02',
                    title: 'Structured report',
                    body: 'A report generator synthesises all findings into a structured remediation plan. Every finding maps to a specific tool call. The report uses a strict machine-readable format so the remediator can parse it without an additional LLM call.',
                    tag: 'Gemini 3.0 Flash',
                  },
                  {
                    step: '03',
                    title: 'Human approval gate',
                    body: 'The agent pauses. You see every finding explained in plain English with a risk description pulled from the live scan. You approve or skip each fix individually — or approve all at once. Nothing is changed without your explicit sign-off.',
                    tag: 'Hard interrupt — no auto-proceed',
                  },
                  {
                    step: '04',
                    title: 'Parallel remediation',
                    body: 'Only the fixes you approved are executed, in parallel. Each tool call goes through a dedicated MCP server running as a subprocess — a clean boundary between the agent and the AWS API layer. Progress streams to your dashboard in real time.',
                    tag: 'MCP protocol over stdio',
                  },
                  {
                    step: '05',
                    title: 'Verification pass',
                    body: 'After remediation, a verifier re-audits only the resources that were changed. It confirms each fix held — no regressions, no half-applied remediations. The scan is only marked complete when every fix is verified.',
                    tag: 'Post-remediation audit',
                  },
                ].map(({ step, title, body, tag }) => (
                  <div key={step} className="relative flex gap-8 pb-10">
                    <div className="w-10 shrink-0 flex flex-col items-center">
                      <div className="w-10 h-10 rounded-full border border-white/10 bg-[#09090b] flex items-center justify-center z-10">
                        <span className="text-xs font-bold text-slate-500" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{step}</span>
                      </div>
                    </div>
                    <div className="flex-1 pt-1.5">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-semibold text-white">{title}</h3>
                        <span className="text-xs text-slate-600 font-mono border border-white/6 px-2 py-0.5 rounded">{tag}</span>
                      </div>
                      <p className="text-sm text-slate-400 leading-relaxed">{body}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* ── Coverage ── */}
        <section className="border-t border-white/5">
          <div className="max-w-4xl mx-auto px-8 py-20">
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Coverage</p>
            <h2 className="text-2xl font-bold text-white mb-3">8 AWS services, fully automated</h2>
            <p className="text-slate-500 text-sm mb-10">Every service is audited and remediated by a dedicated specialist agent.</p>

            <div className="grid grid-cols-2 gap-3">
              {[
                {
                  Icon: Users, label: 'IAM',
                  audit: 'Flags users with AdministratorAccess or PowerUserAccess.',
                  fix: 'Detaches all policies, removes from groups, applies ReadOnlyAccess.',
                },
                {
                  Icon: HardDrive, label: 'S3',
                  audit: 'Checks all buckets for missing or incomplete public access blocks.',
                  fix: 'Enables all four public access block settings on the vulnerable bucket.',
                },
                {
                  Icon: Globe, label: 'VPC',
                  audit: 'Checks every VPC for disabled flow logs.',
                  fix: 'Creates a CloudWatch log group and an IAM role (AegisFlowLogRole), then enables flow logs. Both resources persist in your account — the role is required for flow logs to keep delivering.',
                },
                {
                  Icon: Shield, label: 'Security Groups',
                  audit: 'Flags any inbound rule allowing 0.0.0.0/0 on any port.',
                  fix: 'Revokes the offending ingress rule — leaves all other rules intact.',
                },
                {
                  Icon: Server, label: 'EC2',
                  audit: 'Flags instances with IMDSv1 enabled or unencrypted root volumes.',
                  fix: 'Enforces IMDSv2 via metadata options. Instances with unencrypted root volumes are hard-stopped as a quarantine measure — running workloads on those instances will be interrupted.',
                },
                {
                  Icon: Database, label: 'RDS',
                  audit: 'Flags any RDS instance with PubliclyAccessible set to true.',
                  fix: 'Sets PubliclyAccessible to false — no data is touched.',
                },
                {
                  Icon: Zap, label: 'Lambda',
                  audit: 'Checks execution role policies for AdministratorAccess or wildcard Action.',
                  fix: 'Detaches over-permissioned policies from the execution role.',
                },
                {
                  Icon: FileText, label: 'CloudTrail',
                  audit: 'Flags accounts with no trails, or trails with logging disabled.',
                  fix: 'Creates a trail named remedi-audit-trail and a dedicated S3 bucket for log delivery. Both persist after the scan. The S3 bucket will accumulate CloudTrail log files over time.',
                },
              ].map(({ Icon, label, audit, fix }) => (
                <div key={label} className="rounded-xl border border-white/6 p-5" style={{ background: 'rgba(14,14,18,0.6)' }}>
                  <div className="flex items-center gap-2.5 mb-3">
                    <div className="w-8 h-8 rounded-lg border border-white/8 flex items-center justify-center" style={{ background: 'rgba(139,92,246,0.08)' }}>
                      <Icon size={14} className="text-violet-400" />
                    </div>
                    <span className="font-semibold text-white text-sm">{label}</span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex gap-2">
                      <span className="text-xs font-medium text-slate-600 shrink-0 w-10 pt-0.5">Audit</span>
                      <p className="text-xs text-slate-400 leading-relaxed">{audit}</p>
                    </div>
                    <div className="flex gap-2">
                      <span className="text-xs font-medium text-violet-600 shrink-0 w-10 pt-0.5">Fix</span>
                      <p className="text-xs text-slate-400 leading-relaxed">{fix}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Security model ── */}
        <section className="border-t border-white/5 bg-[#0a0a0f]">
          <div className="max-w-4xl mx-auto px-8 py-20">
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Security model</p>
            <h2 className="text-2xl font-bold text-white mb-12">Your credentials, handled correctly</h2>
            <div className="grid grid-cols-3 gap-6">
              {[
                {
                  Icon: Lock,
                  title: 'Encrypted at rest',
                  body: 'AWS credentials are encrypted with AES-256 (Fernet) before being written to the database. The encryption key is stored separately in the environment — never alongside the data.',
                },
                {
                  Icon: Eye,
                  title: 'Auto-expire after 30 minutes',
                  body: 'A background job checks every 5 minutes and deletes credentials that haven\'t been used in 30 minutes. Inactivity means automatic revocation — no manual cleanup required.',
                },
                {
                  Icon: CheckCircle,
                  title: 'Deleted on sign-out',
                  body: 'Signing out immediately deletes your credentials from the database before the Clerk session is cleared. There is no retention window — they\'re gone the moment you leave.',
                },
                {
                  Icon: Shield,
                  title: 'Least-privilege IAM user',
                  body: 'The CloudFormation template creates a purpose-built IAM user with only the specific actions Remedi needs. No AdministratorAccess, no wildcards beyond what each operation requires.',
                },
                {
                  Icon: GitBranch,
                  title: 'Credential user auto-protected',
                  body: 'Remedi calls STS GetCallerIdentity on every scan to identify whose credentials it\'s running with. That user is automatically added to the protected list — Remedi will never lock you out.',
                },
                {
                  Icon: Terminal,
                  title: 'Human approval is a hard gate',
                  body: 'The agent process literally blocks on stdin — it cannot proceed without a signal from your browser. There is no timeout, no fallback, no auto-approve. The graph is frozen until you act.',
                },
              ].map(({ Icon, title, body }) => (
                <div key={title} className="rounded-xl border border-white/6 p-5" style={{ background: 'rgba(14,14,18,0.6)' }}>
                  <div className="w-8 h-8 rounded-lg border border-white/8 flex items-center justify-center mb-4" style={{ background: 'rgba(139,92,246,0.08)' }}>
                    <Icon size={14} className="text-violet-400" />
                  </div>
                  <h3 className="font-semibold text-white text-sm mb-2">{title}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Tech stack ── */}
        <section className="border-t border-white/5">
          <div className="max-w-4xl mx-auto px-8 py-20">
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Technical architecture</p>
            <h2 className="text-2xl font-bold text-white mb-12">Built on modern AI infrastructure</h2>
            <div className="grid grid-cols-2 gap-8">
              <div className="space-y-6">
                {[
                  {
                    Icon: Cpu,
                    label: 'LangGraph',
                    detail: 'Agent orchestration with persistent graph state, human-in-the-loop interrupts, and parallel node execution. Each scan gets its own thread — no state bleed between concurrent users.',
                  },
                  {
                    Icon: Zap,
                    label: 'Gemini 3.0 Flash',
                    detail: 'Powers all LLM calls — audit analysis, report synthesis, and verification. Flash provides the latency profile required for real-time streaming without sacrificing reasoning quality.',
                  },
                  {
                    Icon: Terminal,
                    label: 'Model Context Protocol (MCP)',
                    detail: 'All AWS API calls live in a dedicated MCP server subprocess. The agent communicates via JSON-RPC over stdio — a clean boundary that keeps tool execution separate from agent logic.',
                  },
                ].map(({ Icon, label, detail }) => (
                  <div key={label} className="flex gap-4">
                    <div className="w-9 h-9 rounded-xl border border-white/8 flex items-center justify-center shrink-0" style={{ background: 'rgba(139,92,246,0.08)' }}>
                      <Icon size={15} className="text-violet-400" />
                    </div>
                    <div>
                      <p className="font-semibold text-white text-sm mb-1">{label}</p>
                      <p className="text-xs text-slate-400 leading-relaxed">{detail}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="space-y-6">
                {[
                  {
                    Icon: Server,
                    label: 'FastAPI + streaming',
                    detail: 'The backend serves a StreamingResponse for each scan — the frontend reads it line by line. Structured events prefixed with [SCAN], [EXEC], and [ACTION_REQUIRED] drive the real-time UI without WebSockets.',
                  },
                  {
                    Icon: Shield,
                    label: 'Next.js 15 + Clerk',
                    detail: 'App Router frontend with Clerk JWT authentication. Every API call carries a signed JWT verified by the backend against Clerk\'s JWKS endpoint. No session cookies, no server state.',
                  },
                  {
                    Icon: Database,
                    label: 'PostgreSQL on Railway',
                    detail: 'Scan history, remediation logs, compliance check statuses, and encrypted credentials all live in a single Postgres instance. Schema migrations run on startup via ALTER TABLE IF NOT EXISTS.',
                  },
                ].map(({ Icon, label, detail }) => (
                  <div key={label} className="flex gap-4">
                    <div className="w-9 h-9 rounded-xl border border-white/8 flex items-center justify-center shrink-0" style={{ background: 'rgba(139,92,246,0.08)' }}>
                      <Icon size={15} className="text-violet-400" />
                    </div>
                    <div>
                      <p className="font-semibold text-white text-sm mb-1">{label}</p>
                      <p className="text-xs text-slate-400 leading-relaxed">{detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* ── CTA ── */}
        <section className="border-t border-white/5 bg-[#0a0a0f]">
          <div className="max-w-4xl mx-auto px-8 py-20 text-center">
            <h2 className="text-3xl font-bold text-white mb-4">Ready to secure your account?</h2>
            <p className="text-slate-400 mb-8 max-w-md mx-auto">Connect your AWS account in 2 minutes. The first scan is free and finds issues most teams don&apos;t know they have.</p>
            <Link
              href={isSignedIn ? '/dashboard' : '/sign-up'}
              className="inline-flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-7 py-3.5 rounded-xl transition-colors"
            >
              {isSignedIn ? 'Go to dashboard' : 'Get started free'} <ArrowRight size={15} />
            </Link>
          </div>
        </section>

      </main>

      <footer className="relative z-10 border-t border-white/5 px-8 py-6 text-center text-slate-600 text-xs" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
        © {new Date().getFullYear()} Remedi
      </footer>
    </div>
  );
}
