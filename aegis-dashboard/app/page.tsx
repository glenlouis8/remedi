'use client';

import Link from 'next/link';
import { useAuth, useClerk } from '@clerk/nextjs';
import { ShieldCheck, ArrowRight, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

const mockFindings = [
  { icon: <XCircle size={14} className="text-red-500" />, label: 'S3 bucket "prod-uploads" is publicly readable', action: 'Block public access', severity: 'CRITICAL' },
  { icon: <XCircle size={14} className="text-red-500" />, label: 'dev-user-01 has AdministratorAccess', action: 'Revoke admin policy', severity: 'CRITICAL' },
  { icon: <AlertTriangle size={14} className="text-amber-500" />, label: 'Security group sg-0a3f allows 0.0.0.0/0 on port 22', action: 'Revoke SSH ingress', severity: 'HIGH' },
  { icon: <AlertTriangle size={14} className="text-amber-500" />, label: 'VPC flow logs disabled on vpc-09f2', action: 'Enable flow logs', severity: 'HIGH' },
  { icon: <CheckCircle size={14} className="text-emerald-500" />, label: 'EC2 i-0b3c running IMDSv2', action: 'Already compliant', severity: 'PASS' },
];

export default function HomePage() {
  const { isSignedIn } = useAuth();
  const { signOut } = useClerk();

  return (
    <div className="min-h-screen bg-white text-slate-900 flex flex-col">

      {/* Nav */}
      <nav className="flex items-center justify-between px-8 py-4 border-b border-slate-200">
        <div className="flex items-center gap-2">
          <ShieldCheck className="text-emerald-600" size={20} />
          <span className="font-semibold tracking-tight text-slate-900">Remedi</span>
        </div>
        <div className="flex items-center gap-4">
          {isSignedIn ? (
            <>
              <Link
                href="/dashboard"
                className="text-sm bg-emerald-500 hover:bg-emerald-600 text-white font-semibold px-4 py-2 rounded-lg transition-colors"
              >
                Go to dashboard
              </Link>
              <button
                onClick={() => signOut({ redirectUrl: '/' })}
                className="text-sm text-slate-500 hover:text-slate-900 transition-colors"
              >
                Sign out
              </button>
            </>
          ) : (
            <>
              <Link href="/sign-in" className="text-sm text-slate-500 hover:text-slate-900 transition-colors">
                Sign in
              </Link>
              <Link
                href="/sign-up"
                className="text-sm bg-emerald-500 hover:bg-emerald-600 text-white font-semibold px-4 py-2 rounded-lg transition-colors"
              >
                Try free
              </Link>
            </>
          )}
        </div>
      </nav>

      <main className="flex flex-col items-center flex-1 px-6">

        {/* Hero */}
        <div className="text-center pt-24 pb-16 max-w-2xl">
          <p className="text-emerald-600 text-sm font-medium mb-4 tracking-wide uppercase">AWS Security & Compliance</p>
          <h1 className="text-5xl font-bold tracking-tight leading-[1.15] mb-5 text-slate-900">
            Your AWS account has problems.{' '}
            <span className="text-emerald-600">Remedi fixes them.</span>
          </h1>
          <p className="text-slate-500 text-lg mb-8">
            Connect your account, get a full security audit in minutes, and fix every finding with one click — after you approve it.
          </p>
          <Link
            href={isSignedIn ? '/dashboard' : '/sign-up'}
            className="inline-flex items-center gap-2 bg-emerald-500 hover:bg-emerald-600 text-white font-semibold px-6 py-3 rounded-lg transition-colors"
          >
            {isSignedIn ? 'Go to dashboard' : 'Scan my AWS account'} <ArrowRight size={16} />
          </Link>
        </div>

        {/* Mock UI */}
        <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl overflow-hidden shadow-2xl mb-24">
          {/* Mock header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700/80 bg-slate-800/80">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-red-500/70" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
              <div className="w-3 h-3 rounded-full bg-emerald-500/70" />
            </div>
            <span className="text-xs text-slate-400 font-mono">Scan #4821 — your-aws-account</span>
            <div className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Live scan
            </div>
          </div>

          {/* CIS score bar */}
          <div className="px-5 py-4 border-b border-slate-700/50 flex items-center justify-between bg-slate-900">
            <div>
              <p className="text-xs text-slate-400 mb-1">CIS AWS Foundations Score</p>
              <div className="flex items-end gap-2">
                <span className="text-3xl font-bold text-white">6</span>
                <span className="text-slate-500 text-lg mb-0.5">/ 10</span>
                <span className="text-xs text-amber-400 bg-amber-400/10 px-2 py-0.5 rounded-full mb-1 ml-1">Needs attention</span>
              </div>
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-400 mb-1">4 issues found</p>
              <button className="text-sm bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-1.5 rounded-lg hover:bg-red-500/20 transition-colors">
                Review & approve fixes
              </button>
            </div>
          </div>

          {/* Findings list */}
          <div className="divide-y divide-slate-700/50 bg-slate-900">
            {mockFindings.map((f, i) => (
              <div key={i} className="flex items-center justify-between px-5 py-3 hover:bg-slate-800/40 transition-colors">
                <div className="flex items-center gap-3">
                  {f.icon}
                  <span className="text-sm text-slate-300">{f.label}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0 ml-4">
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    f.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400' :
                    f.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-400' :
                    'bg-emerald-500/10 text-emerald-400'
                  }`}>{f.severity}</span>
                  <span className="text-xs text-slate-500 hidden sm:block">{f.action}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Three steps */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-3xl w-full mb-24">
          {[
            { n: '01', title: 'Connect AWS', body: 'Paste your IAM credentials. Read-only access for scanning, write access only when you approve a fix.' },
            { n: '02', title: 'Get your report', body: 'Remedi checks IAM, S3, EC2, VPCs, and security groups against CIS benchmarks and surfaces every risk.' },
            { n: '03', title: 'Approve and fix', body: 'Each fix is explained in plain English. Click approve — Remedi runs the fix and verifies it worked.' },
          ].map(({ n, title, body }) => (
            <div key={n} className="bg-slate-50 border border-slate-200 rounded-xl p-6">
              <span className="text-xs text-slate-400 font-mono">{n}</span>
              <h3 className="font-semibold mt-2 mb-2 text-slate-900">{title}</h3>
              <p className="text-slate-500 text-sm">{body}</p>
            </div>
          ))}
        </div>
      </main>

      <footer className="border-t border-slate-200 px-8 py-5 text-center text-slate-400 text-sm">
        © {new Date().getFullYear()} Remedi &mdash; built on{' '}
        <a href="https://github.com/glenlouis8/ageis-flow" target="_blank" rel="noopener noreferrer" className="hover:text-slate-600 transition-colors">
          AEGIS-FLOW
        </a>
      </footer>
    </div>
  );
}
