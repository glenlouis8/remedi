'use client';

import Link from 'next/link';
import { useAuth, useClerk } from '@clerk/nextjs';
import { ShieldCheck, ArrowRight, CheckCircle, XCircle, AlertTriangle, Shield, Zap, Eye } from 'lucide-react';

const mockFindings = [
  { icon: <XCircle size={13} className="text-red-400 shrink-0" />, label: 'S3 bucket "prod-uploads" is publicly readable', action: 'Block public access', severity: 'CRITICAL' },
  { icon: <XCircle size={13} className="text-red-400 shrink-0" />, label: 'dev-user-01 has AdministratorAccess', action: 'Revoke admin policy', severity: 'CRITICAL' },
  { icon: <AlertTriangle size={13} className="text-amber-400 shrink-0" />, label: 'Security group sg-0a3f allows 0.0.0.0/0 on port 22', action: 'Revoke SSH ingress', severity: 'HIGH' },
  { icon: <AlertTriangle size={13} className="text-amber-400 shrink-0" />, label: 'VPC flow logs disabled on vpc-09f2', action: 'Enable flow logs', severity: 'HIGH' },
  { icon: <CheckCircle size={13} className="text-violet-400 shrink-0" />, label: 'EC2 i-0b3c running IMDSv2', action: 'Already compliant', severity: 'PASS' },
];

const steps = [
  {
    icon: <Shield size={18} className="text-violet-400" />,
    n: '01',
    title: 'Connect AWS',
    body: 'One-click CloudFormation setup creates a least-privilege IAM user. No admin access required. Revoke anytime.',
  },
  {
    icon: <Eye size={18} className="text-violet-400" />,
    n: '02',
    title: 'Get your report',
    body: 'Eight specialist AI agents scan IAM, S3, EC2, VPCs, RDS, Lambda, and CloudTrail in parallel against CIS benchmarks.',
  },
  {
    icon: <Zap size={18} className="text-violet-400" />,
    n: '03',
    title: 'Approve and fix',
    body: 'Review each finding individually. Approve the ones you want fixed — Remedi runs the fix and verifies it held.',
  },
];

export default function HomePage() {
  const { isSignedIn } = useAuth();
  const { signOut } = useClerk();

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        .font-sora { font-family: 'Space Grotesk', sans-serif; }
        .font-mono-code { font-family: 'JetBrains Mono', monospace; }
        .text-gradient {
          background: linear-gradient(135deg, #8b5cf6 0%, #a78bfa 60%, #c4b5fd 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }
        .scan-line {
          animation: scandown 3s ease-in-out infinite;
        }
        @keyframes scandown {
          0% { transform: translateY(-100%); opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { transform: translateY(500%); opacity: 0; }
        }
        .fade-up {
          animation: fadeup 0.6s ease both;
        }
        @keyframes fadeup {
          from { opacity: 0; transform: translateY(16px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
        .delay-4 { animation-delay: 0.4s; }
      `}</style>

      <div className="min-h-screen bg-[#09090b] text-white flex flex-col font-sora">

        {/* Nav */}
        <nav className="relative z-10 flex items-center justify-between px-8 py-5 border-b border-white/5">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-violet-500/15 border border-violet-500/25 flex items-center justify-center">
              <ShieldCheck size={15} className="text-violet-400" />
            </div>
            <span className="font-semibold tracking-tight text-white">Remedi</span>
            <span className="text-xs font-medium px-1.5 py-0.5 rounded-full border font-mono-code" style={{ color: '#f59e0b', borderColor: 'rgba(245,158,11,0.25)', background: 'rgba(245,158,11,0.08)' }}>beta</span>
          </div>
          <div className="flex items-center gap-6">
            <Link href="/about" className="text-sm text-slate-400 hover:text-white transition-colors">About</Link>
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

        <main className="relative z-10 flex flex-col items-center flex-1 px-6">

          {/* Hero */}
          <div className="text-center pt-24 pb-16 max-w-3xl fade-up">
            <div className="inline-flex items-center gap-2 text-xs font-mono-code text-violet-400 bg-violet-500/10 border border-violet-500/20 px-3 py-1.5 rounded-full mb-8">
              <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
              AI-powered AWS security scanning & auto-remediation
            </div>
            <h1 className="text-5xl sm:text-6xl font-bold tracking-tight leading-[1.1] mb-6 text-white">
              Your AWS account<br />
              has vulnerabilities.{' '}
              <span className="text-gradient">We fix them.</span>
            </h1>
            <p className="text-slate-400 text-lg mb-10 leading-relaxed max-w-xl mx-auto">
              Connect your account, get a full security audit across 8 services in minutes, and fix every finding — only after you approve it.
            </p>
            <div className="flex items-center justify-center gap-4 fade-up delay-2">
              <Link
                href={isSignedIn ? '/dashboard' : '/sign-up'}
                className="inline-flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-6 py-3 rounded-xl transition-all hover:shadow-lg hover:shadow-violet-500/20"
              >
                {isSignedIn ? 'Go to dashboard' : 'Scan my AWS account'} <ArrowRight size={16} />
              </Link>
              <Link href="/about" className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors px-4 py-3">
                How it works
              </Link>
            </div>
          </div>

          {/* Stats row */}
          <div className="flex items-center gap-8 mb-16 fade-up delay-3">
            {[
              { value: '8', label: 'services scanned' },
              { value: '< 5 min', label: 'full audit time' },
              { value: '100%', label: 'human-approved fixes' },
            ].map(({ value, label }) => (
              <div key={label} className="text-center">
                <p className="text-2xl font-bold text-white font-mono-code">{value}</p>
                <p className="text-xs text-slate-500 mt-0.5">{label}</p>
              </div>
            ))}
          </div>

          {/* Mock UI */}
          <div className="w-full max-w-3xl mb-28 fade-up delay-4">
            <div className="text-center mb-3">
              <span className="text-xs font-mono-code text-slate-600 tracking-wider uppercase">Example output · not real account data</span>
            </div>
            <div className="bg-[#111116] border border-white/8 rounded-2xl overflow-hidden">

              {/* Window chrome */}
              <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5 bg-[#0a0a0d]">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-violet-500/60" />
                </div>
                <span className="text-xs font-mono-code text-slate-500">remedi — example scan — us-east-1</span>
                <div className="flex items-center gap-1.5 text-xs text-slate-500 bg-white/5 px-2.5 py-1 rounded-full border border-white/8">
                  Demo
                </div>
              </div>

              {/* CIS score */}
              <div className="px-6 py-5 border-b border-white/5 flex items-center justify-between">
                <div>
                  <p className="text-xs text-slate-500 mb-1 font-mono-code uppercase tracking-wider">CIS AWS Foundations</p>
                  <div className="flex items-end gap-2">
                    <span className="text-4xl font-bold text-white font-mono-code">62</span>
                    <span className="text-slate-600 text-xl mb-1">%</span>
                    <span className="text-xs text-amber-400 bg-amber-400/10 border border-amber-400/20 px-2 py-0.5 rounded-full mb-1.5 ml-1">Needs attention</span>
                  </div>
                  <div className="mt-2 w-48 h-1 bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full w-[62%] bg-gradient-to-r from-violet-500 to-violet-400 rounded-full" />
                  </div>
                </div>
                <button className="text-sm bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-2 rounded-xl hover:bg-red-500/20 transition-colors font-medium">
                  Review 4 findings
                </button>
              </div>

              {/* Findings with scan line effect */}
              <div className="relative overflow-hidden">
                <div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-violet-400/40 to-transparent scan-line z-10 pointer-events-none" />
                <div className="divide-y divide-white/4">
                  {mockFindings.map((f, i) => (
                    <div key={i} className="flex items-center justify-between px-6 py-3.5 hover:bg-white/2 transition-colors group">
                      <div className="flex items-center gap-3 min-w-0">
                        {f.icon}
                        <span className="text-sm text-slate-300 truncate font-mono-code text-xs">{f.label}</span>
                      </div>
                      <div className="flex items-center gap-3 shrink-0 ml-4">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium font-mono-code ${
                          f.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                          f.severity === 'HIGH'     ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                                                     'bg-violet-500/10 text-violet-400 border border-violet-500/20'
                        }`}>{f.severity}</span>
                        <span className="text-xs text-slate-600 hidden sm:block group-hover:text-slate-400 transition-colors">{f.action}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Three steps */}
          <div className="w-full max-w-3xl mb-28">
            <p className="text-xs font-mono-code text-slate-500 uppercase tracking-widest text-center mb-10">How it works</p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {steps.map(({ icon, n, title, body }) => (
                <div key={n} className="bg-[#111116] border border-white/6 rounded-2xl p-6 hover:border-violet-500/20 transition-colors group">
                  <div className="flex items-center justify-between mb-5">
                    <div className="w-9 h-9 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center group-hover:bg-violet-500/15 transition-colors">
                      {icon}
                    </div>
                    <span className="text-xs font-mono-code text-slate-600">{n}</span>
                  </div>
                  <h3 className="font-semibold text-white mb-2">{title}</h3>
                  <p className="text-slate-500 text-sm leading-relaxed">{body}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Bottom CTA */}
          <div className="text-center mb-28 max-w-xl">
            <h2 className="text-3xl font-bold text-white mb-4">Ready to secure your account?</h2>
            <p className="text-slate-400 text-sm mb-8">Takes 2 minutes to connect. No credit card required.</p>
            <Link
              href={isSignedIn ? '/dashboard' : '/sign-up'}
              className="inline-flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-8 py-3.5 rounded-xl transition-all hover:shadow-lg hover:shadow-violet-500/20"
            >
              {isSignedIn ? 'Go to dashboard' : 'Get started free'} <ArrowRight size={16} />
            </Link>
          </div>

        </main>

        <footer className="relative z-10 border-t border-white/5 px-8 py-6 flex items-center justify-between text-xs text-slate-600">
          <div className="flex items-center gap-2">
            <ShieldCheck size={13} className="text-violet-500/50" />
            <span>Remedi</span>
          </div>
          <span>© {new Date().getFullYear()} — AWS credentials encrypted at rest, deleted on sign out, auto-expire after 30 min of inactivity</span>
          <Link href="/about" className="hover:text-slate-400 transition-colors">About</Link>
          <Link href="/developer" className="hover:text-slate-400 transition-colors">Developer</Link>
        </footer>
      </div>
    </>
  );
}
