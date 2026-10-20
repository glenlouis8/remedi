'use client';

import Link from 'next/link';
import { useAuth, useClerk } from '@clerk/nextjs';
import { ShieldCheck, ArrowRight, CheckCircle, Shield, Zap, Eye, Play } from 'lucide-react';

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
    body: 'Eight specialist AI agents scan IAM, S3, EC2, VPCs, security groups, RDS, Lambda, and CloudTrail in parallel against CIS benchmarks.',
  },
  {
    icon: <Zap size={18} className="text-violet-400" />,
    n: '03',
    title: 'Approve and fix',
    body: 'Review each finding individually. Approve the ones you want fixed — Remedi runs the fix and verifies it held.',
  },
];

const safeguards = [
  { title: 'Nothing changes without your yes', body: 'The approval gate is enforced in code, not in a prompt. A scan nobody approves aborts after 30 minutes.' },
  { title: 'Protected users stay untouched', body: 'The IAM user Remedi runs as is always protected, plus any users you add to the list.' },
  { title: 'Least-privilege access', body: 'A CloudFormation stack creates the one IAM user Remedi uses. Delete the stack to revoke it.' },
  { title: 'Keys encrypted, then gone', body: 'AWS keys are Fernet-encrypted at rest and purged after 30 idle minutes or when you sign out.' },
  { title: 'Every fix is re-checked', body: 'A verifier re-audits each fixed resource and only calls the scan secure if the problem is gone.' },
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
        <nav className="relative z-10 flex items-center justify-between px-4 sm:px-8 py-5 border-b border-white/5">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-violet-500/15 border border-violet-500/25 flex items-center justify-center">
              <ShieldCheck size={15} className="text-violet-400" />
            </div>
            <span className="font-semibold tracking-tight text-white">Remedi</span>
            <span className="text-xs font-medium px-1.5 py-0.5 rounded-full border font-mono-code" style={{ color: '#f59e0b', borderColor: 'rgba(245,158,11,0.25)', background: 'rgba(245,158,11,0.08)' }}>beta</span>
          </div>
          <div className="flex items-center gap-3 sm:gap-6">
            <Link href="/about" className="hidden sm:block text-sm text-slate-400 hover:text-white transition-colors">About</Link>
            <Link href="/developer" className="hidden sm:block text-sm text-slate-400 hover:text-white transition-colors">Built by</Link>
            {isSignedIn ? (
              <>
                <Link href="/dashboard" className="text-sm bg-violet-500 hover:bg-violet-400 text-white font-semibold px-4 py-2 rounded-lg transition-colors">
                  Dashboard
                </Link>
                <button onClick={() => signOut({ redirectUrl: '/' })} className="hidden sm:block text-sm text-slate-400 hover:text-white transition-colors">
                  Sign out
                </button>
              </>
            ) : (
              <>
                <Link href="/sign-in" className="hidden sm:block text-sm text-slate-400 hover:text-white transition-colors">Sign in</Link>
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
            <h1 className="text-5xl sm:text-6xl font-bold tracking-tight leading-[1.1] mb-6 text-white">
              Your AWS account<br />
              has vulnerabilities.{' '}
              <span className="text-gradient">We fix them.</span>
            </h1>
            <p className="text-slate-400 text-lg mb-10 leading-relaxed max-w-xl mx-auto">
              Connect your account, get a full security audit across 8 services in minutes, and fix every finding — only after you approve it.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 fade-up delay-2">
              <Link
                href={isSignedIn ? '/dashboard' : '/sign-up'}
                className="inline-flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-6 py-3 rounded-xl transition-all hover:shadow-lg hover:shadow-violet-500/20"
              >
                {isSignedIn ? 'Go to dashboard' : 'Scan my AWS account'} <ArrowRight size={16} />
              </Link>
              <Link
                href="/demo"
                className="inline-flex items-center gap-2 text-sm font-medium text-slate-200 border border-white/10 hover:border-violet-500/40 hover:bg-violet-500/5 px-5 py-3 rounded-xl transition-colors"
              >
                <Play size={13} className="fill-current text-violet-400" /> Try the demo
              </Link>
              <Link href="/about" className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors px-4 py-3">
                How it works
              </Link>
            </div>
            <p className="mt-4 text-xs text-slate-600">The demo needs no signup and no AWS keys.</p>
          </div>

          {/* Stats row */}
          <div className="flex items-center gap-8 mb-16 fade-up delay-3">
            {[
              { value: '8', label: 'services scanned' },
              { value: '$0.02', label: 'per full scan' },
              { value: '100%', label: 'fixes re-verified' },
            ].map(({ value, label }) => (
              <div key={label} className="text-center">
                <p className="text-2xl font-bold text-white font-mono-code">{value}</p>
                <p className="text-xs text-slate-500 mt-0.5">{label}</p>
              </div>
            ))}
          </div>

          {/* Launch video */}
          <div className="w-full max-w-3xl mb-20 fade-up delay-4">
            <div className="bg-[#111116] border border-white/8 rounded-2xl overflow-hidden shadow-2xl shadow-violet-900/20">
              <video
                src="/remedi-launch.mp4"
                poster="/remedi-launch.jpg"
                // browsers only autoplay muted video; React doesn't always emit the
                // muted attribute in server HTML, so set it on the element too
                ref={el => { if (el) { el.muted = true; el.play().catch(() => {}); } }}
                autoPlay
                muted
                loop
                playsInline
                preload="auto"
                disablePictureInPicture
                aria-hidden
                tabIndex={-1}
                className="w-full aspect-video block pointer-events-none"
              />
            </div>
            <p className="text-center mt-3 text-xs text-slate-600">21 seconds · a real run against the simulated demo account</p>
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

          {/* Safeguards */}
          <div className="w-full max-w-3xl mb-28">
            <p className="text-xs font-mono-code text-slate-500 uppercase tracking-widest text-center mb-10">Why it&apos;s safe to point at your account</p>
            <div className="bg-[#111116] border border-white/8 rounded-2xl divide-y divide-white/5">
              {safeguards.map(({ title, body }) => (
                <div key={title} className="flex items-start gap-4 px-6 py-5">
                  <CheckCircle size={16} className="text-violet-400 shrink-0 mt-0.5" />
                  <div>
                    <h3 className="font-semibold text-white text-sm">{title}</h3>
                    <p className="text-slate-500 text-sm leading-relaxed mt-1">{body}</p>
                  </div>
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
            <p className="mt-4 text-xs text-slate-600">
              Just looking?{' '}
              <Link href="/demo" className="text-slate-400 hover:text-white underline underline-offset-2 transition-colors">
                Watch a demo scan
              </Link>
            </p>
          </div>

        </main>

        <footer className="relative z-10 border-t border-white/5 px-4 sm:px-8 py-6 flex flex-col sm:flex-row items-center gap-3 sm:justify-between text-xs text-slate-600">
          <div className="flex items-center gap-2">
            <ShieldCheck size={13} className="text-violet-500/50" />
            <span>Remedi</span>
          </div>
          <span className="text-center">© {new Date().getFullYear()} — AWS credentials encrypted at rest, deleted on sign out, auto-expire after 30 min of inactivity</span>
          <div className="flex items-center gap-4">
            <Link href="/about" className="hover:text-slate-400 transition-colors">About</Link>
            <Link href="/developer" className="hover:text-slate-400 transition-colors">Built by</Link>
          </div>
        </footer>
      </div>
    </>
  );
}
