'use client';

import Link from 'next/link';
import { useAuth, useClerk } from '@clerk/nextjs';
import { ShieldCheck, ArrowRight } from 'lucide-react';

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

      <main className="relative z-10 flex-1 max-w-xl mx-auto px-6 py-24 w-full">

        <div className="flex items-center gap-2 mb-6">
          <ShieldCheck className="text-violet-400" size={22} />
          <span className="font-semibold text-white">Remedi</span>
        </div>

        <h1 className="text-3xl font-bold text-white mb-4 leading-snug">
          AWS security scanning<br />and auto-remediation.
        </h1>

        <p className="text-slate-400 leading-relaxed mb-6">
          Remedi audits your AWS account across IAM, S3, EC2, VPC, Security Groups, RDS, Lambda, and CloudTrail — then fixes every finding automatically after you approve.
        </p>

        <p className="text-slate-400 leading-relaxed mb-10">
          Nothing is changed without your review. Your credentials are encrypted, never logged, and deleted automatically after 30 minutes of inactivity.
        </p>

        <div className="space-y-3 text-sm text-slate-400 mb-12">
          {[
            'Full audit across 8 AWS services in parallel',
            'Structured findings report with severity levels',
            'One-click approval before any fix is applied',
            'Verification pass after every remediation',
          ].map(item => (
            <div key={item} className="flex items-center gap-2.5">
              <div className="w-1.5 h-1.5 rounded-full bg-violet-500 shrink-0" />
              {item}
            </div>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <Link
            href={isSignedIn ? '/dashboard' : '/sign-up'}
            className="inline-flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold px-5 py-2.5 rounded-lg transition-colors text-sm"
          >
            {isSignedIn ? 'Go to dashboard' : 'Get started free'} <ArrowRight size={14} />
          </Link>
        </div>

      </main>

      <footer className="relative z-10 border-t border-white/5 px-8 py-6 text-center text-slate-600 text-xs" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
        © {new Date().getFullYear()} Remedi
      </footer>
    </div>
  );
}
