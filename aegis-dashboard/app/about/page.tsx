'use client';

import Link from 'next/link';
import { useAuth, useClerk } from '@clerk/nextjs';
import { ShieldCheck, ArrowRight } from 'lucide-react';

export default function AboutPage() {
  const { isSignedIn } = useAuth();
  const { signOut } = useClerk();

  return (
    <div className="min-h-screen bg-white text-slate-900 flex flex-col">

      {/* Nav */}
      <nav className="flex items-center justify-between px-8 py-4 border-b border-slate-200">
        <Link href="/" className="flex items-center gap-2">
          <ShieldCheck className="text-emerald-600" size={20} />
          <span className="font-semibold tracking-tight text-slate-900">Remedi</span>
        </Link>
        <div className="flex items-center gap-4">
          <Link href="/docs"  className="text-sm text-slate-500 hover:text-slate-900 transition-colors">Docs</Link>
          <Link href="/about" className="text-sm text-slate-900 font-medium">About</Link>
          {isSignedIn ? (
            <>
              <Link href="/dashboard" className="text-sm bg-emerald-500 hover:bg-emerald-600 text-white font-semibold px-4 py-2 rounded-lg transition-colors">
                Dashboard
              </Link>
              <button onClick={() => signOut({ redirectUrl: '/' })} className="text-sm text-slate-500 hover:text-slate-900 transition-colors">
                Sign out
              </button>
            </>
          ) : (
            <>
              <Link href="/sign-in" className="text-sm text-slate-500 hover:text-slate-900 transition-colors">Sign in</Link>
              <Link href="/sign-up" className="text-sm bg-emerald-500 hover:bg-emerald-600 text-white font-semibold px-4 py-2 rounded-lg transition-colors">
                Try free
              </Link>
            </>
          )}
        </div>
      </nav>

      <main className="flex-1 max-w-xl mx-auto px-6 py-24 w-full">

        <div className="flex items-center gap-2 mb-6">
          <ShieldCheck className="text-emerald-600" size={22} />
          <span className="font-semibold text-slate-900">Remedi</span>
        </div>

        <h1 className="text-3xl font-bold text-slate-900 mb-4 leading-snug">
          AWS security scanning<br />and auto-remediation.
        </h1>

        <p className="text-slate-500 leading-relaxed mb-6">
          Remedi audits your AWS account across IAM, S3, EC2, VPC, Security Groups, RDS, Lambda, and CloudTrail — then fixes every finding automatically after you approve.
        </p>

        <p className="text-slate-500 leading-relaxed mb-10">
          Nothing is changed without your review. Your credentials are encrypted, never logged, and deleted automatically after 30 minutes of inactivity.
        </p>

        <div className="space-y-3 text-sm text-slate-500 mb-12">
          {[
            'Full audit across 8 AWS services in parallel',
            'Structured findings report with severity levels',
            'One-click approval before any fix is applied',
            'Verification pass after every remediation',
          ].map(item => (
            <div key={item} className="flex items-center gap-2.5">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
              {item}
            </div>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <Link
            href={isSignedIn ? '/dashboard' : '/sign-up'}
            className="inline-flex items-center gap-2 bg-emerald-500 hover:bg-emerald-600 text-white font-semibold px-5 py-2.5 rounded-lg transition-colors text-sm"
          >
            {isSignedIn ? 'Go to dashboard' : 'Get started free'} <ArrowRight size={14} />
          </Link>
          <Link href="/docs" className="text-sm text-slate-500 hover:text-slate-900 transition-colors">
            Read the docs →
          </Link>
        </div>

      </main>

      <footer className="border-t border-slate-200 px-8 py-5 text-center text-slate-400 text-sm">
        © {new Date().getFullYear()} Remedi
      </footer>
    </div>
  );
}
