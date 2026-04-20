'use client';

import Link from 'next/link';
import { useAuth, useClerk } from '@clerk/nextjs';
import { ShieldCheck, Mail, Github, Linkedin, Globe } from 'lucide-react';

export default function DeveloperPage() {
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
          <Link href="/about" className="text-sm text-slate-400 hover:text-white transition-colors">About</Link>
          <Link href="/developer" className="text-sm text-violet-400 font-medium">Developer</Link>
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

      <main className="flex-1 flex items-center justify-center px-8">
        <div className="max-w-md w-full space-y-10">

          {/* Identity */}
          <div className="flex items-center gap-5">
            <div className="w-14 h-14 rounded-xl flex items-center justify-center text-xl font-bold text-violet-300 shrink-0"
              style={{ background: 'rgba(139,92,246,0.12)', border: '1px solid rgba(139,92,246,0.2)' }}>
              G
            </div>
            <div>
              <h1 className="text-xl font-semibold text-white">Glen Louis</h1>
              <p className="text-sm text-slate-500 mt-0.5">Software Engineer</p>
            </div>
          </div>

          {/* Bio */}
          <p className="text-slate-400 leading-relaxed">
            I&apos;m a software engineer with a focus on backend systems and AI engineering. I built Remedi as a
            demonstration of what a production-grade AI agent looks like end-to-end — from LangGraph orchestration
            and MCP tooling to a real-time streaming frontend. If you have questions about the project or just want
            to connect, feel free to reach out.
          </p>

          {/* Contact */}
          <div>
            <p className="text-xs font-medium text-slate-600 uppercase tracking-wider mb-3">Contact</p>
            <div className="flex flex-col gap-2">
              <a href="mailto:glen.louis08@gmail.com"
                className="flex items-center gap-3 text-sm text-slate-400 hover:text-white border border-white/8 hover:border-white/20 rounded-lg px-4 py-3 transition-colors">
                <Mail size={14} className="shrink-0" /> glen.louis08@gmail.com
              </a>
              <a href="https://www.linkedin.com/in/marian-glen-louis" target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-3 text-sm text-slate-400 hover:text-white border border-white/8 hover:border-white/20 rounded-lg px-4 py-3 transition-colors">
                <Linkedin size={14} className="shrink-0" /> linkedin.com/in/marian-glen-louis
              </a>
              <a href="https://github.com/glenlouis8" target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-3 text-sm text-slate-400 hover:text-white border border-white/8 hover:border-white/20 rounded-lg px-4 py-3 transition-colors">
                <Github size={14} className="shrink-0" /> github.com/glenlouis8
              </a>
              <a href="https://glen-louis.vercel.app" target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-3 text-sm text-slate-400 hover:text-white border border-white/8 hover:border-white/20 rounded-lg px-4 py-3 transition-colors">
                <Globe size={14} className="shrink-0" /> glen-louis.vercel.app
              </a>
            </div>
          </div>

        </div>
      </main>

      <footer className="border-t border-white/5 px-8 py-6 text-center text-slate-700 text-xs" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
        © {new Date().getFullYear()} Remedi
      </footer>
    </div>
  );
}
