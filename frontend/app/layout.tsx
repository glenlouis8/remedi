import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { ClerkProvider } from "@clerk/nextjs";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const SITE_URL = "https://remedi-kohl-seven.vercel.app";
const DESCRIPTION =
  "Connect your AWS account, get a full security audit across 8 services in minutes, and auto-fix every finding — only after you approve it.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: "Remedi — AI AWS security scanning & auto-remediation",
  description: DESCRIPTION,
  openGraph: {
    title: "Remedi — AI AWS security scanning & auto-remediation",
    description: DESCRIPTION,
    url: SITE_URL,
    siteName: "Remedi",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Remedi — AI AWS security scanning & auto-remediation",
    description: DESCRIPTION,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <ClerkProvider publishableKey={process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY}>
      <html lang="en">
        <body
          className={`${geistSans.variable} ${geistMono.variable} antialiased`}
        >
          {children}
        </body>
      </html>
    </ClerkProvider>
  );
}
