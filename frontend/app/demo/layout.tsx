import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Demo — Remedi",
  description:
    "Watch Remedi scan a simulated AWS account, wait for your approval, fix every finding and verify the fixes. A recorded replay of a real run, no signup needed.",
};

export default function DemoLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
