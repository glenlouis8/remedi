import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Remedi — AI AWS security scanning & auto-remediation";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OGImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background:
            "radial-gradient(1000px 500px at 15% 0%, rgba(139,92,246,0.22), transparent), #09090b",
          padding: "72px",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
          <svg width="56" height="56" viewBox="0 0 32 32" fill="none">
            <rect width="32" height="32" rx="8" fill="#1a0a2e" />
            <path
              d="M16 4L6 8.5V16c0 5.25 4.2 10.15 10 11.5C21.8 26.15 26 21.25 26 16V8.5L16 4Z"
              fill="#8b5cf6"
            />
            <path
              d="M13 16.5l2 2 4-4"
              stroke="white"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span
            style={{ color: "#a78bfa", fontSize: "30px", fontWeight: 700, letterSpacing: "-0.5px" }}
          >
            Remedi
          </span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
          <div
            style={{
              color: "white",
              fontSize: "68px",
              fontWeight: 800,
              lineHeight: 1.1,
              letterSpacing: "-2px",
              display: "flex",
              flexWrap: "wrap",
            }}
          >
            Your AWS account has vulnerabilities.&nbsp;
            <span style={{ color: "#8b5cf6" }}>We fix them.</span>
          </div>
          <div style={{ color: "#a1a1aa", fontSize: "30px", lineHeight: 1.4 }}>
            AI security audit across 8 services · auto-remediation after you approve
          </div>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          {["8 AWS services", "CIS Benchmark", "Human approval gate", "~$0.02 / scan"].map((t) => (
            <div
              key={t}
              style={{
                display: "flex",
                color: "#c4b5fd",
                fontSize: "22px",
                border: "1px solid rgba(139,92,246,0.3)",
                background: "rgba(139,92,246,0.1)",
                padding: "8px 18px",
                borderRadius: "999px",
              }}
            >
              {t}
            </div>
          ))}
        </div>
      </div>
    ),
    size
  );
}
