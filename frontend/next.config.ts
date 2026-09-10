import type { NextConfig } from "next";

// Fail the production build loudly rather than shipping a bundle that falls back
// to http://localhost:8080 for every API call (also mixed-content-blocked on
// HTTPS) when the deploy env forgot to set this.
if (process.env.NODE_ENV === "production" && !process.env.NEXT_PUBLIC_API_URL) {
  throw new Error(
    "NEXT_PUBLIC_API_URL is not set — refusing to build a production bundle that " +
    "would point every API call at localhost. Set it in the deploy environment."
  );
}

const nextConfig: NextConfig = {
  /* config options here */
};

export default nextConfig;
