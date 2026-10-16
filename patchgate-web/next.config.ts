import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  // Keep the dev badge out of the UI (and out of review screenshots).
  devIndicators: false,
  // `next dev` only: the hosted lab serves the dev server as https://patchgate.patchgate-lab.internal:3443 (lab/README.md).
  allowedDevOrigins: ["patchgate.patchgate-lab.internal"],
  cacheComponents: true,
  partialPrefetching: true,
  // Production image (Dockerfile): self-contained .next/standalone/server.js with only the traced
  // node_modules. Supported with cacheComponents (docs: guides/self-hosting "Cache Components").
  output: "standalone",
  // Prisma loads its query engine via a computed path; make sure the trace always carries it.
  outputFileTracingIncludes: {
    "/*": ["./node_modules/.prisma/client/libquery_engine-*", "./node_modules/.prisma/client/schema.prisma"],
  },
  // Version-skew protection across web instances during rolling upgrades (set by the Docker build).
  deploymentId: process.env.PATCHGATE_BUILD_ID || undefined,
  poweredByHeader: false,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
