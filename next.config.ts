import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Cross-Origin-Opener-Policy", value: "same-origin-allow-popups" },
        ],
      },
    ];
  },
  webpack(config) {
    config.experiments = {
      ...(config.experiments ?? {}),
      asyncWebAssembly: true,
      layers: true,
    };
    return config;
  },
};

export default nextConfig;
