// The browser always calls /api on the Next.js server. Next forwards those calls to the
// Spring Boot backend, so the browser never talks to port 8080 directly and no CORS setup
// is needed.
const backend = process.env.THREATLENS_API_URL || "http://localhost:8080";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
  },
};

export default nextConfig;
