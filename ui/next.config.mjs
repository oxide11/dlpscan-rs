// Next.js config — sets the UI to be served from the /ui subpath
// behind Nginx and emits a fully-static export so the container can
// ship `out/` into Nginx's /srv/ui without a running Node runtime.
//
// When developing locally with `next dev`, drop the basePath override
// by running: `BASE_PATH= pnpm dev` — otherwise `next dev` listens
// at http://localhost:3000/ui/ to match production.

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  basePath: process.env.BASE_PATH ?? "/ui",
  assetPrefix: process.env.BASE_PATH ?? "/ui",
  trailingSlash: true,
  reactStrictMode: true,
  images: {
    // `next/image` requires a running Node server for optimization;
    // static export can't do it. Opt into the unoptimized pipeline
    // so <Image> still renders — just without on-the-fly transforms.
    unoptimized: true,
  },
  experimental: {
    // React 19 strict mode + the App Router's streaming SSR are on
    // by default in Next 15; nothing to toggle here yet.
  },
};

export default nextConfig;
