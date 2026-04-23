// Tailwind v4 has first-class PostCSS support via the dedicated
// `@tailwindcss/postcss` plugin — no more `tailwindcss` +
// `autoprefixer` dance, and no JS config file (see globals.css for
// the `@theme` block that replaces tailwind.config.ts).

export default {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};
