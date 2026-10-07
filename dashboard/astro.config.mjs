import { defineConfig } from "astro/config";
import vercel from "@astrojs/vercel";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  output: "server",
  adapter: vercel(),
  site: "https://sentinel-bench.vercel.app",
  build: { format: "directory" },
  vite: {
    server: { allowedHosts: true },
    plugins: [tailwindcss()],
  },
});
