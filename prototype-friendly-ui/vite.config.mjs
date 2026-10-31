import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  build: {
    outDir: "dist/client",
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (/recharts|d3-|victory-vendor/.test(id)) return "charts";
          if (/react-markdown|remark|rehype|micromark|mdast|hast|unified/.test(id)) return "report-markdown";
          if (/world-atlas|simple-maps|topojson/.test(id)) return "map-geometry";
          return "vendor";
        },
      },
    },
  },
  optimizeDeps: {
    include: ["react", "react-dom/client"],
  },
  server: {
    host: "0.0.0.0",
    allowedHosts: ["terminal.local"],
    proxy: {
      "/api/ui": {
        target: process.env.PCAP_HUNTER_WEB_PROXY || "http://127.0.0.1:8501",
        changeOrigin: true,
      },
    },
    warmup: {
      clientFiles: ["./src/main.jsx"],
    },
  },
  plugins: [react()],
});
