import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // Served by the Sentinel API under /app (the landing + auth site lives at /).
  base: "/app/",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/v1": "http://localhost:8443",
      "/health": "http://localhost:8443",
      "/mcp": "http://localhost:8443",
    },
  },
});
