import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The marketing + auth site. Served at / by the Sentinel API; the dashboard lives at /app.
export default defineConfig({
  base: "/",
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/v1": "http://localhost:8443",
      "/health": "http://localhost:8443",
    },
  },
});
