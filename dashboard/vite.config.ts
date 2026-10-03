import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const apiOrigin = process.env.INSIDIA_API_ORIGIN ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/healthz": apiOrigin,
      "/readyz": apiOrigin,
    },
  },
  preview: {
    port: 5173,
    proxy: {
      "/healthz": apiOrigin,
      "/readyz": apiOrigin,
    },
  },
});
