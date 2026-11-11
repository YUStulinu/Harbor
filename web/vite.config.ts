/// <reference types="vitest/config" />
import { defineConfig } from "vite";

// In development `harbor serve` runs separately (in WSL, port 8800); in production it serves web/dist.
export default defineConfig({
  base: "./",
  server: { proxy: { "/api": "http://127.0.0.1:8800" } },
  test: { environment: "node" },
});
