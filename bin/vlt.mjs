#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ext = process.platform === "win32" ? ".exe" : "";
const bin = path.join(__dirname, "native", `vlt${ext}`);

if (!existsSync(bin)) {
  await import("./install.js");
}
if (!existsSync(bin)) {
  console.error("[ERROR] vlt native binary is not installed (download failed or unsupported platform)");
  process.exit(1);
}
const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
process.exit(result.status ?? 1);
