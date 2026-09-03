import { spawnSync } from "node:child_process";

const command = process.platform === "win32"
  ? {
      file: process.env.ComSpec ?? "cmd.exe",
      args: ["/d", "/s", "/c", "npm --prefix frontend run build"],
    }
  : {
      file: "npm",
      args: ["--prefix", "frontend", "run", "build"],
    };
const result = spawnSync(command.file, command.args, {
  stdio: "inherit",
});

if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
