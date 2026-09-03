import { build } from "esbuild";
import { cp, mkdir, readFile, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
await mkdir("dist", { recursive: true });
await cp("index.html", "dist/index.html");
await cp("styles.css", "dist/styles.css");
await cp("assets", "dist/assets", { recursive: true });
await build({
  entryPoints: ["main.js"],
  bundle: true,
  format: "esm",
  target: ["es2022"],
  outfile: "dist/main.js",
  sourcemap: false,
  minify: true,
});

const bundle = await readFile("dist/main.js", "utf8");
if (!bundle.includes("__TAURI_INTERNALS__")) throw new Error("Tauri v2 core invoke bootstrap is missing from the production bundle.");
if (bundle.includes("window." + "__TAURI__?.core?.invoke")) throw new Error("Legacy global Tauri detection remains in the production bundle.");
