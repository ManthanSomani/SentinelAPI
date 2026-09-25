import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const source = await readFile(resolve(here, "..", "main.py"), "utf8");
const match = source.match(/HTML_DASHBOARD = """([\s\S]*?)"""\s*\n\s*@app\.get\("\/"/);
const backendUrl = process.env.SENTINEL_BACKEND_URL || "https://sentinelapi-backend-0iao.onrender.com";

if (!match) {
  throw new Error("Could not extract HTML_DASHBOARD from main.py");
}

await mkdir(resolve(here, "dist"), { recursive: true });
const html = match[1].trimStart().replaceAll("http://127.0.0.1:8080", backendUrl);
await writeFile(resolve(here, "dist", "index.html"), html, "utf8");
