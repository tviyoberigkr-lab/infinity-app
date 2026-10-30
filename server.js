// Infinity — тонкий вузол доступу перед статичним застосунком.
// Жодних залежностей — лише вбудовані модулі Node, щоб деплой лишався простим.
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const PORT = process.env.PORT || 10000;

const AUTH_USER = process.env.AUTH_USER || "";
const AUTH_PASS = process.env.AUTH_PASS || ""; // формат "salt:hash" (scrypt, hex)
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const SESSION_DAYS = 30;

if (!AUTH_USER || !AUTH_PASS || !SESSION_SECRET) {
  console.error("Відсутні змінні середовища AUTH_USER / AUTH_PASS / SESSION_SECRET — застосунок не може перевіряти вхід і не запуститься.");
  process.exit(1);
}

// Файли, доступні без входу: іконки, маніфест, шрифти застосунку, сама сторінка входу.
const PUBLIC_PATHS = new Set([
  "/login", "/login.html",
  "/manifest-v5.json", "/sw.js",
  "/apple-touch-icon-v5.png", "/icon-1024-v4.png",
  "/icon-192-v5.png", "/icon-192-maskable-v5.png",
  "/icon-512-v5.png", "/icon-512-maskable-v5.png",
  "/logo-tile-v5.png", "/header-inf-v5.png",
  "/title-infiniti-ink.png", "/title-infiniti-white.png",
]);
const SPLASH_RE = /^\/splash-\d+x\d+\.png$/;

const MIME = {
  ".html": "text/html; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".js": "text/javascript; charset=utf-8", ".png": "image/png", ".svg": "image/svg+xml",
  ".ico": "image/x-icon", ".webmanifest": "application/manifest+json",
};

// ---- Обмеження спроб входу (в пам'яті процесу) ----
const attempts = new Map(); // ip -> {count, firstAt}
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 8;

function tooManyAttempts(ip) {
  const a = attempts.get(ip);
  if (!a) return false;
  if (Date.now() - a.firstAt > WINDOW_MS) { attempts.delete(ip); return false; }
  return a.count >= MAX_ATTEMPTS;
}
function recordFailure(ip) {
  const a = attempts.get(ip);
  if (!a || Date.now() - a.firstAt > WINDOW_MS) attempts.set(ip, { count: 1, firstAt: Date.now() });
  else a.count++;
}
function clearFailures(ip) { attempts.delete(ip); }

// ---- Сесія: підписана кука без збереження стану на сервері (переживає перезапуск) ----
function sign(payload) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
}
function makeSessionCookie() {
  const exp = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const payload = String(exp);
  const sig = sign(payload);
  const value = Buffer.from(payload + "." + sig).toString("base64url");
  return `inf_sess=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 24 * 60 * 60}`;
}
function clearSessionCookie() {
  return "inf_sess=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}
function isAuthed(req) {
  const cookieHeader = req.headers.cookie || "";
  const m = cookieHeader.match(/(?:^|;\s*)inf_sess=([^;]+)/);
  if (!m) return false;
  let decoded;
  try { decoded = Buffer.from(m[1], "base64url").toString("utf8"); } catch { return false; }
  const idx = decoded.lastIndexOf(".");
  if (idx < 0) return false;
  const payload = decoded.slice(0, idx), sig = decoded.slice(idx + 1);
  const expected = sign(payload);
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  const exp = Number(payload);
  return Number.isFinite(exp) && Date.now() < exp;
}

function checkCredentials(user, pass) {
  if (typeof user !== "string" || typeof pass !== "string") return false;
  const userOk = user.length === AUTH_USER.length &&
    crypto.timingSafeEqual(Buffer.from(user), Buffer.from(AUTH_USER));
  const [salt, hash] = AUTH_PASS.split(":");
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(pass, salt, 64).toString("hex");
  const passOk = candidate.length === hash.length &&
    crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(hash));
  return userOk && passOk;
}

function send(res, status, body, headers) {
  res.writeHead(status, Object.assign({ "Content-Type": "text/plain; charset=utf-8" }, headers || {}));
  res.end(body);
}
function sendFile(res, filePath, status) {
  const ext = path.extname(filePath);
  const type = MIME[ext] || "application/octet-stream";
  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, "Не знайдено");
    res.writeHead(status || 200, { "Content-Type": type, "Cache-Control": ext === ".html" ? "no-store" : "public, max-age=3600" });
    res.end(data);
  });
}
function readBody(req, limit, cb) {
  let size = 0, chunks = [];
  req.on("data", (c) => { size += c.length; if (size > limit) { req.destroy(); } else chunks.push(c); });
  req.on("end", () => cb(Buffer.concat(chunks).toString("utf8")));
}
function clientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;

  if (req.method === "POST" && p === "/api/login") {
    const ip = clientIp(req);
    if (tooManyAttempts(ip)) return send(res, 429, JSON.stringify({ error: "locked" }), { "Content-Type": "application/json" });
    readBody(req, 4096, (raw) => {
      let data = {};
      try { data = JSON.parse(raw); } catch { }
      const ok = checkCredentials(data.user, data.pass);
      if (!ok) {
        recordFailure(ip);
        // невелика затримка проти перебору
        return setTimeout(() => send(res, 401, JSON.stringify({ error: "bad_credentials" }), { "Content-Type": "application/json" }), 300);
      }
      clearFailures(ip);
      send(res, 200, JSON.stringify({ ok: true }), { "Content-Type": "application/json", "Set-Cookie": makeSessionCookie() });
    });
    return;
  }

  if (req.method === "POST" && p === "/api/logout") {
    send(res, 200, JSON.stringify({ ok: true }), { "Content-Type": "application/json", "Set-Cookie": clearSessionCookie() });
    return;
  }

  if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "Метод не підтримується");

  // Публічні шляхи — завжди доступні (іконки/маніфест/сторінка входу)
  if (p === "/login" || p === "/login.html") return sendFile(res, path.join(ROOT, "login.html"));
  if (PUBLIC_PATHS.has(p) || SPLASH_RE.test(p)) {
    const safe = path.normalize(p).replace(/^(\.\.[\/\\])+/, "");
    return sendFile(res, path.join(ROOT, safe));
  }

  // Усе інше (насамперед "/" і "/index.html") — лише після входу
  if (p === "/" || p === "/index.html") {
    if (!isAuthed(req)) return send(res, 302, "", { Location: "/login" });
    return sendFile(res, path.join(ROOT, "index.html"));
  }

  // Будь-які інші файли з кореня репозиторію (напр. майбутні ассети) — теж лише після входу
  const safe = path.normalize(p).replace(/^(\.\.[\/\\])+/, "");
  const filePath = path.join(ROOT, safe);
  if (!filePath.startsWith(ROOT)) return send(res, 400, "Некоректний шлях");
  if (!isAuthed(req)) return send(res, 302, "", { Location: "/login" });
  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, "Не знайдено");
    sendFile(res, filePath);
  });
});

server.listen(PORT, () => console.log("Infinity gate listening on " + PORT));
