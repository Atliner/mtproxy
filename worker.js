/**
 * ============================================================================
 *  Telegram MTProto Relay — Cloudflare Worker
 * ============================================================================
 *
 *  این ورکر یک تونل رایگان بین کلودفلر و دیتاسنترهای تلگرام است.
 *
 *  معماری:
 *
 *    تلگرام (موبایل/دسکتاپ)
 *        │  MTProto (TCP)
 *        ▼
 *    اپ پراکسی محلی (tg-ws-proxy / TG-Proxy) — روی دستگاه خودتان
 *        │  WebSocket امن (WSS / 443)
 *        ▼
 *    این ورکر  ←────────────  شما این کد را اینجا مستقر (Deploy) می‌کنید
 *        │  TCP خام پورت 443
 *        ▼
 *    دیتاسنترهای تلگرام (DC1..DC5)
 *
 *  مسیرها:
 *    GET /                                        صفحه‌ی راهنما
 *    GET /health                                  وضعیت و اطلاعات DCها (JSON)
 *    WSS /apiws?dst=<IP-DC>&port=443              تونل TCP (سازگار با tg-ws-proxy)
 *    WSS /<host>.web.telegram.org/apiws           پل WebSocket برای تلگرام وب
 *
 *  نکته‌ی امنیتی: مقصد تونل فقط به رنج‌های IP متعلق به تلگرام (AS62041)
 *  محدود شده است؛ هیچ ترافیک دیگری از ورکر شما عبور نمی‌کند.
 * ============================================================================
 */

import { connect } from "cloudflare:sockets";

/* ------------------------------------------------------------------ */
/*  رنج‌های IP متعلق به تلگرام (Telegram Messenger Network, AS62041)   */
/* ------------------------------------------------------------------ */

const TELEGRAM_CIDRS_V4 = [
  "149.154.160.0/20", // DC1..DC4 (149.154.160.x – 149.154.175.x)
  "91.108.4.0/22",
  "91.108.8.0/22",
  "91.108.12.0/22",
  "91.108.16.0/22",
  "91.108.20.0/22",
  "91.108.56.0/22", // DC5
];

const TELEGRAM_CIDRS_V6 = [
  "2001:67c:4e8::/48",
  "2001:b28:f23c::/48",
  "2001:b28:f23d::/48",
  "2001:b28:f23f::/48",
];

// دامنه‌های مجاز برای حالت پل WebSocket (تلگرام وب)
const TELEGRAM_WS_HOST_RE = /^(?:[a-z0-9-]+\.)+web\.telegram\.org$/i;

const DC_INFO = [
  { id: 1, country: "آمریکا، میامی", ip: "149.154.175.50", ws: "pluto.web.telegram.org" },
  { id: 2, country: "هلند، آمستردام", ip: "149.154.167.50", ws: "venus.web.telegram.org" },
  { id: 3, country: "آمریکا، میامی", ip: "149.154.175.100", ws: "aurora.web.telegram.org" },
  { id: 4, country: "هلند، آمستردام", ip: "149.154.167.91", ws: "vesta.web.telegram.org" },
  { id: 5, country: "سنگاپور", ip: "91.108.56.130", ws: "flora.web.telegram.org" },
];

/* ------------------------------------------------------------------ */
/*  ابزارهای بررسی IP / CIDR                                            */
/* ------------------------------------------------------------------ */

export function parseIp(ip) {
  if (typeof ip !== "string" || ip.length === 0 || ip.length > 45) return null;
  if (ip.includes(":")) return parseV6(ip);
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8n) | BigInt(v);
  }
  return { n, bits: 32 };
}

function parseV6(input) {
  let ip = input;
  if (ip.startsWith("[")) ip = ip.slice(1, ip.endsWith("]") ? -1 : 0);
  if (ip.includes("%")) ip = ip.split("%")[0]; // zone id را نادیده بگیر
  const halves = ip.split("::");
  if (halves.length > 2) return null;

  const parseGroups = (s) => {
    if (s === "") return [];
    const out = [];
    for (const h of s.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
      out.push(parseInt(h, 16));
    }
    return out;
  };

  let groups;
  if (halves.length === 1) {
    groups = parseGroups(halves[0]);
    if (!groups || groups.length !== 8) return null;
  } else {
    const left = parseGroups(halves[0]);
    const right = parseGroups(halves[1]);
    if (!left || !right) return null;
    const missing = 8 - left.length - right.length;
    if (missing < 0) return null;
    groups = [...left, ...new Array(missing).fill(0), ...right];
  }

  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(g);
  return { n, bits: 128 };
}

export function ipInCidr(ip, cidr) {
  const parsed = parseIp(ip);
  if (!parsed) return false;
  const [addr, lenStr] = cidr.split("/");
  const net = parseIp(addr);
  if (!net || net.bits !== parsed.bits) return false;
  const len = Number(lenStr);
  if (!Number.isInteger(len) || len < 0 || len > parsed.bits) return false;
  if (len === 0) return true;
  const shift = BigInt(parsed.bits - len);
  return (parsed.n >> shift) === (net.n >> shift);
}

export function isTelegramIp(ip) {
  const list = typeof ip === "string" && ip.includes(":") ? TELEGRAM_CIDRS_V6 : TELEGRAM_CIDRS_V4;
  return list.some((cidr) => ipInCidr(ip, cidr));
}

export function isTelegramWsHost(host) {
  return TELEGRAM_WS_HOST_RE.test(host);
}

/* ------------------------------------------------------------------ */
/*  ابزارهای WebSocket / TCP                                           */
/* ------------------------------------------------------------------ */

async function toU8(data) {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data && typeof data.arrayBuffer === "function") {
    return new Uint8Array(await data.arrayBuffer());
  }
  throw new Error("نوع پیام WebSocket پشتیبانی نمی‌شود");
}

/**
 * حالت ۱: تونل TCP — سازگار با tg-ws-proxy / tg-ws-proxy-rs / TG-Proxy (اندروید)
 * کلاینت به /apiws?dst=<IP-DC> وصل می‌شود و ورکر یک سوکت TCP خام به DC باز می‌کند.
 */
function openTcpTunnel(ws, request) {
  const url = new URL(request.url);
  let dst = (url.searchParams.get("dst") || "").replace(/^\[|\]$/g, "").trim();
  let port = Number.parseInt(url.searchParams.get("port") || "443", 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) port = 443;

  ws.accept();

  if (!dst) {
    ws.close(1008, "پارامتر dst مشخص نشده است");
    return;
  }
  if (!isTelegramIp(dst)) {
    ws.close(1008, "مقصد مجاز نیست — فقط دیتاسنترهای تلگرام");
    return;
  }

  let socket;
  try {
    socket = connect({ hostname: dst, port, secureTransport: "off" });
  } catch {
    try { ws.close(1011, "اتصال به DC برقرار نشد"); } catch {}
    return;
  }

  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();

  // کلاینت (WS) → تلگرام (TCP)
  ws.addEventListener("message", async (event) => {
    try {
      await writer.write(await toU8(event.data));
    } catch {
      try { ws.close(1011, "نوشتن روی TCP شکست خورد"); } catch {}
    }
  });

  ws.addEventListener("close", () => {
    try { writer.close(); } catch {}
    try { socket.close(); } catch {}
  });
  ws.addEventListener("error", () => {
    try { socket.close(); } catch {}
  });

  // تلگرام (TCP) → کلاینت (WS)
  (async () => {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) ws.send(value);
      }
    } catch {
      // سوکت DC بسته شد — پایین حلقه همه‌چیز را می‌بندد
    } finally {
      try { ws.close(1000, "اتصال DC بسته شد"); } catch {}
      try { reader.releaseLock(); } catch {}
      try { socket.close(); } catch {}
    }
  })();
}

/**
 * حالت ۲: پل WebSocket — برای تلگرام وب (Telegram Web / TG-WS-API style)
 * کلاینت به wss://<worker>/<host>.web.telegram.org/apiws وصل می‌شود.
 */
function openWsBridge(ws, request, host) {
  const url = new URL(request.url);
  const prefix = "/" + host;
  const path = url.pathname.startsWith(prefix) ? url.pathname.slice(prefix) : "/apiws";
  const upstreamUrl = "wss://" + host + (path || "/apiws") + url.search;

  ws.accept();

  let upstream;
  try {
    const protoHeader = request.headers.get("Sec-WebSocket-Protocol");
    const protocols = protoHeader
      ? protoHeader.split(",").map((s) => s.trim()).filter(Boolean)
      : undefined;
    upstream = new WebSocket(upstreamUrl, protocols);
  } catch {
    try { ws.close(1011, "ایجاد اتصال بالادست شکست خورد"); } catch {}
    return;
  }

  let opened = false;
  const pending = [];

  upstream.addEventListener("open", () => {
    opened = true;
    for (const chunk of pending) {
      try { upstream.send(chunk); } catch {}
    }
    pending.length = 0;
  });

  // تلگرام وب (WSS) → کلاینت
  upstream.addEventListener("message", (event) => {
    try { ws.send(event.data); } catch {}
  });
  upstream.addEventListener("close", () => {
    try { ws.close(1000, "بالادست بسته شد"); } catch {}
  });
  upstream.addEventListener("error", () => {
    try { ws.close(1011, "خطای بالادست"); } catch {}
  });

  // کلاینت → تلگرام وب (WSS)
  ws.addEventListener("message", async (event) => {
    try {
      const chunk = await toU8(event.data);
      if (opened) upstream.send(chunk);
      else pending.push(chunk);
    } catch {}
  });
  ws.addEventListener("close", () => {
    try { upstream.close(); } catch {}
  });
  ws.addEventListener("error", () => {
    try { upstream.close(); } catch {}
  });
}

/* ------------------------------------------------------------------ */
/*  پاسخ‌ها و صفحه‌ی راهنما                                            */
/* ------------------------------------------------------------------ */

function wsResponse(client, request) {
  const headers = {};
  const proto = request.headers.get("Sec-WebSocket-Protocol");
  if (proto) headers["Sec-WebSocket-Protocol"] = proto.split(",")[0].trim();
  return new Response(null, { status: 101, webSocket: client, headers });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function landingPage(host) {
  const domain = host || "YOUR-WORKER.workers.dev";
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ریله‌ی MTProto تلگرام — Cloudflare Worker</title>
<style>
  :root { --bg:#0f1419; --card:#1a2029; --line:#2a3441; --fg:#e6edf3; --mut:#8b98a8; --ok:#3fb950; --acc:#58a6ff; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
        font-family:Vazirmatn,Segoe UI,Tahoma,sans-serif; line-height:1.9; padding:24px 16px; }
  .wrap { max-width:860px; margin:0 auto; }
  h1 { font-size:1.5rem; margin:0 0 4px; }
  .sub { color:var(--mut); margin:0 0 24px; font-size:.95rem; }
  .ok { color:var(--ok); font-weight:700; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:14px;
          padding:18px 20px; margin:16px 0; }
  .card h2 { font-size:1.08rem; margin:0 0 10px; color:var(--acc); }
  code,pre { font-family:ui-monospace,Menlo,Consolas,monospace; direction:ltr;
             text-align:left; unicode-bidi:embed; }
  pre { background:#0b0f14; border:1px solid var(--line); border-radius:10px;
        padding:12px 14px; overflow-x:auto; font-size:.85rem; margin:8px 0; }
  p,li { font-size:.95rem; }
  .mut { color:var(--mut); }
  a { color:var(--acc); }
  .flow { text-align:center; font-size:.9rem; }
  .flow b { color:var(--ok); }
  table { width:100%; border-collapse:collapse; font-size:.9rem; }
  th,td { border:1px solid var(--line); padding:6px 10px; text-align:right; }
  th { background:#0b0f14; }
  .step { margin:6px 0; }
  .num { display:inline-flex; width:24px; height:24px; border-radius:50%;
         background:var(--acc); color:#0b0f14; align-items:center; justify-content:center;
         font-weight:700; font-size:.85rem; margin-left:6px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>🚀 ریله‌ی MTProto تلگرام روی Cloudflare Worker</h1>
  <p class="sub">وضعیت: <span class="ok">✅ ورکر فعال است</span> &nbsp;|&nbsp; دامنه: <code>${domain}</code></p>

  <div class="card">
    <h2>این ورکر چطور کار می‌کند؟</h2>
    <p class="flow">
      تلگرام (موبایل/دسکتاپ) &nbsp;←&nbsp; <b>پراکسی محلی</b> روی دستگاه شما &nbsp;←&nbsp;
      <b>این ورکر</b> (WSS) &nbsp;←&nbsp; TCP:443 &nbsp;←&nbsp; دیتاسنتر تلگرام
    </p>
    <p class="mut">
      ⚠️ ورکر کلودفلر سوکت TCP ورودی ندارد و به‌تنهایی نمی‌تواند پراکسی MTProto باشد؛
      بنابراین به یک برنامه‌ی کوچکِ محلی نیاز دارید که پروتکل MTProto را روی گوشی/کامپیوتر
      شما صحبت کند و ترافیک را به‌صورت WebSocket از داخل این ورکر عبور دهد.
      این ورکر فقط به دیتاسنترهای تلگرام وصل می‌شود (فهرست سفید IP) و قابل استفاده برای
      ترافیک دیگر نیست.
    </p>
  </div>

  <div class="card">
    <h2>💻 کامپیوتر (ویندوز/لینوکس/مک) — tg-ws-proxy</h2>
    <p class="step"><span class="num">۱</span> برنامه‌ی <b>tg-ws-proxy</b> را از
      <a href="https://github.com/Flowseal/tg-ws-proxy/releases" target="_blank">این آدرس</a>
      دانلود و اجرا کنید (یا نسخه‌ی لینوکس: <code>tg-ws-proxy-rs</code>).</p>
    <p class="step"><span class="num">۲</span> دامنه‌ی ورکر خود را در تنظیمات
      «Cloudflare Worker» برنامه وارد کنید — یا هنگام اجرا:</p>
    <pre>tg-ws-proxy --cf-worker-domain ${domain}</pre>
    <p class="step"><span class="num">۳</span> در تلگرام: <b>تنظیمات ← پیشرفته ← نوع اتصال ← افزودن پروکسی ← MTProto</b></p>
    <p>سرور: <code>127.0.0.1</code> &nbsp; پورت: <code>1443</code> &nbsp; Secret: همان مقداری که برنامه نمایش می‌دهد.</p>
  </div>

  <div class="card">
    <h2>📱 اندروید — اپلیکیشن TG Proxy</h2>
    <p class="step"><span class="num">۱</span> اپ <b>TG Proxy</b> را از
      <a href="https://github.com/Dushnyj/TG-Proxy/releases" target="_blank">اینجا</a> نصب کنید.</p>
    <p class="step"><span class="num">۲</span> در بخش مسیرها (Routes)، گزینه‌ی
      <b>Cloudflare Worker</b> را انتخاب و دامنه‌ی زیر را وارد کنید:</p>
    <pre>${domain}</pre>
    <p class="step"><span class="num">۳</span> اپ به‌صورت خودکار لینک <code>tg://proxy</code>
      (127.0.0.1:1443) را برای افزودن به تلگرام می‌سازد.</p>
  </div>

  <div class="card">
    <h2>🌐 تلگرام وب (Telegram Web / مرورگر)</h2>
    <p>در تنظیمات پروکسی کلاینت وب (مثلاً Telegram Web A MOD)، دامنه‌ی پروکسی را این مقدار بگذارید:</p>
    <pre>${domain}</pre>
    <p class="mut">اتصال به‌شکل <code>wss://${domain}/venus.web.telegram.org/apiws</code> برقرار می‌شود.</p>
  </div>

  <div class="card">
    <h2>🗄️ دیتاسنترهای تلگرام</h2>
    <table>
      <tr><th>DC</th><th>موقعیت</th><th>IP</th><th>دامنه‌ی WS</th></tr>
      ${DC_INFO.map((d) => `<tr><td>${d.id}</td><td>${d.country}</td><td><code>${d.ip}</code></td><td><code>${d.ws}</code></td></tr>`).join("\n      ")}
    </table>
    <p class="mut">بررسی سلامت ورکر: <a href="/health"><code>/health</code></a></p>
  </div>
</div>
</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/*  روتر اصلی                                                          */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isWs = (request.headers.get("Upgrade") || "").toLowerCase() === "websocket";
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (isWs) {
      // حالت ۱: تونل TCP سازگار با tg-ws-proxy
      if (url.pathname === "/apiws") {
        const pair = new WebSocketPair();
        openTcpTunnel(pair[1], request);
        return wsResponse(pair[0], request);
      }

      // حالت ۲: پل WSS برای تلگرام وب — /<host>.web.telegram.org/...
      const m = url.pathname.match(/^\/((?:[a-z0-9-]+\.)+web\.telegram\.org)(\/.*)?$/i);
      if (m && env?.ALLOW_WS_BRIDGE !== "0") {
        const host = m[1].toLowerCase();
        if (isTelegramWsHost(host)) {
          const pair = new WebSocketPair();
          openWsBridge(pair[1], request, host);
          return wsResponse(pair[0], request);
        }
      }

      return new Response("مسیر WebSocket یافت نشد", {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "text/plain; charset=utf-8" },
      });
    }

    if (url.pathname === "/health" || url.pathname === "/status") {
      return jsonResponse({
        ok: true,
        service: "telegram-mtproto-relay",
        time: new Date().toISOString(),
        routes: {
          tcpTunnel: "/apiws?dst=<TELEGRAM_DC_IP>&port=443",
          wsBridge: "/<host>.web.telegram.org/apiws",
        },
        datacenters: DC_INFO,
        allowedV4Cidrs: TELEGRAM_CIDRS_V4,
      });
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      return new Response(landingPage(url.hostname), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    return new Response("Not found", {
      status: 404,
      headers: { ...corsHeaders, "Content-Type": "text/plain; charset=utf-8" },
    });
  },
};
