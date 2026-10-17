import collections
import hashlib
import hmac
import html
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MAC_PORT", "8900"))
DATA_DIR = "/data"
REC_FILE = os.path.join(DATA_DIR, "macs.jsonl")
COOKIE = "mac_sid"

# ---- đọc options của add-on ----
def load_options():
    for p in ("/data/options.json", "/options.json"):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


OPTS = load_options()
USER = str(OPTS.get("username") or "admin")
PASS = str(OPTS.get("password") or "")
TG_TOKEN = str(OPTS.get("telegram_token") or "")
TG_CHAT = str(OPTS.get("telegram_chat_id") or "")

os.makedirs(DATA_DIR, exist_ok=True)
SECRET = secrets.token_bytes(32)

# session đơn giản: token -> hết hạn
SESSIONS = {}
SID_TTL = 12 * 3600


def new_session():
    tok = secrets.token_urlsafe(24)
    SESSIONS[tok] = int(time.time()) + SID_TTL
    return tok


def session_ok(tok):
    exp = SESSIONS.get(tok or "")
    if not exp:
        return False
    if exp < time.time():
        SESSIONS.pop(tok, None)
        return False
    return True


def tg_send(text):
    if not (TG_TOKEN and TG_CHAT):
        return
    try:
        body = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": text}).encode()
        urllib.request.urlopen(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            data=body, timeout=10,
        )
    except Exception as e:
        print("telegram error:", e, flush=True)


def page(name):
    with open("/index.html", encoding="utf-8") as f:
        html_doc = f.read()
    return html_doc.replace("{{TITLE}}", html.escape(name))


# ---------------- rate limit (lop bao ve phu, ngoai Cloudflare) ----------------
_rl_lock = threading.Lock()
_rl_hits = {}    # (ip, bucket) -> deque[timestamps]
_rl_block = {}   # (ip, bucket) -> until_ts

LOGIN_MAX, LOGIN_WIN, LOGIN_BLOCK = 10, 600, 600   # 10 lan / 10 phut -> block 10 phut
ALL_MAX, ALL_WIN, ALL_BLOCK = 120, 60, 120          # 120 request / phut -> block 2 phut


def is_ingress(handler):
    # HA ingress luon gui header nay; cong 8900 truc tiep thi khong
    return bool(handler.headers.get("X-Ingress-Path"))


def client_ip(handler):
    # sau Cloudflare:  CF-Connecting-IP là IP thật
    for h in ("CF-Connecting-IP", "X-Forwarded-For"):
        v = handler.headers.get(h, "")
        if v:
            return v.split(",")[0].strip()
    return handler.client_address[0]


def rl_check(ip, bucket, limit, window, block_s):
    now = time.time()
    key = (ip, bucket)
    with _rl_lock:
        until = _rl_block.get(key, 0)
        if until > now:
            return False, int(until - now)
        dq = _rl_hits.get(key)
        if dq is None:
            dq = collections.deque()
            _rl_hits[key] = dq
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(dq) >= limit:
            _rl_block[key] = now + block_s
            return False, block_s
        dq.append(now)
    return True, 0


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _sid(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return v
        return ""


    def _too_many(self, retry):
        self._send(429, "qua nhieu request, thu lai sau %s giay" % retry, "text/plain",
                   {"Retry-After": str(retry)})

    def do_GET(self):
        ip = client_ip(self)
        ok, retry = rl_check(ip, "all", ALL_MAX, ALL_WIN, ALL_BLOCK)
        if not ok:
            return self._too_many(retry)
        u = urllib.parse.urlparse(self.path)
        if u.path in ("/", "/index.html"):
            if is_ingress(self) or u.path == "/admin":
                if is_ingress(self):
                    return self._send(200, ADMIN_PAGE)   # sidebar HA = trang quan tri
            if session_ok(self._sid()):
                return self._send(200, MAC_PAGE)          # khach: trang doc MAC
            return self._send(200, LOGIN_PAGE)
        if u.path == "/admin":
            return self._send(403, "trang quan tri chi mo qua thanh ben HA (ingress)")
        if u.path == "/api/list":
            if not is_ingress(self):
                return self._send(403, "forbidden", "text/plain")
            q = (urllib.parse.parse_qs(u.query).get("q") or [""])[0].lower()
            rows = []
            try:
                with open(REC_FILE, encoding="utf-8") as f:
                    rows = [json.loads(l) for l in f if l.strip()]
            except FileNotFoundError:
                pass
            if q:
                rows = [r for r in rows if q in str(r.get("mac","")).lower() or q in str(r.get("label","")).lower()]
            rows = rows[::-1]
            return self._send(200, json.dumps(rows, ensure_ascii=False), "application/json; charset=utf-8")

        if u.path == "/api/csv":
            if not is_ingress(self):
                return self._send(403, "forbidden", "text/plain")
            rows = []
            try:
                with open(REC_FILE, encoding="utf-8") as f:
                    rows = [json.loads(l) for l in f if l.strip()]
            except FileNotFoundError:
                pass
            lines = ["mac,label,time"]
            for r in rows:
                lines.append('"%s","%s","%s"' % (
                    str(r.get("mac","")).replace('"','\\"'),
                    str(r.get("label","")).replace('"','\\"'),
                    str(r.get("time",""))))
            return self._send(200, "\n".join(lines) + "\n", "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="macs.csv"'})

        if u.path == "/export.csv":
            if not session_ok(self._sid()):
                return self._send(401, "unauthorized", "text/plain")
            rows = []
            try:
                with open(REC_FILE, encoding="utf-8") as f:
                    rows = [json.loads(l) for l in f if l.strip()]
            except FileNotFoundError:
                pass
            lines = ["mac,label,time"]
            for r in rows:
                lines.append('"%s","%s","%s"' % (
                    str(r.get("mac","")).replace('"','\"'),
                    str(r.get("label","")).replace('"','\"'),
                    str(r.get("time",""))))
            return self._send(200, "\n".join(lines) + "\n", "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="macs.csv"'})

        if u.path == "/list":
            if not session_ok(self._sid()):
                return self._send(401, "unauthorized", "text/plain")
            rows = []
            try:
                with open(REC_FILE, encoding="utf-8") as f:
                    rows = [json.loads(l) for l in f if l.strip()]
            except FileNotFoundError:
                pass
            rows = rows[-500:][::-1]
            trs = "".join(
                "<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
                    html.escape(str(r.get("mac",""))), html.escape(str(r.get("label",""))),
                    html.escape(str(r.get("time","")))) for r in rows)
            body = """<!doctype html><html lang="vi"><meta charset="utf-8"><title>MAC đã nhận</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;background:#111;color:#eee}
table{width:100%%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #333;text-align:left}
th{color:#93c5fd}code{color:#4ade80}
a.btn{display:inline-block;background:#2563eb;color:#fff;padding:8px 14px;border-radius:8px;text-decoration:none;margin-right:8px}
</style>
<h2>MAC khách đã gửi (%d)</h2>
<p><a class="btn" href="/">← Trang đọc MAC</a><a class="btn" href="/export.csv">⬇ Tải CSV</a></p>
<table><tr><th>MAC</th><th>Tên / đơn</th><th>Thời gian</th></tr>%s</table></html>""" % (len(rows), trs or '<tr><td colspan=3>(chưa có)</td></tr>')
            return self._send(200, body)
        if u.path == "/logout":
            SESSIONS.pop(self._sid(), None)
            return self._send(302, "", extra={"Location": "/", "Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0"})
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        ip = client_ip(self)
        ok, retry = rl_check(ip, "all", ALL_MAX, ALL_WIN, ALL_BLOCK)
        if not ok:
            return self._too_many(retry)
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")

        if u.path == "/login":
            ok, retry = rl_check(ip, "login", LOGIN_MAX, LOGIN_WIN, LOGIN_BLOCK)
            if not ok:
                return self._too_many(retry)
            q = urllib.parse.parse_qs(raw)
            user = (q.get("username") or [""])[0]
            pw = (q.get("password") or [""])[0]
            ok = hmac.compare_digest(user, USER) and bool(PASS) and hmac.compare_digest(pw, PASS)
            if not ok:
                return self._send(200, LOGIN_PAGE.replace("{{ERR}}", "Sai tên đăng nhập hoặc mật khẩu"))
            tok = new_session()
            return self._send(302, "", extra={
                "Location": "/",
                "Set-Cookie": f"{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Lax",
            })

        if not (session_ok(self._sid()) or is_ingress(self)):
            return self._send(401, "unauthorized", "text/plain")

        if u.path == "/submit":
            try:
                d = json.loads(raw)
            except Exception:
                return self._send(400, "bad json", "text/plain")
            mac = str(d.get("mac") or "").strip().upper()
            label = str(d.get("label") or "").strip()[:120]
            if not mac:
                return self._send(400, "missing mac", "text/plain")
            rec = {"mac": mac, "label": label, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "ua": self.headers.get("User-Agent", "")[:160]}
            with open(REC_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            tg_send(f"MAC khách: {mac}\nĐơn/tên: {label or '(trống)'}\n{rec['time']}")
            return self._send(200, json.dumps({"ok": True}), "application/json")

        if u.path == "/api/add":
            if not is_ingress(self):
                return self._send(403, "forbidden", "text/plain")
            try:
                d = json.loads(raw)
            except Exception:
                return self._send(400, "bad json", "text/plain")
            mac = str(d.get("mac") or "").strip().upper()
            label = str(d.get("label") or "").strip()[:120]
            if not mac:
                return self._send(400, "missing mac", "text/plain")
            rec = {"mac": mac, "label": label, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "ua": "admin"}
            with open(REC_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            return self._send(200, json.dumps({"ok": True}), "application/json")

        if u.path == "/api/del":
            if not is_ingress(self):
                return self._send(403, "forbidden", "text/plain")
            try:
                d = json.loads(raw)
            except Exception:
                return self._send(400, "bad json", "text/plain")
            mac = str(d.get("mac") or "").strip().upper()
            keep, removed = [], 0
            try:
                with open(REC_FILE, encoding="utf-8") as f:
                    for l in f:
                        if not l.strip():
                            continue
                        r = json.loads(l)
                        if str(r.get("mac","")).upper() == mac:
                            removed += 1
                        else:
                            keep.append(l)
            except FileNotFoundError:
                pass
            with open(REC_FILE, "w", encoding="utf-8") as f:
                f.writelines(keep)
            return self._send(200, json.dumps({"ok": True, "removed": removed}), "application/json")

        self._send(404, "not found", "text/plain")

    def log_message(self, *a):
        pass


ADMIN_PAGE = """<!doctype html><html lang="vi"><meta charset="utf-8">
<title>Quản trị MAC khách</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1000px;margin:20px auto;padding:0 16px;background:#111;color:#eee}
h2{margin:0 0 12px}
input,button{font-size:15px;padding:9px 12px;border-radius:8px;border:1px solid #444;background:#1b1b1b;color:#eee}
button{background:#2563eb;color:#fff;border:0;cursor:pointer}
button.ghost{background:#333}
table{width:100%;border-collapse:collapse;margin-top:14px}
th,td{padding:8px;border-bottom:1px solid #333;text-align:left}
th{color:#93c5fd}
code{color:#4ade80}
td button{padding:4px 10px;font-size:13px;background:#b91c1c}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.muted{color:#888;font-size:13px}
</style>
<h2>Quản trị MAC khách</h2>
<div class="bar" style="margin-bottom:10px">
  <input id="q" placeholder="Tìm theo MAC / tên / đơn" style="min-width:260px">
  <button onclick="load()">Tìm</button>
  <button class="ghost" onclick="q.value='';load()">Xoá lọc</button>
  <a href="/api/csv"><button class="ghost">⬇ Tải CSV</button></a>
  <span class="muted" id="n"></span>
</div>
<div class="bar" style="margin-bottom:6px">
  <input id="m" placeholder="MAC khách (AA:BB:CC:DD:EE:FF)">
  <input id="l" placeholder="Tên / mã đơn" style="min-width:220px">
  <button onclick="add()">Thêm</button>
</div>
<table><thead><tr><th>MAC</th><th>Tên / đơn</th><th>Thời gian</th><th></th></tr></thead>
<tbody id="tb"></tbody></table>
<script>
const $=id=>document.getElementById(id);
async function load(){
  const r=await fetch('api/list?q='+encodeURIComponent($('q').value));
  const d=await r.json();
  $('n').textContent=d.length+' bản ghi';
  $('tb').innerHTML=d.map(x=>`<tr><td><code>${x.mac}</code></td><td>${(x.label||'').replace(/</g,'&lt;')}</td><td>${x.time||''}</td>
    <td><button onclick="del('${x.mac}')">Xoá</button></td></tr>`).join('')||'<tr><td colspan="4">(chưa có)</td></tr>';
}
async function add(){
  const mac=$('m').value.trim(), label=$('l').value.trim();
  if(!mac){alert('Nhập MAC');return;}
  const r=await fetch('api/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac,label})});
  if(r.ok){$('m').value='';$('l').value='';load();}else alert('Lỗi '+r.status);
}
async function del(mac){
  if(!confirm('Xoá '+mac+' ?'))return;
  const r=await fetch('api/del',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac})});
  if(r.ok)load();else alert('Lỗi '+r.status);
}
$('q').addEventListener('keydown',e=>{if(e.key==='Enter')load();});
$('m').addEventListener('keydown',e=>{if(e.key==='Enter')add();});
load();
</script></html>"""


LOGIN_PAGE = """<!doctype html><html lang="vi"><meta charset="utf-8">
<title>Đăng nhập</title>
<style>
body{font-family:system-ui,sans-serif;max-width:380px;margin:80px auto;padding:0 16px;background:#111;color:#eee}
input{width:100%;padding:10px;margin:6px 0;border-radius:8px;border:1px solid #444;background:#1b1b1b;color:#eee;font-size:16px;box-sizing:border-box}
button{width:100%;margin-top:12px;background:#2563eb;color:#fff;border:0;padding:12px;border-radius:8px;font-size:16px;cursor:pointer}
.err{color:#f87171}
</style>
<h2>ESP MAC Reader</h2>
<p class="err">{{ERR}}</p>
<form method="post" action="login">
 <input name="username" placeholder="Tên đăng nhập" autocomplete="username">
 <input name="password" type="password" placeholder="Mật khẩu" autocomplete="current-password">
 <button>Đăng nhập</button>
</form></html>"""

MAC_PAGE = """<!doctype html><html lang="vi"><meta charset="utf-8">
<title>Đọc MAC ESP32</title>
<style>
body{font-family:system-ui,sans-serif;max-width:680px;margin:28px auto;padding:0 16px;background:#111;color:#eee}
button{background:#2563eb;color:#fff;border:0;padding:10px 16px;border-radius:8px;font-size:15px;cursor:pointer}
button:disabled{background:#444}
input{width:100%;padding:10px;margin:8px 0;border-radius:8px;border:1px solid #444;background:#1b1b1b;color:#eee;font-size:16px;box-sizing:border-box}
.mac{font-size:30px;font-weight:700;color:#4ade80;letter-spacing:1px;margin:14px 0}
pre{background:#000;padding:12px;border-radius:8px;overflow:auto;font-size:12px;max-height:260px}
a{color:#93c5fd}
</style>
<h2>Đọc MAC eFuse</h2>
<p>Cắm ESP32 vào USB <b>máy của bạn</b>, bấm Đọc MAC. Không ghi gì vào chip.<br>
Cần Chrome/Edge trên máy tính.</p>
<p><button id="read">Kết nối &amp; Đọc MAC</button> <a href="/list">Danh sách MAC</a> · <a href="/logout">Đăng xuất</a></p>
<div class="mac" id="mac">—</div>
<p><input id="label" placeholder="Tên khách / mã đơn hàng"></p>
<p><button id="send" disabled>Gửi MAC về cho nhà cung cấp</button> <span id="msg"></span></p>
<pre id="log"></pre>
<script type="module">
const $=id=>document.getElementById(id);
let ESPLoader, Transport;
try{
  const m = await import('https://unpkg.com/esptool-js@0.5.4/bundle.js');
  ESPLoader = m.ESPLoader; Transport = m.Transport;
}catch(e){ $('log').textContent='Không tải được esptool-js: '+e; }

async function readMac(){
  $('read').disabled=true; $('mac').textContent='...'; $('log').textContent='';
  try{
    const port = await navigator.serial.requestPort();
    const transport = new Transport(port, true);
    const loader = new ESPLoader({ transport, baudrate: 115200, terminal: {
      clean(){}, writeLine(t){ $('log').textContent += t+"\n"; }, write(t){ $('log').textContent += t; } } });
    await loader.main();
    const mac = (await loader.readMac(0)).toUpperCase();
    $('mac').textContent = mac;
    $('send').disabled = false;
    $('log').textContent += "\nMAC = "+mac+"\n";
  }catch(e){
    $('mac').textContent='LỖI';
    $('log').textContent += "\n"+e;
  }
  $('read').disabled=false;
}
$('read').onclick = readMac;
$('send').onclick = async ()=>{
  $('send').disabled=true; $('msg').textContent='';
  try{
    const r = await fetch('submit',{method:'POST',headers:{'Content-Type':'application/json'},
      body: JSON.stringify({mac:$('mac').textContent, label:$('label').value})});
    $('msg').textContent = r.ok ? '✅ Đã gửi' : '❌ Lỗi '+r.status;
  }catch(e){ $('msg').textContent='❌ '+e; }
  $('send').disabled=false;
};
</script></html>"""


if __name__ == "__main__":
    print(f"listening on 0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
