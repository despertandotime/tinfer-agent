import os, subprocess, sqlite3, time
from db import init_findings_hash_table, is_duplicate, register_finding

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
DB_PATH = os.path.expanduser("~/tinfer.db")
API = f"https://api.telegram.org/bot{TOKEN}"

import urllib.request, json

def send(text):
    data = urllib.parse.urlencode({"chat_id": CHAT_ID, "text": text}).encode()
    urllib.request.urlopen(f"{API}/sendMessage", data=data)

def get_updates(offset=None):
    url = f"{API}/getUpdates"
    if offset:
        url += f"?offset={offset}"
    with urllib.request.urlopen(url) as r:
        return json.load(r)

def run_scan(target):
    send(f"🚀 Agente despachado\nTarget: {target}\nModo: scan")
    subfinder = subprocess.run(
        [os.path.expanduser("~/go/bin/subfinder"), "-d", target, "-silent"],
        capture_output=True, text=True
    )
    subs = subfinder.stdout.strip().splitlines()
    if not subs:
        subs = [target]
    httpx_input = "\n".join(subs)
    httpx = subprocess.run(
        [os.path.expanduser("~/go/bin/httpx"), "-silent"],
        input=httpx_input, capture_output=True, text=True
    )
    live = httpx.stdout.strip().splitlines()
    if not live:
        send(f"⚠️ Sin hosts vivos para {target}")
        return
    nuclei_input = "\n".join(live)
    nuclei = subprocess.run(
        [os.path.expanduser("~/go/bin/nuclei"), "-silent", "-jsonl"],
        input=nuclei_input, capture_output=True, text=True
    )
    conn = sqlite3.connect(DB_PATH)
    init_findings_hash_table(conn)
    new_count = 0
    for line in nuclei.stdout.strip().splitlines():
        try:
            f = json.loads(line)
        except:
            continue
        vuln_type = f.get("template-id", "unknown")
        endpoint = f.get("matched-at", target)
        if is_duplicate(conn, target, vuln_type, endpoint):
            continue
        register_finding(conn, target, vuln_type, endpoint, target)
        new_count += 1
        send(f"🔥 Nuevo hallazgo\nTarget: {target}\nTipo: {vuln_type}\nEndpoint: {endpoint}")
    if new_count == 0:
        send(f"✅ Scan completo: {target}\nSin hallazgos nuevos")

def cmd_findings(target):
    conn = sqlite3.connect(DB_PATH)
    init_findings_hash_table(conn)
    rows = conn.execute(
        "SELECT vuln_type, endpoint, reported_at FROM findings_hash WHERE target=?", (target,)
    ).fetchall()
    if not rows:
        send(f"❌ Target {target} no encontrado.")
        return
    msg = f"📋 Findings para {target}:\n"
    for r in rows:
        msg += f"- {r[0]} @ {r[1]} ({r[2]})\n"
    send(msg)

def cmd_status():
    conn = sqlite3.connect(DB_PATH)
    init_findings_hash_table(conn)
    count = conn.execute("SELECT COUNT(DISTINCT target) FROM findings_hash").fetchone()[0]
    if count == 0:
        send("📖 No hay targets registrados.")
    else:
        send(f"🟢 MATRIX online\nTargets con hallazgos: {count}")

def main():
    send("TINFER online")
    offset = None
    while True:
        updates = get_updates(offset)
        for u in updates.get("result", []):
            offset = u["update_id"] + 1
            msg = u.get("message", {})
            text = msg.get("text", "")
            if text.startswith("/scan "):
                target = text.split(" ", 1)[1].strip()
                run_scan(target)
            elif text.startswith("/findings "):
                target = text.split(" ", 1)[1].strip()
                cmd_findings(target)
            elif text == "/status":
                cmd_status()
            elif text == "/start":
                send("TINFER online")
        time.sleep(3)

if __name__ == "__main__":
    main()
