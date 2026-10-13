# Send one Proton email with NO AI in the loop. Env: TASK_PARAMS (account / inputs content stores, key store),
# AES_KEY (the key store picked in the task), IPROYAL_API (default store).
# 1. account.json (username, password) from the account store; address.txt / subject.txt / content.txt from the
#    inputs store (content.py: through the machine's local API), decrypted in memory (aesfile: AES-256-GCM,
#    nonce||ct||tag). Nothing is written to disk and every line of output passes a redactor that blanks all of those
#    values.
# 2. A fresh IPRoyal residential sub-user (Proton blocks datacenter IPs), a local pproxy forwarder (Chromium can't take
#    proxy creds), headless Chromium (the session image's Playwright): password login (no CAPTCHA seen on a
#    residential IP), mail.proton.me, compose, the body pasted as HTML text (<p>/<br>), Send, and wait for "Message
#    sent." The sub-user is deleted at the end.
import html, json, os, re, secrets, socket, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import requests
import aesfile, content

IPR = "https://resi-api.iproyal.com/v1/residential-subusers"


class Redactor:
    def __init__(self, stream): self.stream, self.words = stream, []
    def write(self, s):
        for w in self.words: s = re.sub(re.escape(w), "[redacted]", s, flags=re.I)
        return self.stream.write(s)
    def __getattr__(self, n): return getattr(self.stream, n)
sys.stdout, sys.stderr = Redactor(sys.stdout), Redactor(sys.stderr)
def hide(*vals):
    for v in vals:
        for part in [v] + v.split("\n"):
            if part.strip() and len(part.strip()) >= 4: sys.stdout.words.append(part.strip()); sys.stderr.words.append(part.strip())


def fetch(store, path):
    return content.get(store, path)


def proxy_ready(port, seconds=60):
    """The forwarder is up AND the residential exit completes a real HTTPS request (not just a fixed sleep)."""
    prox = {"https": f"http://127.0.0.1:{port}", "http": f"http://127.0.0.1:{port}"}
    end = time.time() + seconds
    while time.time() < end:
        try:
            if requests.get("https://account.proton.me/", proxies=prox, timeout=20).status_code < 500: return True
        except Exception: pass
        time.sleep(3)
    return False


def goto(pg, url):
    """A residential exit can drop a connection now and then: retry the navigation."""
    for attempt in range(4):
        try: return pg.goto(url, wait_until="domcontentloaded", timeout=120000)
        except Exception as e:
            if attempt == 3: raise
            print(f"page load failed ({str(e).splitlines()[0][:80]}), retrying"); time.sleep(5)


def to_html(text):
    paras = [p.strip() for p in text.strip().split("\n\n") if p.strip()]
    return "".join(f"<p>{html.escape(p).replace(chr(10), '<br>')}</p>" for p in paras)


def main():
    p = json.loads(os.environ["TASK_PARAMS"])
    key = aesfile.key_from(os.environ.get("AES_KEY"))
    acct = json.loads(fetch(p["account"], "account.json"))
    hide(acct["username"], acct["username"] + "@proton.me", acct["password"], acct.get("display_name", "") or "____")
    vals = {n: aesfile.decrypt(fetch(p["inputs"], f"{n}.txt"), key).decode("utf-8").strip() for n in ("address", "subject", "content")}
    hide(*vals.values())
    print(f"inputs decrypted in memory (recipient, subject, body of {len(vals['content'])} chars)")

    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    u, pw = "pm" + secrets.token_hex(4), "Pw" + secrets.token_hex(6)
    H = {"Authorization": f"Bearer {os.environ['IPROYAL_API']}", "Content-Type": "application/json"}
    sub = requests.post(IPR, headers=H, json={"username": u, "password": pw, "traffic": 0.3}, timeout=30).json()["hash"]
    px = None
    try:
        for attempt in range(4):                              # a fresh exit IP per attempt
            if px: px.terminate()
            px = subprocess.Popen([sys.executable, "-m", "pproxy", "-l", f"http://127.0.0.1:{port}", "-r",
                                   f"http://geo.iproyal.com:12321#{u}:{pw}_country-gb_session-{secrets.token_hex(4)}_lifetime-30m"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if proxy_ready(port): break
            print(f"residential exit not answering (attempt {attempt + 1}), trying another")
        else: sys.exit("no working residential exit")
        send(port, acct, vals)
    finally:
        if px: px.terminate()
        requests.delete(f"{IPR}/{sub}", headers=H, timeout=30)
        print("residential sub-user deleted")


def send(port, acct, vals):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch(headless=True, proxy={"server": f"http://127.0.0.1:{port}"}, args=["--disable-quic"])
        pg = b.new_page(viewport={"width": 1280, "height": 900})
        goto(pg, "https://account.proton.me/login")
        pg.wait_for_selector("#username", timeout=120000); time.sleep(3)
        pg.click("#username"); pg.keyboard.type(acct["username"], delay=50)
        pg.click("#password"); pg.keyboard.type(acct["password"], delay=40); pg.keyboard.press("Enter")
        for _ in range(40):
            time.sleep(3)
            t = pg.evaluate("document.body.innerText")
            if "Human Verification" in t: sys.exit("login asked for human verification")
            if "proton.me/apps" in pg.url or "mail.proton.me" in pg.url: break
        else: sys.exit("login did not complete")
        print("logged in")
        goto(pg, "https://mail.proton.me/u/0/inbox")
        for _ in range(40):
            time.sleep(3)
            try:
                if pg.get_by_role("button", name="New message").count(): break
            except Exception: pass
        else: sys.exit("mailbox did not load")
        time.sleep(4)
        for _ in range(6):                                   # welcome / upsell dialogs
            if not pg.locator(".modal-two").count(): break
            pg.keyboard.press("Escape"); time.sleep(2)
        pg.get_by_role("button", name="New message").first.click(); time.sleep(5)
        pg.get_by_test_id("composer:to").click(); pg.keyboard.type(vals["address"], delay=30); pg.keyboard.press("Enter")
        pg.get_by_test_id("composer:subject").click(); pg.keyboard.type(vals["subject"], delay=20)
        ed = pg.frame_locator("iframe[data-testid='rooster-iframe']").locator("[contenteditable=true]").first
        ed.click(); pg.keyboard.press("Control+Home")
        ed.evaluate("""(el, [h, t]) => { el.focus(); const dt = new DataTransfer();
            dt.setData('text/html', h); dt.setData('text/plain', t);
            el.dispatchEvent(new ClipboardEvent('paste', {clipboardData: dt, bubbles: true, cancelable: true})); }""",
                    [to_html(vals["content"]), vals["content"]])
        time.sleep(2)
        first = vals["content"].strip().split("\n")[0][:20]
        if first not in ed.inner_text(): sys.exit("the body did not land in the composer")
        pg.get_by_test_id("composer:send-button").click()
        for _ in range(40):
            time.sleep(2)
            if any("Message sent" in n for n in pg.locator(".notification").all_inner_texts()):
                print("SENT"); break
        else: sys.exit("no 'Message sent' confirmation")
        b.close()


if __name__ == "__main__":
    main()
