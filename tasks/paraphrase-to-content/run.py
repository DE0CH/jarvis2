# Paraphrases TASK_PARAMS.text with the DE0CH/paraphrase Space (hf-spaces/paraphrase/) through its
# Gradio HTTP API, encrypts the result with AES_KEY (aesfile.py) and saves it in the content store (content.py:
# through the machine's local API). Env: AES_KEY (the key store picked in the task), HUGGING_FACE_TOKEN (default
# store). No human step.
# A PAUSED Space is restarted; a cold start (DIPPER is 11B) takes minutes, so the wait is up to 20 min.
import json, os, sys, time
import requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from upload import aes_key, upload_encrypted

SPACE, HOST = "DE0CH/paraphrase", "https://de0ch-paraphrase.hf.space"
p = json.loads(os.environ["TASK_PARAMS"])
key = aes_key(p["keystore"])  # before the slow Space call, so a missing key fails at once
text, name = p["text"].strip(), p["filename"].strip()
if not text:
    sys.exit("the text is empty")
hf = {"Authorization": f"Bearer {os.environ['HUGGING_FACE_TOKEN']}"}


def stage():
    r = requests.get(f"https://huggingface.co/api/spaces/{SPACE}/runtime", headers=hf, timeout=30)
    r.raise_for_status()
    return r.json().get("stage")


t0 = time.time()
s = stage()
if s == "PAUSED":
    print("the Space is paused, restarting it")
    requests.post(f"https://huggingface.co/api/spaces/{SPACE}/restart", headers=hf, timeout=30).raise_for_status()
while (s := stage()) != "RUNNING":
    if s in ("BUILD_ERROR", "RUNTIME_ERROR", "CONFIG_ERROR", "NO_APP_FILE"):
        sys.exit(f"the Space is in {s}")
    if time.time() - t0 > 1200:
        sys.exit(f"the Space did not start in 20 min (stage {s})")
    if s == "SLEEPING":  # a request wakes a sleeping Space
        requests.get(HOST, headers=hf, timeout=30)
    print(f"waiting for the Space ({s})")
    time.sleep(15)
print(f"Space running after {time.time() - t0:.0f} s")

data = [text, p["model"], p["lexical"], p["structure"], p["semantic"]]
r = requests.post(f"{HOST}/gradio_api/call/paraphrase", json={"data": data}, headers=hf, timeout=60)
r.raise_for_status()
eid = r.json()["event_id"]
out, event = None, None
with requests.get(f"{HOST}/gradio_api/call/paraphrase/{eid}", headers=hf, stream=True, timeout=(30, 900)) as sse:
    sse.raise_for_status()
    for line in sse.iter_lines(decode_unicode=True):
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:") and event in ("complete", "error"):
            payload = line[5:].strip()
            if event == "error":
                sys.exit(f"the Space failed: {payload}")
            out = json.loads(payload)[0]
            break
if not out:
    sys.exit("the Space returned no output")
print(f"paraphrased {len(text)} → {len(out)} chars in {time.time() - t0:.0f} s")

upload_encrypted(p["store"], name, out, key)
