"""DM Deyao through the lobster bot (the index belongs to no session, so it uses the DM, like Jarvis's
own pings). LOBSTER_TOKEN comes from the env-default Secret; without it the notice is only logged."""
import json, os, urllib.request

DM_CHANNEL = os.environ.get("LOBSTER_DM_CHANNEL", "1531422588247474266")


def dm(text):
    print(f"[notify] {text}", flush=True)
    tok = os.environ.get("LOBSTER_TOKEN")
    if not tok:
        return
    req = urllib.request.Request(f"https://discord.com/api/v10/channels/{DM_CHANNEL}/messages", method="POST",
                                 data=json.dumps({"content": text[:1990]}).encode(),
                                 headers={"Authorization": "Bot " + tok, "Content-Type": "application/json",
                                          "User-Agent": "DiscordBot (https://github.com/DE0CH, 1) icloud-index"})
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except Exception as e:
        print(f"[notify] discord failed: {e}", flush=True)
