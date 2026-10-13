# Encrypts TASK_PARAMS.text with AES_KEY from the picked key store (aesfile.py) and saves it in the content store
# (content.py: through the machine's local API). Env: AES_KEY (the key store picked in the task). No human step.
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from upload import aes_key, upload_encrypted

p = json.loads(os.environ["TASK_PARAMS"])
key = aes_key(p["keystore"])
if not p["text"].strip():
    sys.exit("the text is empty")
upload_encrypted(p["store"], p["filename"].strip(), p["text"], key)
