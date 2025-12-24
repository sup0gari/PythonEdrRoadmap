import os
import time
import hashlib

TARGET_FILE = "test.txt"

def calc_hash(filepath):
    with open(filepath, "rb") as f:
        content = f.read()
        return hashlib.sha256(content).hexdigest()

last_mtime = os.path.getmtime(TARGET_FILE)
last_hash = calc_hash(TARGET_FILE)
print(f"[*] Monitoring started for {TARGET_FILE}")

while True:
    time.sleep(1)
    current_mtime = os.path.getmtime(TARGET_FILE)
    current_hash = calc_hash(TARGET_FILE)
    if current_mtime != last_mtime:
        if current_hash != last_hash:
            print(f"[!!] CRITICAL: File content modified!")
            print(f"    New Hash: {current_hash}")
            last_hash = current_hash
        last_mtime = current_mtime