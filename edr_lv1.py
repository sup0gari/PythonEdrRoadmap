import os
import time

TARGET_FILE = "test_lv1.txt" # 監視対象

last_atime = os.path.getatime(TARGET_FILE)
print(f"[*] Monitoring started for {TARGET_FILE}")

while True:
    time.sleep(1)
    current_atime = os.path.getatime(TARGET_FILE)
    if current_atime != last_atime:
        print(f"[!] ALERT: Access detected on {TARGET_FILE}")
        last_atime = current_atime