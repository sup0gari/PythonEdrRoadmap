import os
import time
import json
from utils import calc_hash, get_mtime, get_event_log, normalize_format

with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

TARGET_FILES = config["target_files"]
RETRY_COUNT = config["log_retry_count"]
RETRY_DELAY = config["log_retry_delay"] 

file_status = {}
for f in TARGET_FILES:
    exists = os.path.exists(f)
    file_status[f] = {
        "exists": exists,
        "mtime": os.path.getmtime(f) if exists else None,
        "hash": calc_hash(f) if exists else None
    }

try:
    print(f"[*] Monitoring started for : {', '.join(TARGET_FILES)}")
    print("[*] Press Ctrl+C to stop.")
    while True:
        time.sleep(1)
        for f in TARGET_FILES:
            exists_now = os.path.exists(f)
            prev_status = file_status[f]
            target_abs_path = os.path.abspath(f)

            # 削除チェック
            if not exists_now and prev_status["exists"]:
                print(f"\n[!] ALERT: {f} has been DELETED.")
                file_status[f]["exists"] = False
                file_status[f]["hash"] = None
                file_status[f]["mtime"] = None

                proc_info = None
                try:
                    for attempt in range(RETRY_COUNT):
                        print(f"    [*] Checking Logs for Deletion... (Attempt {attempt + 1})")
                        proc_info = get_event_log(target_abs_path, action="DELETE")
                        if proc_info: break
                        time.sleep(RETRY_DELAY)
                except Exception as e:
                    print(f"    [!] Error during deletion log search: {e}")
                
                if proc_info:
                    print(f"    Evidence(DELETION) Found!")
                    print(f"    Process: {proc_info['process']} (PID: {proc_info['pid']})")
                    print(f"    User: {proc_info['user']}")
                else:
                    print("    [?] Deletion evidence not found in Security Log.")
                
                continue
            # 再作成チェック
            if exists_now and not prev_status["exists"]:
                print(f"\n[*] INFO: {f} has been RECREATED.")
                proc_info = get_event_log(target_abs_path, action="WRITE")
                if proc_info:
                    print(f"    Info Found!")
                    print(f"    Process: {proc_info['process']} (PID: {proc_info['pid']})")
                    print(f"    User   : {proc_info['user']}")
                    print(f"    File   : {proc_info['file']}")
                    file_status[f]["exists"] = True
                    file_status[f]["hash"] = calc_hash(f)
                    file_status[f]["mtime"] = get_mtime(f)
                continue
                
            # 編集チェック
            if exists_now:
                current_mtime = get_mtime(f)
                if current_mtime != prev_status["mtime"]:
                    current_hash = calc_hash(f)
                    if current_hash != prev_status["hash"]:
                        print(f"\n[!!] CRITICAL: {f} content modified!")
                        
                        proc_info = None
                        target_abs_path = os.path.abspath(f)
                        for attempt in range(RETRY_COUNT):
                            print(f"    [*] Checking Logs... (Attempt {attempt + 1})")
                            proc_info = get_event_log(target_abs_path)
                            if proc_info: break
                            time.sleep(RETRY_DELAY)

                        if proc_info:
                            print(f"    Process: {proc_info['process']} (PID: {proc_info['pid']})")
                            print(f"    User: {proc_info['user']}")
                            print(f"    File: {proc_info['file']}")
                        else:
                            print("    [?] Evidence not found.")
                        print(f"    New Hash: {current_hash}")

                        file_status[f]["hash"] = current_hash
                    file_status[f]["mtime"] = current_mtime
except KeyboardInterrupt:
    print("\n[!] Monitoring stopped by user.")