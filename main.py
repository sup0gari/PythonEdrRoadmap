#!/usr/bin/env python3
import os
import time
import json
from utils import calc_hash, get_mtime, get_event_log, normalize_format
from collections import deque

with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

RETRY_COUNT = config["log_retry_count"]
RETRY_DELAY = config["log_retry_delay"] 

def main():
    TARGET_FILES = config["target_files"]

    file_status = {}
    for f in TARGET_FILES:
        exists = os.path.exists(f)
        file_status[f] = {
            "exists": exists,
            "mtime": os.path.getmtime(f) if exists else None,
            "hash": calc_hash(f) if exists else None
        }

        seen_handles = deque(maxlen=100)
        try:
            print(f"[*] Monitoring started for : {', '.join(TARGET_FILES)}")
            print("[*] Press Ctrl+C to stop.")

            while True:
                time.sleep(1)
                for f in TARGET_FILES:
                    exists_now = os.path.exists(f)
                    prev_status = file_status[f]

                    # 削除チェック
                    if not exists_now and prev_status["exists"]:
                        check_info(f, "DELETE", f"[!] ALERT: {f} has been DELETED!", seen_handles)
                        file_status[f].update({"exists": False, "hash": None, "mtime": None})
                    
                    # 再作成チェック
                    if exists_now and not prev_status["exists"]:
                        check_info(f, "WRITE", f"\n[*] INFO: {f} has been RECREATED.", seen_handles)
                        file_status[f].update({"exists": True, "hash": calc_hash(f), "mtime": get_mtime(f)})
                        
                    # 編集チェック
                    if exists_now:
                        current_mtime = get_mtime(f)
                        if current_mtime != prev_status["mtime"]:
                            current_hash = calc_hash(f)
                            if current_hash != prev_status["hash"]:
                                check_info(f, "WRITE", f"\n[!!] CRITICAL: {f} content modified!", seen_handles)
                                print(f"    New Hash: {current_hash}")
                                file_status[f].update({"hash": current_hash, "mtime": current_mtime})
                            else:
                                file_status[f]["mtime"] = current_mtime

        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped by user.")

def check_info(file, action, msg, seen_handles):
    print(msg)
    abs_path = os.path.abspath(file)
    proc_info = None

    for attempt in range(RETRY_COUNT):
        print(f"    [*] Checking Logs...(Attempt {attempt + 1})")
        proc_info = get_event_log(abs_path, action, seen_handles)
        if proc_info: break
        time.sleep(RETRY_DELAY)
    
    if proc_info:
        print(f"    Log Found!")
        print(f"    Handle : {proc_info['handle']}")
        print(f"    Process: {proc_info['process']} (PID: {proc_info['pid']})")
        print(f"    User   : {proc_info['user']}")
        print(f"    File   : {proc_info['file']}")
    else:
        print(f"    [?] Log not found in Security Log.")
    return proc_info

if __name__ == "__main__":
    main()