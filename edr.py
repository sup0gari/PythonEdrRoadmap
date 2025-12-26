import os
import time
import hashlib
import win32evtlog
import json

with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

TARGET_FILES = config["target_files"]
RETRY_COUNT = config["log_retry_count"]
RETRY_DELAY = config["log_retry_delay"]

# ファイルのハッシュ値取得
def calc_hash(filepath):
    sha256hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # 4096バイトずつ読み込み、メモリクラッシュを防ぐ
        for byte in iter(lambda: f.read(4096), b""):
            sha256hash.update(byte)
    return sha256hash.hexdigest()

# ファイル編集時間取得
def get_mtime(filepath):
    if os.path.exists(filepath):
        return os.path.getmtime(filepath)
    return None

def normalize_format(inserts, source="WINDOWS"):
    try:
        pid = int(inserts[10], 16)
    except:
        pid = inserts[10]
    return {
        "process_name": inserts[11],
        "user": inserts[1],
        "pid": pid,
        "file": inserts[6],
        "source": source
    }

# WindowsEventLogの検索
def get_event_log(file, action="WRITE"):
    server = 'localhost'
    log_type = 'Security'
    handle = win32evtlog.OpenEventLog(server, log_type)

    # Windowsイベントログを最新から読み取る
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    # events = win32evtlog.ReadEventLog(handle, flags, 0)

    all_events = []
    for _ in range(5): # 5回分（数百件〜千件程度）読み込む
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events: break
        all_events.extend(events)

    if action == "DELETE":
        delete_handle_ids = set()
        for event in all_events:
            if event.EventID == 4660:
                delete_handle_ids.add(event.StringInserts[5])
        
        for event in all_events:
            if event.EventID == 4663:
                inserts = event.StringInserts
                if inserts[7] in delete_handle_ids:
                    if "python.exe" in inserts[11]: continue
                    return normalize_format(inserts)

    for event in all_events:
        # イベントID 4663（ファイル操作）で対象ファイルかどうか
        if event.EventID == 4663:
            inserts = event.StringInserts
            event_str = str(event.StringInserts)

            # Pythonによるハッシュ読み込みを除外
            if "python.exe" in inserts[11]:
                continue
            if os.path.basename(file).lower() in str(inserts).lower():
                access_mask = inserts[9]
                is_delete = access_mask == "0x10000"
                if action == "DELETE" and is_delete:
                    return normalize_format(inserts)
                elif action == "WRITE" and not is_delete:
                    return normalize_format(inserts)
                
    return None

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
                    print(f"    Process: {proc_info['process_name']} (PID: {proc_info['pid']})")
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
                    print(f"    Process: {proc_info['process_name']} (PID: {proc_info['pid']})")
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
                            print(f"    Process: {proc_info['process_name']} (PID: {proc_info['pid']})")
                            print(f"    User: {proc_info['user']}")
                            print(f"    File: {proc_info['file']}")
                        else:
                            print("    [?] Evidence not found.")
                        print(f"    New Hash: {current_hash}")

                        file_status[f]["hash"] = current_hash
                    file_status[f]["mtime"] = current_mtime
except KeyboardInterrupt:
    print("\n[!] Monitoring stopped by user.")