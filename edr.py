import os
import time
import hashlib
import psutil
import win32evtlog
import json

with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

TARGET_FILES = config["target_files"]
RETRY_COUNT = config["log_retry_count"]
RETRY_DELAY = config["log_retry_delay"]

# ファイルのハッシュ値取得
def calc_hash(filepath):
    with open(filepath, "rb") as f:
        content = f.read()
        return hashlib.sha256(content).hexdigest()

# ファイル編集時間取得
def get_mtime(filepath):
    if os.path.exists(filepath):
        return os.path.getmtime(filepath)
    return None

# ファイル編集プロセス取得
# def get_modifying_process(file):
#     target_abs_path = os.path.abspath(file)
#     # カーネルに実行中のプロセス情報をリクエスト
#     for proc in psutil.process_iter(['pid', 'name', 'username']):
#         try:
#             # ファイルを開いているプロセスリストを検索
#             for f in proc.open_files():
#                 if f.path == target_abs_path:
#                     return proc.info
#         except(psutil.AccessDenied, psutil.NoSuchProcess):
#             continue
#     return None

# WindowsEventLogの検索
def get_event_log(file):
    server = 'localhost'
    log_type = 'Security'
    handle = win32evtlog.OpenEventLog(server, log_type)

    # Windowsイベントログを最新から読み取る
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(handle, flags, 0)

    for event in events:
        # イベントID 4663（ファイル操作）で対象ファイルかどうか
        # print(f"    DEBUG LOG: ID:{event.EventID} | Proc:{event.StringInserts[11]} | File:{event.StringInserts[6]}")
        if event.EventID == 4663:
            inserts = event.StringInserts
            event_str = str(event.StringInserts)

            # Pythonによるハッシュ読み込みを除外
            if "python.exe" in inserts[11]:
                continue
            if os.path.basename(file).lower() in event_str.lower():
                try:
                    pid_decimal = int(inserts[10], 16)
                except:
                    pid_decimal = int(inserts[10])
                return {
                    "process_name": inserts[11],
                    "user": inserts[1],
                    "pid": pid_decimal,
                    "modified_file": inserts[6],
                }
    return None

file_status = {}
for f in TARGET_FILES:
    file_status[f] = {
        "mtime": get_mtime(f),
        "hash": calc_hash(f)
    }

try:
    print(f"[*] Monitoring started for : {', '.join(TARGET_FILES)}")
    print("[*] Press Ctrl+C to stop.")
    while True:
        time.sleep(1)
        for f in TARGET_FILES:
            if not os.path.exists(f):
                print(f"[!] File not found: {f}")
                continue
            current_mtime = get_mtime(f)
            current_hash = calc_hash(f)
        
            if current_mtime != file_status[f]["mtime"]:
                if current_hash != file_status[f]["hash"]:
                    print(f"[!!] CRITICAL: {f} content modified!")
                    proc_info = None
                    target_abs_path = os.path.abspath(f)
                    
                    for attempt in range(RETRY_COUNT):
                        print(f"    [*] Checking Windows Event Logs... (Attempt {attempt + 1})")
                        proc_info = get_event_log(target_abs_path)
                        if proc_info:
                            break
                        time.sleep(RETRY_DELAY)
                    if proc_info:
                        process_name = proc_info.get('process_name')
                        pid = proc_info.get('pid')
                        user = proc_info.get('user')
                        modifed_file = proc_info.get('modified_file')

                        print(f"    Process: {process_name} (PID: {pid})")
                        print(f"    User: {user}")
                        print(f"    Modifed File: {modifed_file}")
                    else:
                        print("    [?] Evidence not found. (The log might be delayed or not configured)")
                    print(f"    New Hash: {current_hash}")
                
                file_status[f]["hash"] = current_hash
            file_status[f]["mtime"] = current_mtime
except KeyboardInterrupt:
    print("\n[!] Monitoring stopped by user.")