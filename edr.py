import os
import time
import hashlib
import psutil
import win32evtlog

TARGET_FILE = "test.txt"

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
def get_modifying_process(file):
    target_abs_path = os.path.abspath(file)
    # カーネルに実行中のプロセス情報をリクエスト
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            # ファイルを開いているプロセスリストを検索
            for f in proc.open_files():
                if f.path == target_abs_path:
                    return proc.info
        except(psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return None

def get_event_log(file):
    server = 'localhost'
    log_type = 'Security'
    handle = win32evtlog.OpenEventLog(server, log_type)

    # Windowsイベントログを最新から読み取る
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(handle, flags, 0)

    for event in events:
        # イベントID 4663（ファイル操作）で対象ファイルかどうか
        if event.EventID == 4663 and file in str(event.StringInserts):
            return {
                "process_name": event.StringInserts[6], # 実行ファイル名
                "user": event.StringInserts[1], # 実行ユーザー名
                "pid": event.StringInserts[7], # PID
            }
    return None

last_mtime = get_mtime(TARGET_FILE)
last_hash = calc_hash(TARGET_FILE)
print(f"[*] Monitoring started for {TARGET_FILE}")

while True:
    time.sleep(1)
    current_mtime = get_mtime(TARGET_FILE)
    current_hash = calc_hash(TARGET_FILE)
    if current_mtime != last_mtime:
        if current_hash != last_hash:
            print(f"[!!] CRITICAL: File content modified!")
            proc_info = get_modifying_process(TARGET_FILE) # psutilのリアルタイムスキャン
            
            # psutil失敗用
            if not proc_info:
                print("    [*] Real-time scan failed. Cheking Windows Event Logs...")
                proc_info = get_event_log(TARGET_FILE)
            
            if proc_info:
                process_name = proc_info.get('name') or proc_info.get('process_name')
                pid = proc_info.get('pid') or proc_info.get('pid')
                user = proc_info.get('username') or proc_info.get('user')

                print(f"    Process: {process_name} (PID: {pid})")
                print(f"    User: {user}")
            else:
                print("    [?] Evidence not found in Event Logs yet. (Wait for OS to write log)")
            print(f"    New Hash: {current_hash}")
            
            last_hash = current_hash
        last_mtime = current_mtime