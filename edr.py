import os
import time
import hashlib
import psutil

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

last_mtime = get_mtime(TARGET_FILE)
last_hash = calc_hash(TARGET_FILE)
print(f"[*] Monitoring started for {TARGET_FILE}")

while True:
    time.sleep(1)
    current_mtime = get_mtime(TARGET_FILE)
    current_hash = calc_hash(TARGET_FILE)
    if current_mtime != last_mtime:
        if current_hash != last_hash:
            proc_info = get_modifying_process(TARGET_FILE)
            print(f"[!!] CRITICAL: File content modified!")
            if proc_info:
                print(f"    Process: {proc_info['name']} (PID: {proc_info['pid']})")
                print(f"    User: {proc_info['username']}")
            else:
                print("    Process: Could not be identified (Closed too fast)")
            print(f"    New Hash: {current_hash}")
            
            last_hash = current_hash
        last_mtime = current_mtime