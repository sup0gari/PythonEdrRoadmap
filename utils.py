import os
import hashlib
import win32evtlog

def get_mtime(file):
    if os.path.exists(file):
        return os.path.getmtime(file)
    return None  

def calc_hash(file):
    sha256hash = hashlib.sha256()
    try:
        with open(file, "rb") as f:
            for byte in iter(lambda: f.read(4096), b""):
                sha256hash.update(byte)
        return sha256hash.hexdigest()
    except:
        return None

def normalize_format(data, source="WINDOWS"):
    try:
        pid = int(data[10], 16)
    except:
        pid = data[10]
    return {
        "process": data[11],
        "user": data[1],
        "pid": pid,
        "file": data[6],
        "source": source
    }

def get_event_log(file, action="WRITE"):
    server = 'localhost'
    log_type = 'Security'
    handle = win32evtlog.OpenEventLog(server, log_type)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    # events = win32evtlog.ReadEventLog(handle, flags, 0)
    all_events = []
    for _ in range(5):
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