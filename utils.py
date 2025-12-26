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

    all_events = []
    for _ in range(5):
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events: break
        all_events.extend(events)

    delete_handle_ids =  {event.StringInserts[5] for event in all_events if event.EventID == 4660}

    for event in all_events:
        if event.EventID != 4663: continue
        inserts = event.StringInserts
        if "python.exe" in inserts[11].lower(): continue
        
        is_target = os.path.basename(file).lower() in inserts[6].lower()
        is_deleted_now = inserts[7] in delete_handle_ids
        delete_access = (inserts[9] == "0x10000")

        if action == "DELETE":
            if is_deleted_now or (is_target and delete_access):
                return normalize_format(inserts)
        elif action == "WRITE":
            if is_target and not delete_access:
                return normalize_format(inserts)
    return None