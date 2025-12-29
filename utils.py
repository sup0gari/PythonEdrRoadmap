import os
import hashlib
import win32evtlog
import pywintypes

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
        "handle": data[7],
        "process": data[11],
        "user": data[1],
        "pid": pid,
        "file": data[6],
        "source": source
    }

def get_event_log(file, action="WRITE", seen_handles = None):
    server = 'localhost'
    log_type = 'Security'

    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        all_events = []
        
        try:
            for _ in range(5):
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events: break
                all_events.extend(events)
        except pywintypes.error as e:
            if e.winerror == 1503:
                return {
                    "handle": "N/A",
                    "process": "[!] WARNING: LOG_CLEARED_BY_SOMEONE",
                    "user": "UNKNOWN",
                    "pid": "N/A",
                    "file": file,
                    "source": "ANTI-FORENSICS"
                }

        delete_handle_ids =  {event.StringInserts[5] for event in all_events if event.EventID == 4660}

        for event in all_events:
            if event.EventID != 4663: continue
            inserts = event.StringInserts
            handle_id = inserts[7]
            if seen_handles is not None and handle_id in seen_handles: continue
            if "python.exe" in inserts[11].lower(): continue
            
            is_target = os.path.basename(file).lower() in inserts[6].lower()
            is_deleted_now = inserts[7] in delete_handle_ids
            delete_access = (inserts[9] == "0x10000")

            is_matched = False
            if action == "DELETE":
                if is_deleted_now or (is_target and delete_access):
                    is_matched = True
            elif action == "WRITE":
                if is_target and not delete_access:
                    is_matched = True
            
            if is_matched:
                if seen_handles is not None:
                    seen_handles.append(handle_id)
                return normalize_format(inserts)
    except Exception as e:
        print(f"    [!] Unexpected Error in get_event_log: {e}")
        return None
    return None