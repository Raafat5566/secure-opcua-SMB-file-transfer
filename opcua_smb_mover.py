import os
import time
import shutil
import hashlib
from datetime import datetime
from opcua import Client, ua

# Streamlit run app.py

# =========================
# CONFIG (EDIT THESE)
# =========================
OPCUA_ENDPOINT = "opc.tcp://192.168.20.10:4840"
#OPCUA_ENDPOINT = "opc.tcp://localhost:4840"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Certificate material for authenticated client sessions
CLIENT_CERT_PATH = os.path.join(BASE_DIR, "pki", "mover", "certs", "mover_cert.der")
CLIENT_KEY_PATH = os.path.join(BASE_DIR, "pki", "mover", "private", "mover_key.pem")
SERVER_CERT_PATH = os.path.join(BASE_DIR, "pki", "server", "certs", "server_cert.der")

# Namespace URI advertised by the secure server; resolve its numeric index at runtime
NAMESPACE_URI = "http://example.org/secure-file-ingress"

# Browse path template to your file object (Objects -> Programs -> GCode_Job1)
FILE_OBJECT_PATH_TEMPLATE = [
    "0:Objects",
    "{ns}:Programs",
    "{ns}:GCode_Job1",
]

# Where your OPC UA server writes uploaded files on disk (same as FILE_STORAGE_PATH in server)
STAGING_DIR = r"D:\Case Studies\Scalance S\OT_Security\Scenerio1\Final__Code\uploaded_files"

# Your SMB share target (works locally)
SMB_TARGET_DIR = r"D:\Case Studies\Scalance S\OT_Security\Scenerio1\Final__Code\SMB_Share"

# Behavior
DELETE_FROM_STAGING_AFTER_COPY = True
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB safety cap
ALLOWED_EXTENSIONS = {".txt", ".nc", ".gcode", ".hex", ".csv", ".pdf",".jpg",".jpeg", ".png"}  # adjust for your case

# Polling behavior
WAIT_FOR_REQUEST = True
REQUEST_POLL_SECONDS = 1.0
REQUEST_TIMEOUT_SECONDS = 0  # 0 = wait forever
FILE_WAIT_SECONDS = 30

# Node browse-name templates residing under the file object
NODE_TRANSFER_REQUEST = "{ns}:TransferRequest"
NODE_REQUESTED_FILE   = "{ns}:RequestedFileName"
NODE_LAST_STATUS      = "{ns}:LastTransferStatus"
NODE_LAST_TIME        = "{ns}:LastTransferTime"


# =========================
# HELPERS
# =========================
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def pick_file(staging_dir: str, requested_name: str) -> str:
    if requested_name and requested_name.strip():
        candidate = os.path.join(staging_dir, requested_name.strip())
        if not os.path.isfile(candidate):
            raise FileNotFoundError(f"Requested file not found in staging: {candidate}")
        return candidate

    # else pick newest regular file
    files = [
        os.path.join(staging_dir, f)
        for f in os.listdir(staging_dir)
        if os.path.isfile(os.path.join(staging_dir, f))
    ]
    if not files:
        raise FileNotFoundError("No files found in staging directory.")
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return files[0]

def validate_file(path: str):
    size = os.path.getsize(path)
    if size <= 0:
        raise ValueError("File is empty.")
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"File too large: {size} bytes (cap={MAX_FILE_SIZE_BYTES})")
    ext = os.path.splitext(path)[1].lower()
    if ALLOWED_EXTENSIONS and ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension not allowed: {ext} (allowed={sorted(ALLOWED_EXTENSIONS)})")

def wait_for_request(n_req, n_name):
    start_time = time.time()
    while True:
        transfer_request = bool(n_req.get_value())
        requested_name = str(n_name.get_value() or "").strip()

        if transfer_request:
            return True, requested_name

        if not WAIT_FOR_REQUEST:
            return False, requested_name

        if REQUEST_TIMEOUT_SECONDS and (time.time() - start_time) >= REQUEST_TIMEOUT_SECONDS:
            return False, requested_name

        time.sleep(REQUEST_POLL_SECONDS)

def wait_for_file(staging_dir: str, requested_name: str, timeout_seconds: int):
    start_time = time.time()
    while True:
        try:
            candidate = pick_file(staging_dir, requested_name)
            return candidate
        except FileNotFoundError:
            if timeout_seconds and (time.time() - start_time) >= timeout_seconds:
                raise
            time.sleep(1)


def update_error_state(n_status, n_time, n_req, message: Exception):
    """Attempt to push an error marker back to the OPC UA server."""
    timestamp = datetime.now().isoformat(timespec="seconds")
    try:
        n_status.set_value(f"ERROR: {message}")
        n_time.set_value(timestamp)
        n_req.set_value(False)
    except Exception:
        pass


# =========================
# MAIN
# =========================
def main():
    # sanity checks
    if not os.path.isdir(STAGING_DIR):
        raise RuntimeError(f"STAGING_DIR does not exist: {STAGING_DIR}")
    if not os.path.isdir(SMB_TARGET_DIR):
        raise RuntimeError(f"SMB_TARGET_DIR not reachable: {SMB_TARGET_DIR}")
    for path, label in (
        (CLIENT_CERT_PATH, "client certificate"),
        (CLIENT_KEY_PATH, "client private key"),
        (SERVER_CERT_PATH, "server certificate"),
    ):
        if not os.path.isfile(path):
            raise RuntimeError(f"Missing {label} at: {path}")

    client = Client(OPCUA_ENDPOINT)
    client.set_security_string(
        f"Basic256Sha256,SignAndEncrypt,{CLIENT_CERT_PATH},{CLIENT_KEY_PATH},{SERVER_CERT_PATH}"
    )
    client.connect()
    print("[INFO] Connected to OPC UA:", OPCUA_ENDPOINT)

    try:
        try:
            ns_index = client.get_namespace_index(NAMESPACE_URI)
        except ua.UaError as exc:
            raise RuntimeError(
                f"Namespace URI '{NAMESPACE_URI}' not found on server"
            ) from exc
        file_object_path = [seg.format(ns=ns_index) for seg in FILE_OBJECT_PATH_TEMPLATE]
        node_transfer_request = NODE_TRANSFER_REQUEST.format(ns=ns_index)
        node_requested_file = NODE_REQUESTED_FILE.format(ns=ns_index)
        node_last_status = NODE_LAST_STATUS.format(ns=ns_index)
        node_last_time = NODE_LAST_TIME.format(ns=ns_index)

        # Get file object node
        node = client.get_root_node()
        for p in file_object_path:
            node = node.get_child(p)

        # Get control variable nodes
        n_req = node.get_child([node_transfer_request])
        n_name = node.get_child([node_requested_file])
        n_status = node.get_child([node_last_status])
        n_time = node.get_child([node_last_time])

        print("[INFO] Watching for transfer requests. Press Ctrl+C to stop.")

        while True:
            try:
                transfer_request, requested_name = wait_for_request(n_req, n_name)

                if not transfer_request:
                    time.sleep(REQUEST_POLL_SECONDS)
                    continue

                # Mark in progress
                n_status.set_value("IN_PROGRESS")
                n_time.set_value(datetime.now().isoformat(timespec="seconds"))

                # Pick & validate file (wait briefly if needed)
                src_path = wait_for_file(STAGING_DIR, requested_name, FILE_WAIT_SECONDS)
                validate_file(src_path)

                fname = os.path.basename(src_path)
                dst_path = os.path.join(SMB_TARGET_DIR, fname)

                print(f"[INFO] Moving file: {src_path} -> {dst_path}")

                # Copy
                shutil.copy2(src_path, dst_path)

                # Verify
                src_size = os.path.getsize(src_path)
                dst_size = os.path.getsize(dst_path)
                if src_size != dst_size:
                    raise RuntimeError(f"Copy verification failed: size mismatch {src_size} != {dst_size}")

                src_hash = sha256_file(src_path)
                dst_hash = sha256_file(dst_path)
                if src_hash != dst_hash:
                    raise RuntimeError("Copy verification failed: SHA256 mismatch")

                # Cleanup staging
                if DELETE_FROM_STAGING_AFTER_COPY:
                    os.remove(src_path)
                    print("[INFO] Deleted staging file after successful copy.")

                # Success status + reset request
                n_status.set_value(f"DONE: {fname}")
                n_time.set_value(datetime.now().isoformat(timespec="seconds"))
                n_req.set_value(False)
                n_name.set_value("")  # clear requested name

                print("[SUCCESS] Transfer completed and request reset. Waiting for next request...")

            except Exception as transfer_error:
                update_error_state(n_status, n_time, n_req, transfer_error)
                print(f"[ERROR] Transfer failed: {transfer_error}")
                time.sleep(REQUEST_POLL_SECONDS)

    except KeyboardInterrupt:
        print("[INFO] Keyboard interrupt received. Stopping watcher.")

    finally:
        client.disconnect()
        print("[INFO] Disconnected from OPC UA")


if __name__ == "__main__":
    main()
