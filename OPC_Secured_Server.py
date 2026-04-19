from opcua import Server, ua
import os
import hashlib
import datetime
import time
import subprocess
import sys
from opcua.crypto import uacrypto
from opcua.common.connection import SecureConnection


_original_decrypt_rsa_oaep = uacrypto.decrypt_rsa_oaep
_original_decrypt_rsa15 = uacrypto.decrypt_rsa15


def _decrypt_rsa_oaep_safe(private_key, data):
    if isinstance(data, bytearray):
        data = bytes(data)
    return _original_decrypt_rsa_oaep(private_key, data)


def _decrypt_rsa15_safe(private_key, data):
    if isinstance(data, bytearray):
        data = bytes(data)
    return _original_decrypt_rsa15(private_key, data)


uacrypto.decrypt_rsa_oaep = _decrypt_rsa_oaep_safe
uacrypto.decrypt_rsa15 = _decrypt_rsa15_safe

# =========================
# Configuration
# =========================
ENDPOINT = "opc.tcp://192.168.20.10:4840"
#ENDPOINT = "opc.tcp://localhost:4840"

NAMESPACE_URI = r"http://example.org/secure-file-ingress"
FILE_STORAGE_PATH = r"D:\Case Studies\Scalance S\OT_Security\Scenerio1\Final__Code\uploaded_files"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRUSTED_CLIENT_CERT_DIR = os.path.join(BASE_DIR, "pki", "server", "trusted", "certs")

os.makedirs(FILE_STORAGE_PATH, exist_ok=True)
os.makedirs(TRUSTED_CLIENT_CERT_DIR, exist_ok=True)


def load_trusted_certificates():
    certs = []
    for filename in os.listdir(TRUSTED_CLIENT_CERT_DIR):
        path = os.path.join(TRUSTED_CLIENT_CERT_DIR, filename)
        if not os.path.isfile(path):
            continue
        try:
            cert = uacrypto.load_certificate(path)
            certs.append(uacrypto.der_from_x509(cert))
        except Exception as exc:
            print(f"[WARN] Failed to load trusted cert '{filename}': {exc}")
    return certs


TRUSTED_CLIENT_CERTS = load_trusted_certificates()


def normalize_cert_bytes(cert_bytes):
    if not cert_bytes:
        return b""
    if isinstance(cert_bytes, bytearray):
        cert_bytes = bytes(cert_bytes)
    try:
        cert_obj = uacrypto.x509_from_der(cert_bytes)
        if cert_obj is None:
            return cert_bytes
        return uacrypto.der_from_x509(cert_obj)
    except Exception:
        return cert_bytes


def validate_client_cert(cert_bytes):
    normalized = normalize_cert_bytes(cert_bytes)
    if not normalized:
        return False
    normalized_hash = sha256(normalized)
    return any(sha256(trusted) == normalized_hash for trusted in TRUSTED_CLIENT_CERTS)


# Monkey patch connection handling to enforce trust list during handshake
_original_select_policy = SecureConnection.select_policy


def _select_policy_with_validation(self, uri, peer_certificate, mode=None):
    if isinstance(peer_certificate, bytearray):
        peer_certificate = bytes(peer_certificate)
    if peer_certificate:
        peer_hash = sha256(normalize_cert_bytes(peer_certificate))
        trusted_hashes = {sha256(c) for c in TRUSTED_CLIENT_CERTS}
        if peer_hash not in trusted_hashes:
            print(f"[SECURITY] Rejected client certificate SHA256={peer_hash}")
            print("[SECURITY] Trusted certificate SHA256 list:")
            for cert_hash in sorted(trusted_hashes):
                print(f"  - {cert_hash}")
    if peer_certificate and not validate_client_cert(peer_certificate):
        raise ua.UaError("Client certificate not trusted")
    return _original_select_policy(self, uri, peer_certificate, mode)


SecureConnection.select_policy = _select_policy_with_validation


server = Server()
server.set_endpoint(ENDPOINT)
server.set_server_name("Secure File Server")
server.set_security_policy([
    ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt
])

server.load_certificate(r"D:\Case Studies\Scalance S\Code\Final__Code\Scenario_A\pki\server\certs\server_cert.pem")
server.load_private_key(r"D:\Case Studies\Scalance S\Code\Final__Code\Scenario_A\pki\server\private\server_key.pem")

server.set_security_IDs(["Certificate"])



idx = server.register_namespace(NAMESPACE_URI)
objects = server.get_objects_node()

# =========================
# Helper Function
# =========================
def sha256(data):
    return hashlib.sha256(data).hexdigest()

# =========================
# Create Custom FileType with Hex Support
# =========================
# Get the standard FileType from OPC UA
base_file_type = server.get_node(ua.ObjectIds.FileType)

# Create our custom file type derived from FileType
hex_file_type = objects.add_object_type(idx, "HexFileType")

# Add additional properties for hex file handling
checksum_var = hex_file_type.add_variable(
    idx, "Checksum", ""
)
checksum_var.set_modelling_rule(True)

# =========================
# File Handle Management
# =========================
file_handles = {}
next_handle = 1

def open_file(parent, mode, file_name):
    """Open method for hex file"""
    global next_handle
    
    # Extract values from Variant if needed
    if isinstance(mode, ua.Variant):
        mode = mode.Value
    if isinstance(file_name, ua.Variant):
        file_name = file_name.Value
    
    print(f"[DEBUG] Open called with mode: {mode}, file_name: {file_name}")
    
    try:
        # Convert parent to Node if it's a NodeId
        if isinstance(parent, ua.NodeId):
            parent_node = server.get_node(parent)
        else:
            parent_node = parent
        
        # Use provided file name or default to node name
        if not file_name or file_name.strip() == "":
            file_name = parent_node.get_browse_name().Name + ".txt"
        
        file_path = os.path.join(FILE_STORAGE_PATH, file_name)
        
        handle = next_handle
        next_handle += 1
        
        file_handles[handle] = {
            'parent': parent_node,
            'file_name': file_name,
            'file_path': file_path,
            'buffer': bytearray(),
            'mode': mode
        }
        
        print(f"[DEBUG] File opened with handle: {handle}, path: {file_path}")
        return [ua.Variant(handle, ua.VariantType.UInt32)]
        
    except Exception as e:
        print(f"[ERROR] Failed to open file: {e}")
        return [ua.Variant(0, ua.VariantType.UInt32)]

def write_hex(parent, file_handle, hex_data):
    """Write hex data to file"""
    # Extract values from Variant if needed
    if isinstance(file_handle, ua.Variant):
        file_handle = file_handle.Value
    if isinstance(hex_data, ua.Variant):
        hex_data = hex_data.Value
    
    print(f"[DEBUG] Write called - handle: {file_handle}, data length: {len(hex_data)}")
    
    try:
        if file_handle not in file_handles:
            print(f"[ERROR] Invalid file handle: {file_handle}")
            return [ua.Variant(ua.StatusCode(ua.StatusCodes.BadInvalidArgument))]
        
        # Convert hex string to bytes
        hex_clean = hex_data.replace(' ', '').replace('\n', '').replace('\r', '')
        
        if len(hex_clean) % 2 != 0:
            print(f"[ERROR] Hex data has odd length")
            return [ua.Variant(ua.StatusCode(ua.StatusCodes.BadInvalidArgument))]
        
        data = bytes.fromhex(hex_clean)
        file_handles[file_handle]['buffer'].extend(data)
        
        print(f"[DEBUG] Appended {len(data)} bytes, total buffer: {len(file_handles[file_handle]['buffer'])}")
        return [ua.Variant(ua.StatusCode(ua.StatusCodes.Good))]
        
    except ValueError as e:
        print(f"[ERROR] Invalid hex data: {e}")
        return [ua.Variant(ua.StatusCode(ua.StatusCodes.BadInvalidArgument))]
    except Exception as e:
        print(f"[ERROR] Write failed: {e}")
        return [ua.Variant(ua.StatusCode(ua.StatusCodes.BadInternalError))]

def close_file(parent, file_handle):
    """Close file and write to disk"""
    # Extract value from Variant if needed
    if isinstance(file_handle, ua.Variant):
        file_handle = file_handle.Value
    
    print(f"[DEBUG] Close called - handle: {file_handle}")
    
    try:
        if file_handle not in file_handles:
            print(f"[ERROR] Invalid file handle: {file_handle}")
            return [ua.Variant(ua.StatusCode(ua.StatusCodes.BadInvalidArgument))]
        
        handle_info = file_handles[file_handle]
        data = bytes(handle_info['buffer'])
        
        # Write to file
        with open(handle_info['file_path'], 'wb') as f:
            f.write(data)
        
        # Update properties - use stored parent_node
        parent_node = handle_info['parent']
        checksum = sha256(data)
        parent_node.get_child([f"{idx}:Size"]).set_value(len(data))
        parent_node.get_child([f"{idx}:Writable"]).set_value(True)
        parent_node.get_child([f"{idx}:UserWritable"]).set_value(True)
        parent_node.get_child([f"{idx}:OpenCount"]).set_value(0)
        parent_node.get_child([f"{idx}:Checksum"]).set_value(checksum)
        
        print(f"[SUCCESS] File '{handle_info['file_name']}' written successfully")
        print(f"  Path: {handle_info['file_path']}")
        print(f"  Size: {len(data)} bytes")
        print(f"  Checksum: {checksum}")
        
        # Clean up
        del file_handles[file_handle]
        return [ua.Variant(ua.StatusCode(ua.StatusCodes.Good))]
        
    except Exception as e:
        print(f"[ERROR] Close failed: {e}")
        if file_handle in file_handles:
            del file_handles[file_handle]
        return [ua.Variant(ua.StatusCode(ua.StatusCodes.BadInternalError))]

# Add methods to the file type
hex_file_type.add_method(
    idx, "Open", open_file,
    [ua.VariantType.Byte, ua.VariantType.String],
    [ua.VariantType.UInt32]
)

hex_file_type.add_method(
    idx, "WriteHex", write_hex,
    [ua.VariantType.UInt32, ua.VariantType.String],
    [ua.VariantType.StatusCode]
)

hex_file_type.add_method(
    idx, "Close", close_file,
    [ua.VariantType.UInt32],
    [ua.VariantType.StatusCode]
)

# Set modelling rules
for method_name in ["Open", "WriteHex", "Close"]:
    hex_file_type.get_child([f"{idx}:{method_name}"]).set_modelling_rule(True)

# Add standard FileType properties
size_var = hex_file_type.add_variable(idx, "Size", 0, ua.VariantType.UInt64)
size_var.set_modelling_rule(True)

writable_var = hex_file_type.add_variable(idx, "Writable", True, ua.VariantType.Boolean)
writable_var.set_modelling_rule(True)

user_writable_var = hex_file_type.add_variable(idx, "UserWritable", True, ua.VariantType.Boolean)
user_writable_var.set_modelling_rule(True)

open_count_var = hex_file_type.add_variable(idx, "OpenCount", 0, ua.VariantType.UInt16)
open_count_var.set_modelling_rule(True)

# =========================
# Instantiate Objects
# =========================
programs_folder = objects.add_folder(idx, "Programs")

file1 = programs_folder.add_object(idx, "GCode_Job1", hex_file_type)

# Transfer coordination variables consumed by SMB mover client
transfer_request_var = file1.add_variable(idx, "TransferRequest", False, ua.VariantType.Boolean)
transfer_request_var.set_writable()

requested_file_var = file1.add_variable(idx, "RequestedFileName", "", ua.VariantType.String)
requested_file_var.set_writable()

last_status_var = file1.add_variable(idx, "LastTransferStatus", "", ua.VariantType.String)
last_status_var.set_writable()

last_time_var = file1.add_variable(idx, "LastTransferTime", "", ua.VariantType.String)
last_time_var.set_writable()

# =========================
# Start Server
# =========================
def find_listeners_on_port(port):
    listeners = []
    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.splitlines():
            if "LISTENING" not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            local_addr = parts[1]
            state = parts[3]
            pid = parts[4]
            if state != "LISTENING":
                continue
            if not local_addr.endswith(f":{port}"):
                continue

            process_name = "unknown"
            proc_result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH", "/FI", f"PID eq {pid}"],
                capture_output=True,
                text=True,
                check=False,
            )
            row = proc_result.stdout.strip()
            if row and "No tasks" not in row:
                if row.startswith('"') and row.count('"') >= 2:
                    process_name = row.split('"')[1]

            listeners.append((local_addr, pid, process_name))
    except Exception:
        return []

    return listeners


try:
    server.start()
except OSError as exc:
    err_code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    if err_code == 10048:
        print("[ERROR] OPC UA server could not start: port 4840 is already in use.")
        listeners = find_listeners_on_port(4840)
        if listeners:
            print("[ERROR] Current listeners on port 4840:")
            for local_addr, pid, process_name in listeners:
                print(f"  - {local_addr} | PID={pid} | Process={process_name}")
        else:
            print("[ERROR] Could not resolve listener process information.")
        print("[HINT] Stop the existing process and start this server again.")
        sys.exit(1)
    raise

print("===================================")
print(" OPC UA Hex File Server Started ")
print(f" Endpoint: {ENDPOINT}")
print(f" Storage: {FILE_STORAGE_PATH}")
print(" Using FileType-based implementation")
print("===================================")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopping server...")
finally:
    server.stop()