import sys
import os
from opcua import Client, ua

# =========================
# CONFIG
# =========================
SERVER_ENDPOINT = "opc.tcp://172.20.10.2:4840"
NODE_PATH = [
    "0:Objects",
    "2:HexFileType"
]

MAX_HEX_CHARS = 30000  # max per WriteHex call


# =========================
# MAIN LOGIC
# =========================
def main():
    if len(sys.argv) != 2:
        print("Usage: python upload_client.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    file_name = os.path.basename(file_path)

    print(f"[INFO] Reading file: {file_path}")

    # 1. Read file as bytes
    with open(file_path, "rb") as f:
        data = f.read()

    print(f"[INFO] File size: {len(data)} bytes")

    # 2. Convert bytes to HEX
    hex_data = data.hex()
    print(f"[INFO] Converted to HEX: {len(hex_data)} hex characters")

    # 3. Split into chunks
    chunks = [
        hex_data[i:i + MAX_HEX_CHARS]
        for i in range(0, len(hex_data), MAX_HEX_CHARS)
    ]

    print(f"[INFO] Total chunks: {len(chunks)}")

    # 4. Connect to OPC UA server
    client = Client(SERVER_ENDPOINT)
    client.connect()
    print("[INFO] Connected to OPC UA server")

    try:
        # 5. Get file object
        node = client.get_root_node()
        for path in NODE_PATH:
            node = node.get_child(path)

        # 6. Call Open
        print("[INFO] Calling Open()")
        result = node.call_method(
            "2:Open",
            ua.Variant(1, ua.VariantType.Byte),  # write mode
            ua.Variant(file_name, ua.VariantType.String)
        )

        if isinstance(result, (list, tuple)) and len(result) > 0:
            file_handle = result[0]
        else:
            file_handle = result
        print(f"[INFO] File handle received: {file_handle}")

        # 7. Send chunks
        for i, chunk in enumerate(chunks, start=1):
            print(f"[INFO] Sending chunk {i}/{len(chunks)} ({len(chunk)} chars)")
            status = node.call_method(
                "2:WriteHex",
                ua.Variant(file_handle, ua.VariantType.UInt32),
                ua.Variant(chunk, ua.VariantType.String)
            )

            if isinstance(status, (list, tuple)) and len(status) > 0:
                status = status[0]

            if isinstance(status, ua.StatusCode):
                if status.value != ua.StatusCodes.Good:
                    raise RuntimeError(f"WriteHex failed at chunk {i}: {status}")
            else:
                raise RuntimeError(f"WriteHex returned unexpected type at chunk {i}: {type(status)}")

        # 8. Close file
        print("[INFO] Calling Close()")
        status = node.call_method(
            "2:Close",
            ua.Variant(file_handle, ua.VariantType.UInt32)
        )

        if isinstance(status, (list, tuple)) and len(status) > 0:
            status = status[0]

        if isinstance(status, ua.StatusCode):
            if status.value != ua.StatusCodes.Good:
                raise RuntimeError(f"Close failed: {status}")
        else:
            raise RuntimeError(f"Close returned unexpected type: {type(status)}")

        print("\n[SUCCESS] Transfer completed successfully!")
        # after Close() succeeded

        control_node = client.get_root_node()
        control_path = [
            "0:Objects",
            "2:Programs",
            "2:GCode_Job1",
            "2:TransferRequest"
        ]

        for p in control_path:
            control_node = control_node.get_child(p)

        control_node.set_value(True)
        print("[INFO] TransferRequest set to TRUE")

    finally:
        client.disconnect()
        print("[INFO] Disconnected from server")


if __name__ == "__main__":
    main()
