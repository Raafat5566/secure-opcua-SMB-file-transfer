# Secure OPC UA File Transfer + SMB Delivery

This project implements a secure, industrial-style file transfer pipeline using OPC UA for ingestion and an SMB mover for final delivery.

![System Overview](System%20Overview.png)



## What this system does

1. A client uploads a file to an OPC UA server in chunks (hex-encoded payload).
2. The server reconstructs the file and stores it in a staging directory.
3. The client sets a transfer trigger (`TransferRequest = True`) and can provide a target file name.
4. A mover service listens for that trigger, validates the staged file, copies it to the SMB target, verifies integrity, and reports status back to OPC UA.

This creates a controlled handoff between **file ingestion** and **file distribution**.

## Main components

- `OPC_Secured_Server.py`
  - Hosts the secure OPC UA endpoint.
  - Enforces trusted client certificates.
  - Exposes file-related methods (`Open`, `WriteHex`, `Close`) and coordination variables:
	 - `TransferRequest`
	 - `RequestedFileName`
	 - `LastTransferStatus`
	 - `LastTransferTime`

- `OPC_Client.py` / `core/opc_client.py`
  - Connects to the server.
  - Opens a remote file handle, sends chunks, closes the file.
  - Sets `TransferRequest` when upload completes.

- `opcua_smb_mover.py`
  - Polls `TransferRequest`.
  - Waits for the staged file, validates size/extension.
  - Copies to `SMB_TARGET_DIR`, verifies size + SHA-256 hash, optionally deletes staging file.
  - Updates `LastTransferStatus` and timestamp, then resets request flags.

- `app.py` (Streamlit dashboard)
  - Provides UI for upload, status, progress, and transfer history.
  - Uses `core/file_handler.py` for chunking and `data/transfer_log.py` for audit logging.

## End-to-end flow

1. **Secure session setup**
	- Client and mover connect using certificate-based security (`Basic256Sha256`, SignAndEncrypt).

2. **Upload stage**
	- Client calls server methods to open and write file chunks.
	- Server writes reconstructed bytes into `uploaded_files`.

3. **Transfer request stage**
	- Client sets `TransferRequest = True` and optionally `RequestedFileName`.

4. **SMB delivery stage**
	- Mover detects request, selects the requested/newest file, validates policy constraints.
	- File is copied to SMB target and verified.

5. **Completion and reset**
	- Mover sets status (`DONE: <file>` or `ERROR: ...`), updates time, clears request values.

## Why this design (brief)

- **Security first**: certificate trust validation reduces unauthorized OPC UA access.
- **Reliability**: staged upload + separate mover decouples ingestion from network share availability.
- **Integrity**: post-copy size and SHA-256 checks detect corruption.
- **Operational visibility**: explicit status/timestamp nodes and transfer logs simplify troubleshooting.
- **Automation-friendly**: `TransferRequest` handshake provides deterministic machine-to-machine coordination.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run order

1. Start the secure OPC UA server:

```powershell
python .\OPC_Secured_Server.py
```

2. Start the SMB mover service:

```powershell
python .\opcua_smb_mover.py
```

3. Upload a file using either:

- CLI client:

```powershell
python .\OPC_Client.py "C:\path\to\file.gcode"
```

- Dashboard:

```powershell
streamlit run .\app.py
```

## Operational notes

- Confirm paths in `OPC_Secured_Server.py` and `opcua_smb_mover.py` match your environment.
- Ensure `SMB_TARGET_DIR` is reachable and writable by the mover process.
- Place trusted client certificates under `pki/server/trusted/certs` for authenticated access.

## Firewall requirements

- **Client -> OPC UA Server:** allow outbound/inbound TCP `4840` (or your configured OPC UA endpoint port).
- **SMB Mover -> SMB Share:** allow SMB traffic on TCP `445` (and TCP `139` only if your environment still requires NetBIOS session service).
- **Host-based firewall:** create explicit allow rules between the involved hosts (Client, OPC UA Server host, SMB host) and deny unused ports by default.
- **Rationale:** these rules ensure secure OPC UA connectivity and reliable SMB file delivery while limiting unnecessary network exposure.
