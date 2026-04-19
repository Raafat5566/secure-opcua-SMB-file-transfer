"""
Main Streamlit application for OPC UA File Transfer Dashboard
"""
import streamlit as st
import time
import os
import tempfile
from ui.components import (
    render_header,
    render_status_card,
    render_progress_bar,
    render_file_info,
    render_alert,
    render_transfer_history,
    render_connection_status
)
from ui.styles import get_custom_css
from core.opc_client import OPCFileTransferClient
from core.file_handler import FileHandler
from data.transfer_log import TransferLogger
from config.settings import REFRESH_INTERVAL, SERVER_ENDPOINT

# Page configuration
st.set_page_config(
    page_title="OPC UA File Transfer Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply custom CSS
st.markdown(get_custom_css(), unsafe_allow_html=True)

# Initialize session state
if 'transfer_status' not in st.session_state:
    st.session_state.transfer_status = 'idle'
if 'current_file' not in st.session_state:
    st.session_state.current_file = None
if 'progress' not in st.session_state:
    st.session_state.progress = {'current': 0, 'total': 0}
if 'last_message' not in st.session_state:
    st.session_state.last_message = None
if 'alert_queue' not in st.session_state:
    st.session_state.alert_queue = []
if 'connection_status' not in st.session_state:
    st.session_state.connection_status = None
if 'connection_error' not in st.session_state:
    st.session_state.connection_error = None
if 'connection_pending' not in st.session_state:
    st.session_state.connection_pending = False
if 'transfer_banner_placeholder' not in st.session_state:
    st.session_state.transfer_banner_placeholder = None
if 'server_mode' not in st.session_state:
    st.session_state.server_mode = 'localhost'
if 'custom_endpoint' not in st.session_state:
    st.session_state.custom_endpoint = ""
if 'server_endpoint' not in st.session_state:
    st.session_state.server_endpoint = SERVER_ENDPOINT
if 'last_check_time' not in st.session_state:
    st.session_state.last_check_time = 0
if 'uploader_key' not in st.session_state:
    st.session_state.uploader_key = 0

# Initialize logger
logger = TransferLogger()


def update_transfer_banner(message: str):
    """Display or refresh the in-progress transfer banner."""
    placeholder = st.session_state.get('transfer_banner_placeholder')
    if placeholder is None:
        return
    placeholder.markdown(
        f"""
        <div class=\"transfer-banner\">
            <div class=\"transfer-spinner\"></div>
            <div>
                <strong>Secure transfer in progress</strong>
                <p style=\"margin: 0; color: #8a6d3b;\">{message}</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def clear_transfer_banner():
    placeholder = st.session_state.get('transfer_banner_placeholder')
    if placeholder is not None:
        placeholder.empty()


def set_active_endpoint(endpoint: str | None):
    previous = st.session_state.get('server_endpoint')
    if previous == endpoint:
        return

    st.session_state.server_endpoint = endpoint
    st.session_state.connection_status = None
    st.session_state.connection_error = None
    st.session_state.connection_pending = False
    st.session_state.last_check_time = 0


def perform_transfer(uploaded_file):
    """Perform the file transfer operation"""
    temp_path = None
    try:
        # Create per-transfer temp file outside project workspace
        suffix = os.path.splitext(uploaded_file.name)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(uploaded_file.getbuffer())
            temp_path = temp_file.name

        # Initialize components
        file_handler = FileHandler(temp_path)
        endpoint = st.session_state.get('server_endpoint')
        if not endpoint:
            raise Exception("No OPC UA endpoint configured.")
        opc_client = OPCFileTransferClient(endpoint=endpoint)
        
        # Update status
        st.session_state.transfer_status = 'in_progress'
        st.session_state.current_file = file_handler.file_info['name']
        update_transfer_banner("Connecting to OPC UA server...")
        
        # Connect to server
        success, message = opc_client.connect()
        if not success:
            raise Exception(message)

        update_transfer_banner("Uploading file to OPC UA server...")
        
        # Prepare file
        file_handler.create_chunks()
        total_chunks = file_handler.get_total_chunks()
        st.session_state.progress = {'current': 0, 'total': total_chunks}
        
        # Log start
        logger.log_transfer(
            file_handler.file_info['name'],
            file_handler.file_info['size'],
            'in_progress',
            chunks_sent=0,
            total_chunks=total_chunks
        )
        
        # Open file
        success, message = opc_client.open_file(file_handler.file_info['name'])
        if not success:
            raise Exception(message)
        
        # Send chunks
        for i, chunk in enumerate(file_handler.chunks):
            success, message = opc_client.write_chunk(chunk)
            if not success:
                raise Exception(message)
            
            st.session_state.progress['current'] = i + 1
            update_transfer_banner(f"Sending chunk {i + 1} of {total_chunks}...")
            time.sleep(0.1)  # Small delay for UI update
        
        # Close file
        success, message = opc_client.close_file()
        if not success:
            raise Exception(message)
        
        # Set transfer request
        success, message = opc_client.set_transfer_request()
        if not success:
            raise Exception(message)
        
        # Success!
        st.session_state.transfer_status = 'success'
        st.session_state.last_message = "Transfer completed successfully!"
        clear_transfer_banner()
        
        logger.log_transfer(
            file_handler.file_info['name'],
            file_handler.file_info['size'],
            'success',
            chunks_sent=total_chunks,
            total_chunks=total_chunks
        )
        
        opc_client.disconnect()
        return True
        
    except Exception as e:
        st.session_state.transfer_status = 'failed'
        st.session_state.last_message = str(e)
        
        logger.log_transfer(
            st.session_state.current_file or "Unknown",
            0,
            'failed',
            error_message=str(e),
            chunks_sent=st.session_state.progress['current'],
            total_chunks=st.session_state.progress['total']
        )
        
        if 'opc_client' in locals():
            opc_client.disconnect()
        clear_transfer_banner()
        return False
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


def main():
    """Main dashboard application"""
    
    # Render header
    render_header()
    
    # Sidebar
    with st.sidebar:
        st.header("Control Panel")

        # Server selection
        st.subheader("Server Connection")
        server_option_map = {
            "Localhost Server": "localhost",
            "Custom Endpoint": "custom",
        }
        mode_labels = list(server_option_map.keys())
        default_index = 0 if st.session_state.server_mode == 'localhost' else 1
        selected_label = st.radio(
            "Choose OPC UA Server",
            options=mode_labels,
            index=default_index,
        )
        selected_mode = server_option_map[selected_label]
        st.session_state.server_mode = selected_mode

        new_endpoint = SERVER_ENDPOINT if selected_mode == 'localhost' else None

        if selected_mode == 'localhost':
            st.info(f"Using local OPC UA server: {SERVER_ENDPOINT}")
        else:
            custom_value = st.text_input(
                "Server Endpoint",
                value=st.session_state.custom_endpoint,
                placeholder="opc.tcp://192.168.0.10:4840",
            )
            st.session_state.custom_endpoint = custom_value
            new_endpoint = custom_value.strip() or None
            if new_endpoint:
                st.success(f"Using custom endpoint: {new_endpoint}")
            else:
                st.warning("Enter a valid OPC UA endpoint to connect.")

        set_active_endpoint(new_endpoint)
        st.markdown("---")
        
        # File upload with dynamic key for reset capability
        uploaded_file = st.file_uploader(
            "Upload File for Transfer",
            type=None,
            help="Select any file to transfer via OPC UA",
            key=f"file_uploader_{st.session_state.uploader_key}"
        )
        
        # Transfer button - only show if server is connected
        if uploaded_file is not None:
            if st.session_state.connection_status:
                st.markdown(
                    """
                    <style>
                    div.stButton > button {
                        background-color: #28a745;
                        color: white;
                        font-weight: bold;
                        border: none;
                        padding: 0.5rem 1rem;
                        border-radius: 5px;
                    }
                    div.stButton > button:hover {
                        background-color: #218838;
                        color: white;
                    }
                    </style>
                    """,
                    unsafe_allow_html=True,
                )

                if st.button("Start Transfer", type="primary"):
                    perform_transfer(uploaded_file)
                    st.rerun()
            else:
                st.markdown(
                    '<p style="color: #dc3545; font-weight: bold; padding: 10px; '
                    'background-color: #f8d7da; border-radius: 5px; text-align: center;">'
                    'Please Connect to the Server First</p>',
                    unsafe_allow_html=True,
                )
        
        st.markdown("---")
        
        # Clear alerts button
        if st.session_state.transfer_status in ['success', 'failed']:
            if st.button("Acknowledge and Clear"):
                st.session_state.transfer_status = 'idle'
                st.session_state.current_file = None
                st.session_state.progress = {'current': 0, 'total': 0}
                st.session_state.last_message = None
                
                # Increment uploader key to reset file uploader
                st.session_state.uploader_key += 1
                
                st.rerun()
        
        st.markdown("---")
        
        # Clear history
        if st.button("Clear History"):
            logger.clear_logs()
            st.success("History cleared!")
            time.sleep(1)
            st.rerun()
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Status card
        render_status_card(
            st.session_state.transfer_status,
            st.session_state.current_file,
            st.session_state.last_message
        )

        # Reserve space for the dynamic transfer banner
        st.session_state.transfer_banner_placeholder = st.empty()
        
        # Progress bar (only during transfer)
        if st.session_state.transfer_status == 'in_progress':
            render_progress_bar(
                st.session_state.progress['current'],
                st.session_state.progress['total']
            )
    
    with col2:
        current_time = time.time()
        active_endpoint = st.session_state.get('server_endpoint')

        # Schedule a new connection check if interval elapsed and an endpoint is available
        if active_endpoint:
            if (
                current_time - st.session_state.last_check_time > 5
                and not st.session_state.connection_pending
            ):
                st.session_state.connection_pending = True
        else:
            st.session_state.connection_pending = False
            st.session_state.connection_status = False
            st.session_state.connection_error = "No OPC UA endpoint configured."

        # Display current connection status or pending state
        render_connection_status(
            st.session_state.connection_status,
            st.session_state.connection_error,
            st.session_state.connection_pending and bool(active_endpoint)
        )

        # Execute connection check while warning is shown, then refresh
        if st.session_state.connection_pending and active_endpoint:
            try:
                opc_client = OPCFileTransferClient(endpoint=active_endpoint)
                is_connected, message = opc_client.connect()
                if is_connected:
                    opc_client.disconnect()
                    st.session_state.connection_error = None
                else:
                    st.session_state.connection_error = (
                        message or "Unable to reach OPC UA server."
                    )
                st.session_state.connection_status = is_connected
            except Exception as exc:
                st.session_state.connection_status = False
                st.session_state.connection_error = str(exc)
            finally:
                st.session_state.last_check_time = time.time()
                st.session_state.connection_pending = False
                st.rerun()
        
        # Current file info
        if st.session_state.current_file:
            latest_log = logger.get_latest_log()
            if latest_log:
                st.markdown("### Current Transfer")
                st.metric("File", latest_log['file_name'])
                st.metric("Status", latest_log['status'].title())
    
    # Transfer history
    st.markdown("---")
    logs = logger.get_all_logs()
    render_transfer_history(logs)
    
    # Auto-refresh during transfer
    if st.session_state.transfer_status == 'in_progress':
        time.sleep(REFRESH_INTERVAL)
        st.rerun()


if __name__ == "__main__":
    main()
