#!./bin/python3
import os
import sys
import gzip
import time
import base64
import socket
import threading
import configparser
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Cipher import AES, PKCS1_OAEP


config = configparser.ConfigParser()
config.read("server_config.ini")

# Where this server should bind, defaults to 0.0.0.0:19385
SERVER_HOST = config['server']['host']
SERVER_PORT = int(config['server']['port'])
LOG_SAVE_PATH = config['server']['log_save_path']
TIME_TO_REQUEST_LOGS = config['server']['time_to_request_logs']

# Crypto settings, clients and servers must match
CRYPTO_RSA_KEYSIZE = int(config['crypto']['rsa_keysize'])
CRYPTO_AES_KEYSIZE = int(config['crypto']['aes_keysize'])

# Path of the server's keys.
KEY_DIRECTORY = Path(config['crypto']['key_directory']).resolve()

INTEGER_SIZE = 32
CHUNK_SIZE = 4096


client_machines_info = {}

@dataclass
class ClientInfo:
    id: str
    ip: str
    port: int    
    last_seen: float = 0.0

@dataclass
class HandshakeResult:
    machine_id: str
    aes_key: bytes
    client_rsa_public_key: RSA.RsaKey | None
    
# ------------------------------------------------------- #
# Key Management
# ------------------------------------------------------- #
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def generate_aes_key(bits=256):
    return os.urandom(int(bits/8))


def load_or_generate_keys(keysize: int, key_directory: str):
    key_dir = Path(key_directory).resolve()
    key_dir.mkdir(parents=True, exist_ok=True)

    pub_path = key_dir /  "server_rsa_public_key.pem"
    priv_path = key_dir / "server_rsa_private_key.pem"

    pub_exists = pub_path.exists() and pub_path.stat().st_size > 0
    priv_exists = priv_path.exists() and priv_path.stat().st_size > 0

    if pub_exists and priv_exists:
        print("[CRYPTO] Loading RSA Keys...")
        rsa_public_key = load_rsa_key(pub_path)
        rsa_private_key = load_rsa_key(priv_path)
        return rsa_public_key, rsa_private_key

    print("[CRYPTO] Generating new RSA keys...")
    key = RSA.generate(keysize)
    rsa_private_key = key
    rsa_public_key = key.publickey()

    # write to disk
    with open(pub_path, "wb") as f:
        f.write(rsa_public_key.export_key())
    with open(priv_path, "wb") as f:
        f.write(rsa_private_key.export_key())

    return rsa_public_key, rsa_private_key

def load_rsa_key(filename: str):
    path = KEY_DIRECTORY / filename
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

# ------------------------------------------------------- #
# AES-GCM
# ------------------------------------------------------- #
def aes_encrypt(key, plaintext: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "nonce": base64.b64encode(cipher.nonce),
        "ciphertext": base64.b64encode(ciphertext),
        "tag": base64.b64encode(tag)
    }


def aes_decrypt(key, encrypted_data: dict):
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])

    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ------------------------------------------------------- #
# RSA
# ------------------------------------------------------- #

def rsa_encrypt(public_key, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def rsa_decrypt(private_key, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(data)

def generate_rsa_pss_signature(rsa_private_key: RSA.RsaKey, message: bytes) -> bytes:
    h = SHA512.new(message)
    signature = pss.new(rsa_private_key).sign(h)
    return signature

def verify_rsa_pss_signature(rsa_public_key: RSA.RsaKey, message: bytes, signature: bytes) -> bool:
    h = SHA512.new(message)
    try:
        pss.new(rsa_public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ------------------------------------------------------ #
# Log Magic
# ------------------------------------------------------ #

def _decompress_and_decode(data: bytes) -> str:
    """Helper: decompress gzip and base64 decode"""
    return base64.b64decode(gzip.decompress(data).decode("UTF-8")).decode("UTF-8")

def recv_log(connection, aes_key, client_rsa_public_key):
    """Receive a single log file (path + data)"""
    dec_pth, lench_pth = recv_aes_encrypted(connection, aes_key, client_rsa_public_key)
    dec_log, lench_log = recv_aes_encrypted(connection, aes_key, client_rsa_public_key)

    log_path = _decompress_and_decode(dec_pth)
    log_data = _decompress_and_decode(dec_log)

    print(f"[NETWORK] Recv log {log_path} ({lench_pth}) with chunks {lench_log}")
    return log_path, log_data

def save_log(machine_id, log_path, log_data) -> None:
    cfg_logpath = Path(LOG_SAVE_PATH).resolve()
    cli_path = Path(log_path)

    if cli_path.is_absolute():
        cli_path = cli_path.relative_to(cli_path.anchor)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    dirs = cli_path.parent
    filename = cli_path.name

    safe_base = cfg_logpath / machine_id
    full_path = safe_base / dirs / f"{timestamp}_{filename}"

    full_path = full_path.resolve()

    if cfg_logpath not in full_path.parents:
        raise ValueError(f"Unsafe log path provided (Path Traversal) {cfg_logpath} not in '{full_path}'")

    full_path.parent.mkdir(parents=True, exist_ok=True)

    with open(full_path, "w") as f:
        print(f"[FS] Saving log to {full_path}")
        f.write(log_data)


# ------------------------------------------------------ #
# Chunk Data Recv
# ------------------------------------------------------ #

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionResetError("Connection closed while receiving chunk")
        data += chunk
    return data


def recv_chunked(connection: socket.socket):
    chunk_count = recv_int(connection)
    chunks = []

    for _ in range(chunk_count):
        chunk_index = recv_int(connection)
        chunk_length = recv_int(connection)

        # IMPORTANT: Read *exactly* chunk_length bytes
        chunk_data = recv_exact(connection, chunk_length)

        chunks.append(chunk_data)

        # ACK
        connection.send(b'2')

    return b"".join(chunks), chunk_count


# ------------------------------------------------------- #
# Helpers
# ------------------------------------------------------- #

def recv_int(connection: socket.socket, size: int = INTEGER_SIZE) -> int:
    return int.from_bytes(connection.recv(size), 'big')

def send_int(connection: socket.socket, value: int, size: int = INTEGER_SIZE) -> None:
    connection.sendall(value.to_bytes(size, 'big'))

def recv_fixed_width(sock: socket.socket, width: int) -> bytes:
    buf = b''
    while len(buf) < width:
        chunk = sock.recv(width - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed during fixed-width receive")
        buf += chunk
    return buf.rstrip(b'\x00')

def send_fixed_width(sock: socket.socket, data: bytes, width: int):
    if len(data) > width:
        raise ValueError("Data too long for fixed-width field")
    padded = data.ljust(width, b'\x00')
    sock.sendall(padded)

def _recv_aes_blob(connection, aes_key, chunked: bool = True):
    """Helper to receive AES encrypted blob (nonce + ciphertext + tag)"""
    nonce_sz = recv_int(connection)
    ciphertext_sz = recv_int(connection)
    tag_sz = recv_int(connection)
    
    if chunked:
        enc_bytes, chunk_count = recv_chunked(connection)
    else:
        enc_bytes = connection.recv(nonce_sz + ciphertext_sz + tag_sz)
        chunk_count = 0
    
    dec_bytes = aes_decrypt(aes_key, {
        "nonce": enc_bytes[:nonce_sz],
        "ciphertext": enc_bytes[nonce_sz:nonce_sz + ciphertext_sz],
        "tag": enc_bytes[-tag_sz:]
    })
    
    return dec_bytes, chunk_count

def recv_aes_encrypted(connection, aes_key, client_rsa_public_key: RSA.RsaKey | None = None):
    """Receive AES encrypted data with optional RSA signature (chunked)"""
    data_dec_bytes, data_lenchunks = _recv_aes_blob(connection, aes_key, chunked=True)

    if client_rsa_public_key is not None:
        sign_dec_bytes, _ = _recv_aes_blob(connection, aes_key, chunked=True)
        
        if not verify_rsa_pss_signature(client_rsa_public_key, data_dec_bytes, sign_dec_bytes):
            raise Exception("Sign Verification Failed")

    return data_dec_bytes, data_lenchunks

def recv_unchunked_aes_encrypted(connection, aes_key, client_rsa_public_key: RSA.RsaKey | None = None):
    """Receive AES encrypted data with optional RSA signature (unchunked)"""
    data_dec_bytes, _ = _recv_aes_blob(connection, aes_key, chunked=False)

    if client_rsa_public_key is not None:
        sign_dec_bytes, _ = _recv_aes_blob(connection, aes_key, chunked=True)  # Signature always chunked
        
        if not verify_rsa_pss_signature(client_rsa_public_key, data_dec_bytes, sign_dec_bytes):
            raise Exception("Sign Verification Failed")

    return data_dec_bytes

# ------------------------------------------------------- #
# All pre-code authentication logic (Handshake)
# ------------------------------------------------------- #

def perform_handshake(connection: socket.socket) -> HandshakeResult:
    # Receive and decrypt AES key
    client_aes_key_enc_bytes = connection.recv(CRYPTO_AES_KEYSIZE)
    client_aes_key = rsa_decrypt(rsa_private_key, client_aes_key_enc_bytes)
    print(f"[CRYPTO] Client AES key (HEX): 0x{client_aes_key.hex().upper()}")

    # Receive machine_id
    machine_id = recv_unchunked_aes_encrypted(connection, client_aes_key).decode("UTF-8")
    print(f"[NETWORK] Recv MachineID {machine_id}")

    # Load client's pre-shared RSA public key
    try:
        client_rsa_public_key = load_rsa_key(f"client_{machine_id}_rsa_public_key.pem")
    except Exception as e:
        raise Exception(f"Failed to load client RSA key: {e}")

    print(f"[HANDSHAKE] ✓ Complete for {machine_id}")
    
    return HandshakeResult(
        machine_id=machine_id,
        aes_key=client_aes_key,
        client_rsa_public_key=client_rsa_public_key
    )

# ------------------------------------------------------- #
# Main Subroutine
# ------------------------------------------------------- #

rsa_public_key, rsa_private_key = load_or_generate_keys(CRYPTO_RSA_KEYSIZE, KEY_DIRECTORY)

print(f"[CRYPTO] Loaded {rsa_private_key}")
print(f"[CRYPTO] Loaded {rsa_public_key}")

def handle_client_request(connection: socket.socket, address) -> bool:
    print(f"[NETWORK] Connection from {address} accepted")

    try:
        handshake = perform_handshake(connection)
    except Exception as e:
        print(f"[HANDSHAKE] Failed: {e}")
        connection.shutdown(socket.SHUT_WR)
        connection.close()
        return

    # Receive operation code
    code = recv_fixed_width(connection, 30)
    
    if code == b'NegotiateReverseConnection':
        client_port = recv_int(connection)
        client_machines_info[handshake.machine_id] = ClientInfo(
            handshake.machine_id, 
            connection.getpeername()[0], 
            client_port, 
            time.time()
        )
        connection.shutdown(socket.SHUT_WR)
        connection.close()
        return

    if code == b'SendLogsBegin':
        logfile_count = recv_int(connection)
        print(f"[NETWORK] Client sending {logfile_count} log files")
        try:
            for i in range(logfile_count):
                log_path, log_data = recv_log(
                    connection, 
                    handshake.aes_key, 
                    handshake.client_rsa_public_key
                )
                save_log(handshake.machine_id, log_path, log_data)
        except Exception as e:
            print(f"[CRYPTO] Client {handshake.machine_id} error: {e}")
        finally:
            connection.shutdown(socket.SHUT_WR)
            connection.close()
        return

    connection.shutdown(socket.SHUT_WR)
    connection.close()

# ------------------------------------------------------- #
# CLI Commands
# ------------------------------------------------------- #

def cli_machines():
    print(f"[CLI] | {"machine-id".ljust(32, ' ')} | {"IP".ljust(15, ' ')} | {"PORT".ljust(5, ' ')} |")
    print(f"[CLI] +-{"".ljust(32, '-')}-+-{"".ljust(15, '-')}-+-{"".ljust(5, '-')}-+")
    for id, info in list(client_machines_info.items()):
        print(f"[CLI] | {str(info.id).ljust(32, ' ')} | {str(info.ip).ljust(15, ' ')} | {str(info.port).ljust(5, ' ')} |")

# HELPER Finds Client by Machine ID
def _find_client(machine_id: str) -> ClientInfo | None:
    for id, info in list(client_machines_info.items()):
        if id == machine_id:
            return info
    return None

# HELPER Sends command to reverse listener
def _send_command_to_client(client: ClientInfo, command: bytes):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((client.ip, client.port))
    send_fixed_width(connection, command, 30)
    client_machines_info[client.id] = None

def cli_renegotiate(cmd):
    cmd_parts = cmd.strip().split(" ")
    if len(cmd_parts) != 2:
        print("[CLI] Usage: renegotiate <machine-id>")
        return

    client = _find_client(cmd_parts[1])
    if not client:
        print(f"[CLI] Client '{cmd_parts[1]}' not found")
        return

    print(f"[NETWORK] Connecting to client {client.id} via {client.ip}:{client.port}")
    _send_command_to_client(client, b'RenegotiateConnection')

def cli_force_send(cmd):
    cmd_parts = cmd.strip().split(" ")
    if len(cmd_parts) != 2:
        print("[CLI] Usage: force_send <machine-id>")
        return

    client = _find_client(cmd_parts[1])
    if not client:
        print(f"[CLI] Client '{cmd_parts[1]}' not found")
        return

    print(f"[NETWORK] Sending log request to {client.id} via {client.ip}:{client.port}")
    _send_command_to_client(client, b'SendLogs')

# Force Send All
def cli_fsa():
    for id, _ in list(client_machines_info.items()):
        cli_force_send(f"force_send {id}")

def cli_whois(cmd):
    cmd_parts = cmd.strip().split(" ")
    if len(cmd_parts) != 2:
        print("[CLI] Usage: whois <ip>")
        return

    ip = cmd_parts[1]
    for id, info in list(client_machines_info.items()):
        if info.ip == ip:
            print(f"[CLI] | {"machine-id".ljust(32, ' ')} | {"IP".ljust(15, ' ')} | {"PORT".ljust(5, ' ')} |")
            print(f"[CLI] +-{"".ljust(32, '-')}-+-{"".ljust(15, '-')}-+-{"".ljust(5, '-')}-+")
            print(f"[CLI] | {str(info.id).ljust(32, ' ')} | {str(info.ip).ljust(15, ' ')} | {str(info.port).ljust(5, ' ')} |")
            return
    print("[CLI] No machine found with that IP")

def cli_exit():
    for id, info in list(client_machines_info.items()):    
        cli_renegotiate(f"renegotiate {id}")
    print("[SERVER] Shutting Down")
    exit()

def command_line_interface():
    try:
        print("[CLI] Input '?' or 'help' to list commands")
        while True:
            cmd = input("[CLI]>").strip().lower()
            match cmd:
                case '?' | 'help':
                    print("[CLI] Listing Commands")
                    print("[CLI] 'machines' - lists info of machines")
                    print("[CLI] 'renegotiate <machine-id>' - disconnect and renegotiate")
                    print("[CLI] 'force_send <machine-id>' - force log send")
                    print("[CLI] 'fsa' - force send all")
                    print("[CLI] 'whois <ip>' - lookup machine by IP")
                    print("[CLI] 'exit' - shutdown server")
                case _ if cmd.startswith("machines"):
                    cli_machines()
                case _ if cmd.startswith("renegotiate"):
                    cli_renegotiate(cmd)
                case _ if cmd.startswith("force_send"):
                    cli_force_send(cmd)
                case _ if cmd.startswith("fsa"):
                    cli_fsa()
                case _ if cmd.startswith("whois"):
                    cli_whois(cmd)
                case _ if cmd.startswith("exit"):
                    cli_exit()
                case _:
                    continue
    except KeyboardInterrupt:
        cli_exit()

def scheduler():
    print(f"[SCHED] Scheduler Thread Started, Log Request Time is '{TIME_TO_REQUEST_LOGS}'")
    while True:
        ct = datetime.now()
        if ct.strftime('%H:%M:%S') == TIME_TO_REQUEST_LOGS:
            print(f"[SCHED] Requesting Logs Now '{ct.strftime('%H:%M:%S')}'")
            for id, info in list(client_machines_info.items()):
                _send_command_to_client(info, b'SendLogs')
        time.sleep(1)

def listen():
    print(f"[NETWORK] Listening @ {SERVER_HOST}:{SERVER_PORT}, RSA_KS: {CRYPTO_RSA_KEYSIZE}")

    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.bind((SERVER_HOST, SERVER_PORT))
    connection.listen(10)

    while True:
        print("[NETWORK] Waiting for connections...")
        sock, address = connection.accept()
        client_thread = threading.Thread(target=handle_client_request, args=(sock, address))
        client_thread.start()

def main_subroutine():
    sys.stdout.reconfigure(write_through=True)

    listener_thread = threading.Thread(target=listen, daemon=True)
    listener_thread.start()

    scheduler_thread = threading.Thread(target=scheduler, daemon=True)
    scheduler_thread.start()
    
    time.sleep(0.2)
    command_line_interface()

if __name__ == "__main__":
    main_subroutine()