import time
import gzip
import socket
import itertools
import os
import base64
import configparser
from dataclasses import dataclass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import pss
from pathlib import Path




config = configparser.ConfigParser()
config.read("client_config.ini")

# These are of the target server to connect to
SERVER_HOST = config['server']['host']
SERVER_PORT = int(config['server']['port'])

# Crypto settings, clients and servers must match
CRYPTO_RSA_KEYSIZE = int(config['crypto']['rsa_keysize'])
CRYPTO_AES_KEYSIZE = int(config['crypto']['aes_keysize'])

# Path of the client's keys and the public of the server (to facilitate the AES key securely from the server, while allowing ephemeral client keys.).
KEY_DIRECTORY = Path(config['crypto']['key_directory']).resolve()
SERVER_PUB_PATH = os.path.join(os.getcwd(), "server_rsa_public_key.pem")

# Self-explanatory really, IF it can read the file, it will send it.
TARGET_LOG_FILES_TO_SEND = [
    # Debian Logs
    "/var/log/syslog", 
    "/var/log/auth.log", 
    "/var/log/ufw.log", 
    "/var/log/dpkg.log",
    
    # UNIX / MacOS Logs
    "/var/log/system.log",
    "/var/log/wifi.log",
    "/var/log/fsck_apfs.log",
    "/var/log/fsck_hfs.log"
    ]

# Sizes for socket comms, server and client need to be the same
INTEGER_SIZE = 32
CHUNK_SIZE = 4096

# Ensure Key directory actually exists...
KEY_DIRECTORY.mkdir(parents=True, exist_ok=True)

@dataclass
class HandshakeResult:
    aes_key: bytes
    machine_id: str

# ------------------------------------------------------- #
# Key Management
# ------------------------------------------------------- #
def generate_rsa_keypair(bits=CRYPTO_RSA_KEYSIZE):
    """Generates an RSA Key. RSA Keys can be unlimited bits although typical values are 2048, 3072 and 4096 bits"""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def generate_aes_key(bits=CRYPTO_AES_KEYSIZE):
    """AES Keys can be 128, 192 or 256 bits."""
    return os.urandom(int(bits/8))

    
def get_rsa_keypair(keysize: int, key_directory: Path):
    """Loads or Generates an RSA Keypair"""
    key_dir = Path(key_directory).resolve()
    key_dir.mkdir(parents=True, exist_ok=True) 
    
    pub_path = key_dir /  f"client_{read_machine_id()}_rsa_public_key.pem"
    priv_path = key_dir / f"client_{read_machine_id()}_rsa_private_key.pem"

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

def load_rsa_key(filename: Path | str):
    """Import RSA key from (dot) PEM"""
    path = KEY_DIRECTORY / filename
    with open(path, "rb") as f:
        return RSA.import_key(f.read())
    
# ------------------------------------------------------- #
# AES-GCM 
# ------------------------------------------------------- #
def aes_encrypt(key, plaintext: bytes) -> dict[str, bytes]:
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
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
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

def generate_rsa_pss_signature(private_key_bytes, message: bytes) -> bytes:
    private_key = RSA.import_key(private_key_bytes)
    h = SHA512.new(message)
    signature = pss.new(private_key).sign(h)
    return signature

def verify_rsa_pss_signature(public_key_bytes, message: bytes, signature: bytes) -> bool:
    public_key = RSA.import_key(public_key_bytes)
    h = SHA512.new(message)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ------------------------------------------------------- #
# Log Stuff
# ------------------------------------------------------- 
def check_log_files(files: list[str]) -> list[str]:
    readable_files = []
    for f in files:
        if os.path.exists(f):
            try:
                with open(f, "r"):
                    readable_files.append(f)
            except Exception as e:
                print(f"[IO] Could not read log file {f}")
        else:
            print(f"[IO] Log file {f} does not exist")
    return readable_files

def _encode_and_compress(data: str) -> bytes:
    """Helper: base64 encode and gzip compress"""
    return gzip.compress(base64.b64encode(data.encode("UTF-8")))

def send_log(sock, aes_key, rsa_private_key, logfile_path):
    """Send a single log file (path + data)"""
    with open(logfile_path, "r") as f:
        # Send path
        send_aes_encrypted(sock, aes_key, _encode_and_compress(logfile_path), rsa_private_key)
        
        # Send data
        chunk_count = send_aes_encrypted(sock, aes_key, _encode_and_compress(f.read()), rsa_private_key)
        
        print(f"[NETWORK] Sent {logfile_path} in {chunk_count} chunks of size {CHUNK_SIZE}")

# ------------------------------------------------------- #
# Chunk Data
# ------------------------------------------------------- #

def send_chunked(sock: socket.socket, data: bytes) -> int:
    chunks = list(itertools.batched(bytes.__iter__(data), CHUNK_SIZE))
    sock.sendall(len(chunks).to_bytes(INTEGER_SIZE, 'big'))
    for idx, chunk in enumerate(chunks):
        send_int(sock, idx)
        send_int(sock, len(chunk))
        sock.sendall(bytes(chunk))
        
        scode = sock.recv(1)
        if scode == b'2':
            continue
        else:
            print("Interrupted from server, ACK did not match")
            print(f":{scode}")
            break
    return len(chunks)

# ------------------------------------------------------- #
# Helpers
# ------------------------------------------------------- #

def read_machine_id() -> str:
    with open("/etc/machine-id", "r") as f:
        return str(f.read().strip())

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


def send_int(sock: socket.socket, value: int, size: int = INTEGER_SIZE) -> None:
    sock.sendall(value.to_bytes(size, 'big'))
    
def _send_aes_blob(sock: socket.socket, encrypted_blob: dict, chunked: bool = True) -> int:
    """Helper to send AES encrypted blob (nonce + ciphertext + tag)"""
    send_int(sock, len(encrypted_blob["nonce"]))
    send_int(sock, len(encrypted_blob["ciphertext"]))
    send_int(sock, len(encrypted_blob["tag"]))
    
    payload = encrypted_blob["nonce"] + encrypted_blob["ciphertext"] + encrypted_blob["tag"]
    
    if chunked:
        return send_chunked(sock, payload)
    else:
        sock.sendall(payload)
        return 0

def send_aes_encrypted(sock: socket.socket, aes_key: bytes, data: bytes, rsa_private_key: RSA.RsaKey | None = None) -> int:
    """Send AES encrypted data with optional RSA signature (chunked)"""
    encrypted_data = aes_encrypt(aes_key, bytes(data))
    chunk_count = _send_aes_blob(sock, encrypted_data, chunked=True)
    
    if rsa_private_key is not None:
        signature = generate_rsa_pss_signature(rsa_private_key.export_key(), bytes(data))
        encrypted_sig = aes_encrypt(aes_key, signature)
        _send_aes_blob(sock, encrypted_sig, chunked=True)
    
    return chunk_count

def send_unchunked_aes_encrypted(sock: socket.socket, aes_key: bytes, data: bytes, rsa_private_key: RSA.RsaKey | None = None):
    """Send AES encrypted data with optional RSA signature (unchunked)"""
    encrypted_data = aes_encrypt(aes_key, bytes(data))
    _send_aes_blob(sock, encrypted_data, chunked=False)
    
    if rsa_private_key is not None:
        signature = generate_rsa_pss_signature(rsa_private_key.export_key(), bytes(data))
        encrypted_sig = aes_encrypt(aes_key, signature)
        _send_aes_blob(sock, encrypted_sig, chunked=True)  # Signature always chunked 

def persistent_connect(host, port, retry_delay=5):
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            print(f"[NETWORK] Connected to {host}:{port}")
            return sock
        except (ConnectionRefusedError, OSError) as e:
            print(f"[NETWORK] Connection failed ({e}), retrying in {retry_delay}s...")
            time.sleep(retry_delay)

# ------------------------------------------------------- #
# All pre-code authentication logic (Handshake)
# ------------------------------------------------------- #

def perform_handshake(sock: socket.socket, server_rsa_public_key: RSA.RsaKey) -> HandshakeResult:
    aes_key = generate_aes_key(CRYPTO_AES_KEYSIZE)
    print(f"[CRYPTO] AES Key is (HEX) 0x{aes_key.hex().upper()}")
    
    print(f"[NET/CRY] Sending AES key")
    client_aes_key_enc_bytes = rsa_encrypt(server_rsa_public_key, aes_key)
    sock.sendall(client_aes_key_enc_bytes)
    
    machine_id = read_machine_id()
    print(f"[NETWORK] Sending /etc/machine-id {machine_id}")
    send_unchunked_aes_encrypted(sock, aes_key, machine_id.encode("UTF-8"))
    
    print(f"[HANDSHAKE] Complete")
    
    return HandshakeResult(
        aes_key=aes_key,
        machine_id=machine_id
    )

# ------------------------------------------------------- #
# Main Subroutine
# ------------------------------------------------------- #

# A single send of the logs, generates a session-based AES key.
def send_logs(rsa_public_key, rsa_private_key, server_rsa_public_key):        
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))

    # ===== HANDSHAKE =====
    handshake = perform_handshake(sock, server_rsa_public_key)
    # =====================
    
    send_fixed_width(sock, b'SendLogsBegin', 30)
    print("[NETWORK] Operation: SendLogsBegin")
    
    log_files_to_send = check_log_files(TARGET_LOG_FILES_TO_SEND)
    print(f"[NETWORK] Sending {len(log_files_to_send)} log files")
    
    send_int(sock, len(log_files_to_send))
    for log_file_path in log_files_to_send:
        send_log(sock, handshake.aes_key, rsa_private_key, log_file_path)

def negotiate_reverse_connection(rsa_public_key, rsa_private_key, server_rsa_public_key):
    sock = persistent_connect(SERVER_HOST, SERVER_PORT)
    
    handshake = perform_handshake(sock, server_rsa_public_key)
    
    send_fixed_width(sock, b'NegotiateReverseConnection', 30)
    print("[NETWORK] Operation: NegotiateReverseConnection")
    
    reverse_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reverse_listener.bind(('0.0.0.0', 0))
    reverse_listener.listen(1)
    
    send_int(sock, reverse_listener.getsockname()[1])
    print(f"[REVERSE] Listening on port {reverse_listener.getsockname()[1]}")
    
    return reverse_listener

# Handles reverse listener connections from server
def handle_reverse_listener(connection, address, rsa_public_key, rsa_private_key, server_rsa_public_key):
    code = recv_fixed_width(connection, 30)
    
    if code == b'SendLogs':
        print("[REVERSE] Server requested logs")
        send_logs(rsa_public_key, rsa_private_key, server_rsa_public_key)
    elif code == b'RenegotiateConnection':
        print("[NETWORK] Server sent renegotiate message")
        connection.shutdown(socket.SHUT_WR)
        connection.close()
    else:
        print(f"[NETWORK] Reverse listener received unknown code '{code}'")
    
    return code

def main_subroutine():
    try:
        rsa_public_key, rsa_private_key = get_rsa_keypair(CRYPTO_RSA_KEYSIZE, KEY_DIRECTORY)
    except Exception as e:
        print(f"[CRYPTO] Error loading or generating client RSA keys, exiting.")
        print(f"[CRYPTO] {e}")
        exit()
        
    try:
        server_rsa_public_key = load_rsa_key("server_rsa_public_key.pem")        
    except:
        print(f"[CRYPTO] Could not load key 'server_rsa_public_key.pem' in directory '{KEY_DIRECTORY}', exiting.")
        exit()
    
    while True:
        connection = negotiate_reverse_connection(rsa_public_key, rsa_private_key, server_rsa_public_key)
        print("[NETWORK] Waiting for connections...")
        sock, address = connection.accept()
        code = handle_reverse_listener(sock, address, rsa_public_key, rsa_private_key, server_rsa_public_key)
        
        if code == b'RenegotiateConnection':
            break
        
if __name__ == "__main__":
    while True:
        try:
            main_subroutine()
        except Exception as e:
            print(f"[M/THREAD] Error while running client code, {e}")
            print("[M/THREAD] Restarting in 5s...")
            time.sleep(5)