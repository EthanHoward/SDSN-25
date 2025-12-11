#!./bin/python3
import os
import sys
import gzip
import time
import json
import base64
import pickle
import socket
import threading
import configparser
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pss
from Crypto.Cipher import AES, PKCS1_OAEP

config = configparser.ConfigParser()
config.read("server_config.ini")

# Where this server should bind, default is meant to be 0.0.0.0:19385
SERVER_HOST = config['server']['host']
SERVER_PORT = int(config['server']['port'])
LOG_SAVE_PATH = config['server']['log_save_path']
TIME_TO_REQUEST_LOGS = config['server']['time_to_request_logs']
SECURITY_LOG_PATH = config['server']['security_log_path']

# Crypto settings, clients and servers must match.
CRYPTO_RSA_KEYSIZE = int(config['crypto']['rsa_keysize'])
CRYPTO_AES_KEYSIZE = int(config['crypto']['aes_keysize'])

# Path of the server's keys.
KEY_DIRECTORY = Path(config['crypto']['key_directory']).resolve()

# ABSOLUTE Path to logstore AES 256 key
LOGSTORE_KEY_FILE = Path(config['crypto']['logstore_key_file'])

# Sizes for socket comms, server and client need to be the same size
INTEGER_SIZE = 32
CHUNK_SIZE = 4096

# Stores connected machines info
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
    client_rsa_public_key: RsaKey | None

# --------------------------------------------------------------------------- #
# Security Logging
# --------------------------------------------------------------------------- #

def get_current_log():
    ct = datetime.now()
    ct_y = ct.year
    ct_m = ct.month
    ct_d = ct.day
    ct_h = ct.hour
    
    cfg_security_log_path = Path(SECURITY_LOG_PATH).resolve()

    cfg_security_log_path.mkdir(parents=True, exist_ok=True)
    
    full_path = cfg_security_log_path / f"{ct_y}-{ct_m}-{ct_d}-{ct_h}-securitylog.log"
    
    return open(full_path, "a+")

def security_log(msg: str):
    """Replaces standard print, prints the given string and adds it to the security log"""
    
    log = f"{datetime.now().strftime("[%d/%m/%Y, %H:%M:%S]")}{msg}"
    print(log)
    
    with get_current_log() as f:
        f.write(f"{log}\n")
        f.close()
        
def perf_log(dt_start: datetime, dt_end: datetime, msg: str):
    """For logging info of a given process and the time it takes to complete"""
    
    log = f"{datetime.now().strftime("[%d/%m/%Y, %H:%M:%S]")}[PERFLOG] {msg} took {(dt_end-dt_start).total_seconds()} seconds"
    print(log)
    
    with get_current_log() as f:
        f.write(f"{log}\n")
        f.close()

# --------------------------------------------------------------------------- #
# Key Management
# --------------------------------------------------------------------------- #


def generate_rsa_keypair(bits=CRYPTO_RSA_KEYSIZE):
    """Generates an RSA Key. RSA Keys can be unlimited bits although typical values are 2048, 3072 and 4096 bits"""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def generate_aes_key(bits=CRYPTO_AES_KEYSIZE):
    """AES Keys can be 128, 192 or 256 bits. (os.urandom runs on bytes, hence the division by 8)"""
    return os.urandom(int(bits/8))


def get_logstore_key(bits=CRYPTO_AES_KEYSIZE):
    """Loads or Generates the key used for Encryption-At-Rest of logs"""
    key_path = LOGSTORE_KEY_FILE.resolve()
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # If it exists and is the correct size, use it.
    if key_path.exists() and key_path.stat().st_size == bits/8:
        with open(key_path, "rb") as f:
            return f.read()

    key = generate_aes_key()

    # Save AES Key to disk
    with open(key_path, "wb") as f:
        f.write(key)

    # Set Perms to 600 / -rw------- (Will silently error if it fails or is on Windows - which it shouldn't be on)
    try:
        os.chmod(key_path, 0o600)
    except PermissionError:
        pass

    return key


def get_rsa_keypair(keysize: int, key_directory: Path):
    """Loads or Generates an RSA Keypair"""
    key_dir = Path(key_directory).resolve()
    key_dir.mkdir(parents=True, exist_ok=True)

    pub_path = key_dir / "server_rsa_public_key.pem"
    priv_path = key_dir / "server_rsa_private_key.pem"

    pub_exists = pub_path.exists() and pub_path.stat().st_size > 0
    priv_exists = priv_path.exists() and priv_path.stat().st_size > 0

    if pub_exists and priv_exists:
        security_log("[CRYPTO] Loading RSA Keys...")
        rsa_public_key = load_rsa_key(pub_path)
        rsa_private_key = load_rsa_key(priv_path)
        return rsa_public_key, rsa_private_key

    security_log("[CRYPTO] Generating new RSA keys...")
    rsa_private_key = RSA.generate(keysize)
    rsa_public_key = rsa_private_key.publickey()

    # write to disk
    with open(pub_path, "wb") as f:
        f.write(rsa_public_key.export_key())
    with open(priv_path, "wb") as f:
        f.write(rsa_private_key.export_key())

    return rsa_public_key, rsa_private_key

def regenerate_rsa_keys(keysize: int = CRYPTO_RSA_KEYSIZE, key_directory: Path = KEY_DIRECTORY):
    old_puk = rsa_public_key
    old_prk = rsa_private_key
    
    key_dir = Path(key_directory).resolve()
    key_dir.mkdir(parents=True, exist_ok=True)

    pub_path = key_dir / "server_rsa_public_key.pem"
    priv_path = key_dir / "server_rsa_private_key.pem"

    pub_exists = pub_path.exists() and pub_path.stat().st_size > 0
    priv_exists = priv_path.exists() and priv_path.stat().st_size > 0

    if pub_exists:
        security_log(f"[CRYPTO] Removed OLD RSA key from disk {pub_path}")
        os.remove(pub_path)
        
    if priv_exists:
        security_log(f"[CRYPTO] Removed OLD RSA key from disk {priv_path}")
        os.remove(priv_path)
        
    new_puk, new_prk = get_rsa_keypair(keysize, key_directory)

    return old_puk, old_prk, new_puk, new_prk

def load_rsa_key(filename: Path | str):
    """Import RSA key from (dot) PEM"""
    path = KEY_DIRECTORY / filename
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

# --------------------------------------------------------------------------- #
# AES-GCM - Advanced Encryption Standard Galois/Counter Mode
# --------------------------------------------------------------------------- #


def aes_encrypt(key, plaintext: bytes):
    """Encrypt the given data with AES"""
    ct_start = datetime.now()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    enc_obj = {
        "nonce": base64.b64encode(cipher.nonce),
        "ciphertext": base64.b64encode(ciphertext),
        "tag": base64.b64encode(tag)
    }

    ct_done = datetime.now()
    perf_log(ct_start, ct_done, f"AES Encryption of data size {len(plaintext)} bytes with keysize {CRYPTO_AES_KEYSIZE}")

    return enc_obj

def aes_decrypt(key, encrypted_data: dict):
    """Decrypt AES-Encrypted data"""
    ct_start = datetime.now()
    
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])

    cipher = AES.new(key, AES.MODE_GCM, nonce)
    decver_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    ct_done = datetime.now()
    
    perf_log(ct_start, ct_done, f"AES Decryption of data size {len(nonce) + len(ciphertext) + len(tag)} bytes with keysize {CRYPTO_AES_KEYSIZE}")
    
    return decver_bytes


# --------------------------------------------------------------------------- #
# RSA - Rivest-Shamir-Adleman cryptosystem
# --------------------------------------------------------------------------- #


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Encrypt given data with RSA"""
    ct_start = datetime.now()
    cipher = PKCS1_OAEP.new(public_key)
    enc_bytes =  cipher.encrypt(data)
    ct_done = datetime.now()
    
    perf_log(ct_start, ct_done, f"RSA Encryption of data size {len(data)} bytes with keysize {CRYPTO_RSA_KEYSIZE}")
    
    return enc_bytes


def rsa_decrypt(private_key, data: bytes) -> bytes:
    """Decrypt RSA-Encrypted data"""
    ct_start = datetime.now()
    cipher = PKCS1_OAEP.new(private_key)
    dec_bytes = cipher.decrypt(data)
    ct_done = datetime.now()
    
    perf_log(ct_start, ct_done, f"RSA Decryption of data size {len(data)} bytes with keysize {CRYPTO_RSA_KEYSIZE}")
    
    return dec_bytes


def generate_rsa_pss_signature(rsa_private_key: RsaKey, message: bytes) -> bytes:
    """Generates an RSA PSS signature"""
    h = SHA512.new(message)
    signature = pss.new(rsa_private_key).sign(h) # type: ignore
    return signature


def verify_rsa_pss_signature(rsa_public_key: RsaKey, message: bytes, signature: bytes) -> bool:
    """Verifies an RSA PSS signature"""
    h = SHA512.new(message)
    try:
        pss.new(rsa_public_key).verify(h, signature) # type: ignore
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
    dec_pth, lench_pth = recv_aes_encrypted(
        connection, aes_key, client_rsa_public_key)
    dec_log, lench_log = recv_aes_encrypted(
        connection, aes_key, client_rsa_public_key)

    log_path = _decompress_and_decode(dec_pth)
    log_data = _decompress_and_decode(dec_log)

    security_log(
        f"[NETWORK] Recv log {log_path} ({lench_pth}) with chunks {lench_log}")
    return log_path, log_data


def save_log(machine_id, log_path, log_data) -> None:
    """Saves a given log file (string data) to disk"""
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
        raise ValueError(
            f"Unsafe log path provided (Path Traversal) {cfg_logpath} not in '{full_path}'")

    full_path.parent.mkdir(parents=True, exist_ok=True)

    with open(full_path, "w") as f:
        security_log(f"[FS] Saving log to {full_path}")
        f.write(log_data)
    
    
    aes_encrypt_file(full_path)


def aes_encrypt_file(filepath: Path, key=get_logstore_key()):
    """AES Encrypts the provided plaintext file, deletes it and writes an encrypted AES file and a SHA signature file"""
    fp_exists = filepath.exists() and filepath.stat().st_size > 0
    
    if not fp_exists:
        return False
    
    data = open(filepath, "r").read().encode("UTF-8")

    data_aes_enc: dict[str, bytes] = aes_encrypt(key, data)

    # Write the encrypted data to a .aes file for now.
    with open(f"{filepath}.aes", "wb") as f:
        security_log(f"[FS/AES] Saving file aes to {filepath}.aes")
        pickle.dump(data_aes_enc, f)

    with open(f"{filepath}.sha", "wb") as f:
        security_log(f"[FS/AES] Saving file sha to {filepath}.sha")
        f.write(SHA512.new(data).digest())
    
    # Delete original, keep encrypted ones
    os.remove(filepath)
    
    
def aes_decrypt_file(filepath_aes: Path, filepath_sha: Path, key=get_logstore_key()):
    """Decrypts the provided AES file and uses the corresponding (if existing) SHA file to verify it"""
    fp_aes_exists = filepath_aes.exists() and filepath_aes.stat().st_size > 0
    fp_sha_exists = filepath_sha.exists() and filepath_sha.stat().st_size > 0
    
    if not fp_aes_exists or not fp_sha_exists:
        security_log(f"[FS/AES] AES or SHA file does not exist... aes: {filepath_aes} sha: {filepath_sha}")
        return False
    
    if not str(filepath_aes).endswith(".aes") or not str(filepath_sha).endswith(".sha"):
        return False
    
    with open(filepath_aes, "rb") as f:
        aes_enc_data: dict[str, bytes] = pickle.load(f)
    
    with open(filepath_sha, "rb") as f:
        sha_stored_digest = f.read()
    
    data = aes_decrypt(key, aes_enc_data)
    
    sha_data_digest = SHA512.new(data).digest()
    
    if sha_data_digest != sha_stored_digest:
        return
    
    with open(filepath_aes.with_suffix(''), "w") as f:
        f.write(data.decode("UTF-8"))
        
    os.remove(filepath_aes)
    os.remove(filepath_sha)
        
    

def get_all_log_files(parent_folder=LOG_SAVE_PATH) -> list[Path]:
    file_paths = []
    
    for root, dirs, files in os.walk(parent_folder):
        for f in files:
            fp = Path(os.path.join(root, f))
            file_paths.append(fp.resolve())
            
    return file_paths


def get_all_encrypted_log_files() -> dict[Path, Path]:
    """Gets pairs of '.aes' and their corresponding '.sha' files from get_all_log_files()'s results"""
    all_files: list[Path] = get_all_log_files()
    
    pairs = {}
    
    for f in all_files:
        if f.name.endswith(".aes"):
            for sf in all_files:
                if sf.stem == f.stem  and sf.name.endswith(".sha"):
                    pairs[f] = sf
            
        
        if f.name.endswith(".sha"):
            for af in all_files:
                if af.stem == f.stem and af.name.endswith(".aes"):
                    pairs[af] = f
    
    security_log(f"[FS] {len(pairs.keys())} encrypted log pairs")
    
    return pairs


def get_all_raw_log_files() -> list[Path]:
    files: list[Path] = get_all_log_files()
    
    raw_logs: list[Path] = []
    for f in files:
        if not f.name.endswith(".aes") and not f.name.endswith(".sha"):
            raw_logs.append(f.resolve())
            
    security_log(f"[FS] {len(raw_logs)} raw logfiles")
    
    return raw_logs


# ------------------------------------------------------ #
# Chunk Data Recv
# ------------------------------------------------------ #


def recv_exact(sock, n):
    """Receives an exact amount (`n`) of data (`bytes`) from a socket"""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionResetError(
                "Connection closed while receiving chunk")
        data += chunk
    return data


def recv_chunked(connection: socket.socket):
    """Receives a set of data sent in chunks and reconstructs it. Does not have order-assurance but should due to TCP socket"""
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


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def recv_int(connection: socket.socket, size: int = INTEGER_SIZE) -> int:
    """Receive a big-endian integer of fixed byte width from a socket."""
    return int.from_bytes(connection.recv(size), 'big')


def send_int(connection: socket.socket, value: int, size: int = INTEGER_SIZE) -> None:
    """Send an integer in big-endian format using fixed-width byte encoding."""
    connection.sendall(value.to_bytes(size, 'big'))


def recv_fixed_width(sock: socket.socket, width: int) -> bytes:
    """Receive a fixed-width, NUL-padded byte field and strip trailing padding."""
    buf = b''
    while len(buf) < width:
        chunk = sock.recv(width - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed during fixed-width receive")
        buf += chunk
    return buf.rstrip(b'\x00')


def send_fixed_width(sock: socket.socket, data: bytes, width: int):
    """Send a fixed-width, NUL-padded byte field. Raises ValueError if data exceeds width."""
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


def recv_aes_encrypted(connection, aes_key, client_rsa_public_key: RsaKey | None = None):
    """Receive AES encrypted data with optional RSA signature (chunked)"""
    data_dec_bytes, data_lenchunks = _recv_aes_blob(
        connection, aes_key, chunked=True)

    if client_rsa_public_key is not None:
        sign_dec_bytes, _ = _recv_aes_blob(connection, aes_key, chunked=True)

        if not verify_rsa_pss_signature(client_rsa_public_key, data_dec_bytes, sign_dec_bytes):
            raise Exception("Sign Verification Failed")

    return data_dec_bytes, data_lenchunks


def recv_unchunked_aes_encrypted(connection, aes_key, client_rsa_public_key: RsaKey | None = None):
    """Receive AES encrypted data with optional RSA signature (unchunked)"""
    data_dec_bytes, _ = _recv_aes_blob(connection, aes_key, chunked=False)

    if client_rsa_public_key is not None:
        sign_dec_bytes, _ = _recv_aes_blob(
            connection, aes_key, chunked=True)  # Signature always chunked

        if not verify_rsa_pss_signature(client_rsa_public_key, data_dec_bytes, sign_dec_bytes):
            raise Exception("Sign Verification Failed")

    return data_dec_bytes


def refresh_server_keys():
    global rsa_public_key
    global rsa_private_key
    global old_rsa_public_key
    global old_rsa_private_key
    
    old_rsa_public_key, old_rsa_private_key, rsa_public_key, rsa_private_key = regenerate_rsa_keys()
    
    for id, info in list(client_machines_info.items()):
        if info is not None:
            _send_command_to_client(info, b"RefreshServerRSA")


def refresh_all_client_keys():
    for id, info in list(client_machines_info.items()):
        if info is not None:
            _send_command_to_client(info, b'RefreshRSAKeys')


# --------------------------------------------------------------------------- #
# All pre-code authentication logic (Handshake)
# --------------------------------------------------------------------------- #


def perform_handshake(connection: socket.socket) -> HandshakeResult:
    """Perform the initial cryptographic handshake:
    decrypt AES session key, receive machine ID, and load the client's RSA public key."""

    client_aes_key_enc_bytes = connection.recv(CRYPTO_AES_KEYSIZE)
    
    client_aes_key = None
    
    try:
        client_aes_key = rsa_decrypt(rsa_private_key, client_aes_key_enc_bytes)
    except Exception:
        security_log(f"[SECVIO] Failed to decrypt client aes session key, client must be unauthorised or using the wrong server key")
        pass

    
    if client_aes_key is None and old_rsa_private_key is not None:
        try:
            client_aes_key = rsa_decrypt(old_rsa_private_key, client_aes_key_enc_bytes)
        except Exception:
            pass
        
    if client_aes_key is None:
        raise Exception("Client AES Key could not be attained")
        
    security_log(f"[CRYPTO] Client AES key (HEX): 0x{client_aes_key.hex().upper()}")

    # Receive machine_id
    try:
        machine_id = recv_unchunked_aes_encrypted(connection, client_aes_key).decode("UTF-8")
    except Exception as e:
        security_log(f"[HANDSHAKE] Failed decrypting machineID")
        raise Exception("MachineID Decryption Failed... AES Key is likely incorrect")
    
    security_log(f"[NETWORK] Recv MachineID {machine_id}")

    # Load client's pre-shared RSA public key
    try:
        client_rsa_public_key = load_rsa_key(
            f"client_{machine_id}_rsa_public_key.pem")
    except Exception as e:
        security_log("[SECVIO] Client key could not be found, client is disallowed")
        raise Exception("Client key could not be found")

    security_log(f"[HANDSHAKE] Complete for {machine_id}")

    return HandshakeResult(
        machine_id=machine_id,
        aes_key=client_aes_key,
        client_rsa_public_key=client_rsa_public_key
    )

# --------------------------------------------------------------------------- #
# Main Subroutine
# --------------------------------------------------------------------------- #


rsa_public_key, rsa_private_key = get_rsa_keypair(CRYPTO_RSA_KEYSIZE, KEY_DIRECTORY)

# Used for Server Key Rotation Logic
old_rsa_public_key, old_rsa_private_key = None, None

security_log(f"[CRYPTO] Loaded {rsa_private_key}")
security_log(f"[CRYPTO] Loaded {rsa_public_key}")


def handle_client_request(connection: socket.socket, address):
    """Handle a fully authenticated client request after handshake, routing based on operation code."""

    global rsa_public_key
    global rsa_private_key
    global old_rsa_public_key
    global old_rsa_private_key
    

    security_log(f"[NETWORK] Connection from {address} accepted")

    try:
        handshake = perform_handshake(connection)
    except Exception as e:
        security_log(f"[HANDSHAKE] Failed: {e}")
        connection.shutdown(socket.SHUT_WR)
        connection.close()
        return

    
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
        security_log(f"[NETWORK] Client sending {logfile_count} log files")
        try:
            for i in range(logfile_count):
                log_path, log_data = recv_log(
                    connection,
                    handshake.aes_key,
                    handshake.client_rsa_public_key
                )
                save_log(handshake.machine_id, log_path, log_data)
        except Exception as e:
            security_log(f"[CRYPTO] Client {handshake.machine_id} error: {e}")
        finally:
            connection.shutdown(socket.SHUT_WR)
            connection.close()
        return
    
    
    if code == b'RequestNewRSAKey':
        pem = rsa_public_key.export_key()
        security_log(f"[CRYPTO] Sending PEM of new RSA Public Key, Length is {len(pem)}")
        
        send_int(connection, len(pem))
        connection.sendall(pem)
        
        return        
        
    if code == b'RefreshClientRSAKeys':
        data, chunks = recv_chunked(connection)

        new_client_public_key = RSA.import_key(data)

        with open(KEY_DIRECTORY / f"client_{handshake.machine_id}_rsa_public_key.pem", "rb+") as f:
            f.write(new_client_public_key.export_key())
        return

    connection.shutdown(socket.SHUT_WR)
    connection.close()

# --------------------------------------------------------------------------- #
# CLI Commands
# --------------------------------------------------------------------------- #


def cli_machines():
    """Print a formatted table of all known client machines and their last negotiated reverse ports."""
    security_log(
        f"[CLI] | {"machine-id".ljust(32, ' ')} | {"IP".ljust(15, ' ')} | {"PORT".ljust(5, ' ')} |")
    security_log(
        f"[CLI] +-{"".ljust(32, '-')}-+-{"".ljust(15, '-')}-+-{"".ljust(5, '-')}-+")
    for id, info in list(client_machines_info.items()):
        if id is None or info is None:
            return
        
        security_log(
            f"[CLI] | {str(info.id).ljust(32, ' ')} | {str(info.ip).ljust(15, ' ')} | {str(info.port).ljust(5, ' ')} |")


def _find_client(machine_id: str) -> ClientInfo | None:
    """Look up a client by machine ID in the active reverse-connection registry."""
    for id, info in list(client_machines_info.items()):
        if id == machine_id:
            return info
    return None


def _send_command_to_client(client: ClientInfo, command: bytes):
    """Directly connect to a client's reverse listener and send a fixed-width command."""
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((client.ip, client.port))
        send_fixed_width(connection, command, 30)
        client_machines_info[client.id] = None
    except Exception:
        security_log(f"[ECONN] Could not connect to client {client.id} via {client.ip}:{client.port}")
        return


def cli_renegotiate(cmd):
    """CLI: Request the server to instruct a client to renegotiate its connection."""
    cmd_parts = cmd.strip().split(" ")
    if len(cmd_parts) != 2:
        security_log("[CLI] Usage: renegotiate <machine-id>")
        return

    client = _find_client(cmd_parts[1])
    if not client:
        security_log(f"[CLI] Client '{cmd_parts[1]}' not found")
        return

    security_log(
        f"[NETWORK] Connecting to client {client.id} via {client.ip}:{client.port}")
    _send_command_to_client(client, b'RenegotiateConnection')


def cli_force_send(cmd):
    """CLI: Force a specific client to immediately send its logs to the server."""
    cmd_parts = cmd.strip().split(" ")
    if len(cmd_parts) != 2:
        security_log("[CLI] Usage: force_send <machine-id>")
        return

    client = _find_client(cmd_parts[1])
    if not client:
        security_log(f"[CLI] Client '{cmd_parts[1]}' not found")
        return

    security_log(
        f"[NETWORK] Sending log request to {client.id} via {client.ip}:{client.port}")
    _send_command_to_client(client, b'SendLogs')


def cli_fsa():
    """CLI: Force-send logs for all currently registered clients."""
    for id, _ in list(client_machines_info.items()):
        cli_force_send(f"force_send {id}")


def cli_whois(cmd):
    """CLI: Given an IP address, display the associated machine ID if known."""
    cmd_parts = cmd.strip().split(" ")
    if len(cmd_parts) != 2:
        security_log("[CLI] Usage: whois <ip>")
        return

    ip = cmd_parts[1]
    for id, info in list(client_machines_info.items()):
        if id is None or info is None:
            return
        
        if info.ip == ip:
            security_log(
                f"[CLI] | {"machine-id".ljust(32, ' ')} | {"IP".ljust(15, ' ')} | {"PORT".ljust(5, ' ')} |")
            security_log(
                f"[CLI] +-{"".ljust(32, '-')}-+-{"".ljust(15, '-')}-+-{"".ljust(5, '-')}-+")
            security_log(
                f"[CLI] | {str(info.id).ljust(32, ' ')} | {str(info.ip).ljust(15, ' ')} | {str(info.port).ljust(5, ' ')} |")
            return
    security_log("[CLI] No machine found with that IP")

def cli_dec_logs():
    log_pairs: dict[Path, Path] = get_all_encrypted_log_files()
    for k in log_pairs.keys():
        v = log_pairs[k]
        security_log(f"[LOG/DEC] A: {k} S: {v}")
        aes_decrypt_file(k, v)
        
def cli_enc_logs():
    raw_logs: list[Path] = get_all_raw_log_files()
    for f in raw_logs:
        security_log("[LOG/ENC]")
        aes_encrypt_file(f)
    

def cli_exit():
    for id, info in list(client_machines_info.items()):
        cli_renegotiate(f"renegotiate {id}")
    security_log("[SERVER] Shutting Down")
    exit()


def command_line_interface():
    try:
        security_log("[CLI] Input '?' or 'help' to list commands")
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
                    print("[CLI] 'dec_logs' - Decrypts all logs with the logstore key, for reading them")
                    print("[CLI] 'enc_logs' - Encrypts all logs with the logstore key, for securing them")
                    print("[CLI] 'refresh_server_keys' ")
                    print("[CLI] 'refresh_client_keys' ")
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
                case _ if cmd.startswith("dec_logs"):
                    cli_dec_logs()
                case _ if cmd.startswith("enc_logs"):
                    cli_enc_logs()
                case _ if cmd.startswith("refresh_server_keys"):
                    refresh_server_keys()
                case _ if cmd.startswith("refresh_client_keys"):
                    refresh_all_client_keys()
                case _ if cmd.startswith("exit"):
                    cli_exit()
                case _:
                    continue
    except KeyboardInterrupt:
        cli_exit()


def scheduler():
    """Scheduler currently manages checking for the time to log"""
    security_log(
        f"[SCHED] Scheduler Thread Started, Log Request Time is '{TIME_TO_REQUEST_LOGS}'")
    while True:
        ct = datetime.now()
        if ct.strftime('%H:%M:%S') == TIME_TO_REQUEST_LOGS:
            security_log(f"[SCHED] Requesting Logs Now '{ct.strftime('%H:%M:%S')}'")
            for id, info in list(client_machines_info.items()):
                _send_command_to_client(info, b'SendLogs')
        time.sleep(1)


def listen():
    "Main listener function, handles the main socket listener for clients to talk via"
    security_log(
        f"[NETWORK] Listening @ {SERVER_HOST}:{SERVER_PORT}, RSA_KS: {CRYPTO_RSA_KEYSIZE}")

    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.bind((SERVER_HOST, SERVER_PORT))
    connection.listen(10)

    while True:
        security_log("[NETWORK] Waiting for connections...")
        sock, address = connection.accept()
        client_thread = threading.Thread(
            target=handle_client_request, args=(sock, address))
        client_thread.start()


def main_subroutine():
    sys.stdout.reconfigure(write_through=True) # type: ignore

    listener_thread = threading.Thread(target=listen, daemon=True)
    listener_thread.start()

    scheduler_thread = threading.Thread(target=scheduler, daemon=True)
    scheduler_thread.start()

    time.sleep(0.2)
    command_line_interface()


if __name__ == "__main__":
    main_subroutine()
