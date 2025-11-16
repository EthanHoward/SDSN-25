import gzip
import socket
import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import base64
import configparser

config = configparser.ConfigParser()
config.read("client_config.ini")

# These are of the target server to connect to 
SERVER_HOST = config['server']['host']
SERVER_PORT = int(config['server']['port'])

# Crypto settings, clients and servers must match
CRYPTO_RSA_KEYSIZE = int(config['crypto']['rsa_keysize'])
CRYPTO_AES_KEYSIZE = int(config['crypto']['aes_keysize'])

# Path of the client's keys and the public of the server (to facilitate the AES key securely from the server, while allowing ephemeral client keys.).
SERVER_PUB_PATH = os.path.join(os.getcwd(), "server_rsa_public_key.pem")

TARGET_LOG_FILES_TO_SEND = ["/var/log/syslog", "/var/log/auth.log", "/var/log/ufw.log", "/var/log/dpkg.log"]

# ------------------------------------------------------- #
# Keygen
# ------------------------------------------------------- #
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def generate_aes_key(bits=256):
    return os.urandom(int(bits/8))


# Omitted 'load_or_generate_keys' due to being unused.


# ------------------------------------------------------- #
# AES-GCM 
# ------------------------------------------------------- #
def aes_encrypt(key, plaintext: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }


def aes_decrypt(key, encrypted_data: dict):
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ------------------------------------------------------- #
# RSA Encryption and Decryption
# ------------------------------------------------------- #
def rsa_encrypt(public_key, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def rsa_decrypt(private_key, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(data)


# ------------------------------------------------------- #
# RSA Signing
# ------------------------------------------------------- #
def generate_rsa_pss_signature(private_key_bytes, message: bytes) -> bytes:
    private_key = RSA.import_key(private_key_bytes)
    h = SHA256.new(message)
    signature = pss.new(private_key).sign(h)
    return signature

def verify_rsa_pss_signature(public_key_bytes, message: bytes, signature: bytes) -> bool:
    public_key = RSA.import_key(public_key_bytes)
    h = SHA256.new(message)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ------------------------------------------------------- #
# Log Collector
# ------------------------------------------------------- #

def collect_logs_to_gzip():
    compressed_logfiles = []
    for log in TARGET_LOG_FILES_TO_SEND:
        
        with open(log, "r") as f:
            data = f.read()
            gzipped = gzip.compress(data.encode("utf-8"))
            compressed_logfiles.append(gzipped)
            print(f"Collected and compressed logfile data from {log}, size {len(gzipped)}")
            
    return compressed_logfiles
    
# ------------------------------------------------------- #
# Main Subroutine
# ------------------------------------------------------- #

def main():
    # If we don't have a server key, the client clearly cannot function, so it exits.
    if not os.path.exists(SERVER_PUB_PATH):
        print("Could not load server key, exiting...")
        exit(1)

    with open(SERVER_PUB_PATH, "rb") as f:
        server_rsa_public_key = RSA.import_key(f.read())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))

    sock.sendall(b"ClientHandshakeBegin")

    # Now Encrypt client's rsa pubkey with server RSA pubkey and send it 
    # The tradeoff here is that we cannot be verified by the server, it simply cannot keep tabs on who is who and who is supposed to be sending logs, fortunately i will send a lot of metadata alongside the logs so that becomes a much smaller tradeoff

    aes_key = generate_aes_key(CRYPTO_AES_KEYSIZE)
    
    client_aes_key_enc_bytes = rsa_encrypt(server_rsa_public_key, aes_key)
    
    sock.sendall(client_aes_key_enc_bytes)
    
    compressed_logfiles = collect_logs_to_gzip()
    
    sock.sendall(len(compressed_logfiles).to_bytes())
    
    #! PROBLEM: Sending from here the logfile size is known but server recv '0' ???
    for clog in compressed_logfiles:
        print(f"Sending logfile data, size is {len(clog)}")
        sock.sendall(len(clog).to_bytes(256, "big"))
    
    exit(0)
    
if __name__ == "__main__":
    main()
    
#!TODO: Add a feature so admins can force-send logs from the serverside so probably add another subroutine here where this has a threaded socket listening on a given port, which the server can then connect to on a KeepAlive basis and send control commands, even its easier because that can send all metas in the futurea.