import os
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import base64
import socket
import configparser

config = configparser.ConfigParser()
config.read("server_config.ini")

# Where this server should bind, defaults to 0.0.0.0:19385
SERVER_HOST = config['server']['host']
SERVER_PORT = int(config['server']['port'])

# Crypto settings, clients and servers must match
CRYPTO_RSA_KEYSIZE = int(config['crypto']['rsa_keysize'])
CRYPTO_AES_KEYSIZE = int(config['crypto']['aes_keysize'])

# Path of the server's keys.
PUB_PATH = os.path.join(os.getcwd(), "server_rsa_public_key.pem")
PRIV_PATH = os.path.join(os.getcwd(), "server_rsa_private_key.pem")

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


def load_or_generate_keys(keysize):
    pub_exists = os.path.exists(PUB_PATH) and os.path.getsize(PUB_PATH) > 0
    priv_exists = os.path.exists(PRIV_PATH) and os.path.getsize(PRIV_PATH) > 0

    if pub_exists and priv_exists:
        print(f"Loading RSA Keys...")
        with open(PUB_PATH, "rb") as f:
            rsa_public_key = RSA.import_key(f.read())
        with open(PRIV_PATH, "rb") as f:
            rsa_private_key = RSA.import_key(f.read())
        return rsa_public_key, rsa_private_key
    
    print("Generated new RSA keys")
    key = RSA.generate(keysize)
    rsa_private_key = key
    rsa_public_key = key.publickey()

    # write to disk
    with open(PUB_PATH, "wb") as f:
        f.write(rsa_public_key.export_key())
    with open(PRIV_PATH, "wb") as f:
        f.write(rsa_private_key.export_key())

    return rsa_public_key, rsa_private_key


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
    


rsa_public_key, rsa_private_key = load_or_generate_keys(CRYPTO_RSA_KEYSIZE)


print(f"RSA Private Key: {rsa_private_key}")
print(f"RSA Public Key: {rsa_public_key}")

def handle_client_request(connection: socket, address) -> bool:
    code = connection.recv(53)
    
    if code != b"ClientHandshakeBegin":
        print(f"Connection From {address} refused, incorrect opening bits '{code}")
        connection.close()
        return False
    
    print(f"Connection from {address} accepted")
    
    client_aes_key_enc_bytes = connection.recv(CRYPTO_AES_KEYSIZE)
    
    client_aes_key = rsa_decrypt(rsa_private_key, client_aes_key_enc_bytes)
    
    print(f"Client AES key: {client_aes_key}")
    

    # Now we expect the client to send a number of files
    logfile_count = int.from_bytes(connection.recv(28))
    
    print(f"Client sending {logfile_count} log files")
    
    compressed_logfiles = []
    
    #! PROBLEM: Server recv '0' from cli, although correctly enc-ed ??? wtf
    for i in range(0, logfile_count):
        clog_sz = int.from_bytes(connection.recv(28), "big")
        print(f"Log file {i+1} is {clog_sz} in size")
        pass
    connection.close()
    
def listen():
    print(f"Listening @ {SERVER_HOST}:{SERVER_PORT}, RSA_KS: {CRYPTO_RSA_KEYSIZE}")
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((SERVER_HOST, SERVER_PORT))
        sock.listen(1)
        print("Waiting for connections...")
        connection, address = sock.accept()
        handle_client_request(connection, address)
        

if __name__ == "__main__":
    try:
        listen()
    except:
        exit()
        
"""
    Auth Decisions
    RAW data will be hashed and that hash is used to generate a hash, the hash is appended to the raw data and it is all encrypted with aes256
    
"""

