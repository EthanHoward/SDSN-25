import socket
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes


client_private_key_name = '1761910596.378423_client_key_private.pem'
server_public_key_name = '1761910596.378423_server_key_public.pem'

# Sign the file with the client's private key
def sign_file(private_key, file_data):
	hash_obj = SHA256.new(file_data)
	signer = PKCS1_v1_5.new(private_key)
	signature = signer.sign(hash_obj)
	return signature

# Encrypt the AES key with RSA (server's public key)
def encrypt_aes_key(public_key, aes_key):
	cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
	encrypted_key = cipher_rsa.encrypt(aes_key)
	return encrypted_key

# Encrypt the file with AES
def encrypt_file_aes(aes_key, file_data):
	cipher_aes = AES.new(aes_key, AES.MODE_GCM)  # GCM uses a nonce
	ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
	return ciphertext, tag, cipher_aes.nonce

def start_client():
	# Load the client's private key to sign the file
	with open(client_private_key_name, "rb") as key_file:
		client_private_key = RSA.import_key(key_file.read())

	# Load the server's public key to encrypt the AES key
	with open(server_public_key_name, "rb") as key_file:
		server_public_key = RSA.import_key(key_file.read())

	# Read the file to send
	with open("plain-text.txt", "rb") as f:
		file_data = f.read()

	# Sign the file
	signature = sign_file(client_private_key, file_data)
	print("...................................")
	print("File signed successfully. and Signature is:", (signature) )
	print("...................................")

	# Generate a random AES key for symmetric encryption
	aes_key = get_random_bytes(16)  # AES-128
	print("...................................")
	print("AES key generated:",(aes_key))
	print("...................................")

	# Encrypt the file with AES
	encrypted_file_data, tag, nonce = encrypt_file_aes(aes_key, file_data)
	print("File encrypted with AES successfully.")

	# Encrypt the AES key with RSA (server's public key)
	encrypted_aes_key = encrypt_aes_key(server_public_key, aes_key)
	print("...................................")
	print("So the AES key is:", (aes_key))
	print("...................................")
	print("...................................")
	print("AES key encrypted with RSA:",(encrypted_aes_key))
	print("...................................")

    
#-------------------------------------------------------------------------
# Create a socket and connect to the server
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client_socket.connect(('127.0.0.1', 12345))  # Replace '127.0.0.1' with server IP when connected remotely

# Send the encrypted AES key
	client_socket.sendall(encrypted_aes_key)
	print("Encrypted AES key sent.")

# Send the length of the encrypted file data (for proper chunk receiving on server-side)
	client_socket.sendall(len(encrypted_file_data).to_bytes(4, byteorder='big'))

# Send the encrypted file data
	client_socket.sendall(encrypted_file_data)
	print("...................................")
	print("Encrypted file sent:",(encrypted_file_data))
	print("...................................")

# Send the tag, nonce, and digital signature for verification
	client_socket.send(tag)
	client_socket.send(nonce)  # Nonce is 16 bytes for AES-GCM
	client_socket.send(signature)
	print("...................................")
	print("Tag:", (tag))
	print("...................................")
	print("Nonce:", (nonce))
	print("...................................")
	print("Signature:", (signature))
	print("...................................")

	client_socket.close()

if __name__ == "__main__":
    start_client()


"""
	Code Flow:
 
	Load Key CLIENT PRIVATE
	Load Key SERVER PUBLIC
 
	Load Data plain-text.txt
 
	Sign File:
		SHA256(file)
		new PKCS1v1.5(CLIENT PRIVATE)
		Sign with sha256 hash of file

	Generate Random AES Key 
 
	Encrypt File AES:
		CIPHER generate using AES key
		CIPHERTEXT and TAG generate using CIPHER and DATA
  
	Encrypt AES Key:
		Generate RSA Cipher
		Encrypt Key
  
	Open Socket @ 127.0.0.1
 
	Sendall Encrypted AES Key
	
	Sendall len(data)
 
	Sendall encrypted data
 
	Sendall:-
		Tag
		Nonce
		Digital Signature
  
	END
	
"""