import socket
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

server_private_key_name = '1761910596.378423_server_key_private.pem'
client_public_key_name = '1761910596.378423_client_key_public.pem'

# Decrypt the AES key with the server's private RSA key
def decrypt_aes_key(private_key, encrypted_aes_key):
	cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
	aes_key = cipher_rsa.decrypt(encrypted_aes_key)
	return aes_key

# Decrypt the file using AES
def decrypt_file_aes(aes_key, encrypted_file_data, tag, nonce):
	cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
	decrypted_file_data = cipher_aes.decrypt_and_verify(encrypted_file_data, tag)
	return decrypted_file_data

# Verify the signature with the client's public key
def verify_signature(public_key, file_data, signature):
	hash_obj = SHA256.new(file_data)
	verifier = PKCS1_v1_5.new(public_key)
	return verifier.verify(hash_obj, signature)

def start_server():
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.bind(('127.0.0.1', 12345))  # Bind to any interface
	server_socket.listen(1)
	print("Server is listening on port 12345...")

	conn, addr = server_socket.accept()
	print("Connection from", (addr))

	# Receive the encrypted AES key
	encrypted_aes_key = conn.recv(256)  # RSA-encrypted AES key
	print("...................................")
	print("Encrypted AES key received.", (encrypted_aes_key))
	print("...................................")

# Receive the length of the encrypted file data
	file_size = int.from_bytes(conn.recv(4), byteorder='big')

	# Receive the encrypted file data
	encrypted_file_data = b''
	while len(encrypted_file_data) < file_size:
		encrypted_file_data += conn.recv(file_size - len(encrypted_file_data))
	print("...................................")
	print("Encrypted file data received:", (encrypted_file_data))
	print("...................................")
 
	with open('encrypted.bin', 'wb') as f:
		f.write(encrypted_file_data)

# Receive the AES tag, nonce, and signature
	tag = conn.recv(16)  # AES-GCM tag
	nonce = conn.recv(16)  # AES-GCM nonce (must be 16 bytes)
	signature = conn.recv(256)  # RSA signature
	print("...................................")
	print("Tag:", (tag))
	print("Nonce:", (nonce))
	print("Signature received.", (signature))
	print("...................................")

	# Load the server's private key to decrypt the AES key
	with open(server_private_key_name, "rb") as key_file:
		server_private_key = RSA.import_key(key_file.read())

	# Decrypt the AES key
	aes_key = decrypt_aes_key(server_private_key, encrypted_aes_key)
	print("...................................")
	print("AES key decrypted.", (aes_key))
	print("...................................")

	# Decrypt the file using the decrypted AES key
	try:
		decrypted_file_data = decrypt_file_aes(aes_key, encrypted_file_data, tag, nonce)
		print("...................................")
		print("File decrypted successfully.", (decrypted_file_data))
		print("...................................")
	except ValueError as e:
		print("Decryption failed: {e}", (e))
		conn.close()
		return

	# Save the decrypted file
	with open("received_file.txt", "wb") as f:
		f.write(decrypted_file_data)
	print("File saved as 'received_file.txt'.")

	# Load the client's public key to verify the signature
	with open(client_public_key_name, "rb") as key_file:
		client_public_key = RSA.import_key(key_file.read())

	# Verify the signature
	if verify_signature(client_public_key, decrypted_file_data, signature):
		print("...................................")
		print("Signature is valid.")
		print("...................................")
	else:
		print("...................................")
		print("Signature is invalid.")
		print("...................................")

	conn.close()

if __name__ == "__main__":
	start_server()

"""
	Code Flow:
 
	Open Socket @ 127.0.0.1
 
	Await Connection

	On Connection:
		Recvall encrypted AES key

		Recvall filesize 
  
		Recvall filedata (using fsz ^)

		Recvall:-
			Tag
			Nonce
			Signature
   
		Loadkey SERVER PRIVATE
		
		Decrypt AES key:
			Generate RSA Cipher
			Decrypt using RSA Cipher
	
		Decrypt File Data:
			Generate AES Cipher
			Decrypt and verify data using AES Cipher and TAG
   
		Writedata received-file.txt
  
		Loadkey CLIENT PUBLIC
  
		Verify Signature:
			Generate HASH of filedata
			new PKCS1v1.5 Verifier()
			Verify Hash and Signature
   
		END
"""

"""
	Presumably here the use of RSA is to safely encrypt the key used to encrypt the data (AES) to make it more secure.
	As RSA is very slow compared to AES, AES is used to encrypt the filedata and the key is secured via RSA.
"""