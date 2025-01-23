#Daniel Dsouza

import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def aes_encrypt(file_content):
    # Generating a random AES key (16 bytes for AES-128)
    symmetric_key = get_random_bytes(16)
    
    # Initializing AES cipher in EAX mode
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    
    # Encrypting the file content and generate authentication tag
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_content)
    
    # Returning the AES key, nonce, tag, and encrypted content (ciphertext)
    return symmetric_key, cipher_aes.nonce, tag, ciphertext

def rsa_encrypt_symmetric_key(public_key_file, symmetric_key):
    with open(public_key_file, 'rb') as f:
        recipient_key = RSA.import_key(f.read())
    
    # Initializing RSA cipher using the public key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    
    # Encrypting the AES symmetric key using RSA
    encrypted_key = cipher_rsa.encrypt(symmetric_key)
    
    return encrypted_key

def save_encrypted_file(output_file, encrypted_key, nonce, tag, ciphertext):
    with open(output_file, 'wb') as f:
        f.write(encrypted_key)  # RSA-encrypted AES key
        f.write(nonce)          # AES nonce
        f.write(tag)            # AES tag
        f.write(ciphertext)     # AES-encrypted content
    print(f"Encrypted data saved to {output_file}")

def aes_decrypt(nonce, tag, ciphertext, symmetric_key):
    # Initializing AES cipher in EAX mode with the given nonce
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    
    # Decrypting the file content and verifying integrity using the tag
    file_content = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    return file_content


def rsa_decrypt_symmetric_key(private_key_file, encrypted_key):
    with open(private_key_file, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    # Initialize RSA cipher using the private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    # Decrypting the AES symmetric key
    symmetric_key = cipher_rsa.decrypt(encrypted_key)
    
    return symmetric_key

def encrypt(receiver_public_key, input_file, output_file):
    with open(input_file, 'rb') as f:
        file_content = f.read()
    
    # Encrypting the file content using AES
    symmetric_key, nonce, tag, ciphertext = aes_encrypt(file_content)
    
    # Encrypting the AES key using RSA and the recipient's public key
    encrypted_key = rsa_encrypt_symmetric_key(receiver_public_key, symmetric_key)
    
    # Saving the encrypted key, nonce, tag, and ciphertext to the output file
    save_encrypted_file(output_file, encrypted_key, nonce, tag, ciphertext)

def decrypt(receiver_private_key, input_file, output_file):
    # Reading the encrypted file (which contains the encrypted AES key, nonce, tag, and ciphertext)
    with open(input_file, 'rb') as f:
        encrypted_key = f.read(256)  # RSA-encrypted AES key is 256 bytes (for RSA-2048)
        nonce = f.read(16)           # AES nonce is 16 bytes
        tag = f.read(16)             # AES authentication tag is 16 bytes
        ciphertext = f.read()        # The remaining data is the AES-encrypted content
    
    # Decrypting the AES key using RSA and the recipient's private key
    symmetric_key = rsa_decrypt_symmetric_key(receiver_private_key, encrypted_key)
    
    # Decrypting the file content using AES
    file_content = aes_decrypt(nonce, tag, ciphertext, symmetric_key)
    
    # Writing the decrypted content to the output file
    with open(output_file, 'wb') as f:
        f.write(file_content)
    
    print(f"Decryption Successful. Decrypted data saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python3 fcrypt.py --encrypt|--decrypt <key-file> <input-file> <output-file>")
        sys.exit(1)

    operation = sys.argv[1]
    key_file = sys.argv[2]
    input_file = sys.argv[3]
    output_file = sys.argv[4]

    if operation == '--encrypt':
        encrypt(key_file, input_file, output_file)
    elif operation == '--decrypt':
        decrypt(key_file, input_file, output_file)
    else:
        print("Invalid operation. Use --encrypt or --decrypt.")
