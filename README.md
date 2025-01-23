# Computer-Security - Cryptographic Tools and User Management System

Here’s a brief description of all the .py files you uploaded:

1. registration.py
Purpose: Implements a user registration and login system.
Key Features:
Handles user registration with secure password storage (salted SHA-256 hashing in the advanced version).
Stores user information (name, email, hashed password) in a users.json file.
Provides a login mechanism to authenticate users based on stored credentials.

2. tls_client.py
Purpose: Implements a TLS client for secure communication.
Key Features:
Establishes a secure connection to a server using TLS.
Uses certificates for mutual authentication (client2.crt, client2.key).
Sends and receives secure messages to/from the server.

3. tls_server.py
Purpose: Implements a TLS server for secure communication.
Key Features:
Accepts incoming client connections securely using TLS.
Uses certificates for mutual authentication (client1.crt, client1.key).
Sends and receives secure messages to/from the client.

4. fcrypt.py
Purpose: Provides file encryption and decryption using hybrid cryptography.
Key Features:
Encrypts files using AES for file content and RSA for the AES key.
Decrypts encrypted files using the recipient's private RSA key.
Saves encrypted files with all necessary components (nonce, tag, ciphertext, encrypted key).

5. generate_rsa_keys.py
Purpose: Generates RSA public and private key pairs for cryptographic operations.
Key Features:
Creates a 2048-bit RSA key pair.
Saves the private key as private.pem and the public key as public.pem.
Provides foundational cryptographic keys for use in hybrid encryption.
