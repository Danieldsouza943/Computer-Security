#Daniel Dsouza

from Crypto.PublicKey import RSA

def generate_rsa_key_pair():
    # Generating a 2048-bit RSA key pair
    key = RSA.generate(2048)

    # Exporting the private key in PEM format
    private_key = key.export_key()
    with open("private.pem", "wb") as private_file:
        private_file.write(private_key)

    # Exporting the public key in PEM format
    public_key = key.publickey().export_key()
    with open("public.pem", "wb") as public_file:
        public_file.write(public_key)

    print("RSA key pair generated and saved to 'private.pem' and 'public.pem'")

if __name__ == "__main__":
    generate_rsa_key_pair()
