import ssl
import socket

def start_client(server_ip, server_port):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile="client2.crt", keyfile="client2.key")
    context.load_verify_locations("ca.crt")

    with socket.create_connection((server_ip, server_port)) as sock:
        with context.wrap_socket(sock, server_hostname="localhost") as ssock:
            print(f" TLS connection established and connected to {server_ip}:{server_port}")
            ssock.sendall(b"Hello, Client 1! This is a secure message from Client 2.")
            data = ssock.recv(1024)
            print(f"Received: {data.decode()}")

if __name__ == "__main__":
    start_client("localhost", 8443)