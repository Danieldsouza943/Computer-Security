import ssl
import socket

def start_server(server_ip, server_port):
    # 1. Create an SSL context for the server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # 2. Load the server's certificate and private key
    context.load_cert_chain(certfile="client1.crt", keyfile="client1.key")
    
    # 3. Load the CA certificate to verify the client's certificate
    context.load_verify_locations("ca.crt")
    context.verify_mode = ssl.CERT_OPTIONAL  # Disables server verification

    # Create a TCP/IP socket
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind(('localhost', 8443))  # Listen on port 8443
    bindsocket.listen(5)
    print("Server listening on port 8443...")

    while True:
        # Accept incoming connection
        newsocket, fromaddr = bindsocket.accept()
        print(f"Connection from {fromaddr}")

        # Wrap the socket with SSL
        with context.wrap_socket(newsocket, server_side=True) as sslsocket:
            print("TLS connection established.")
            # Receive data from client
            data = sslsocket.recv(1024).decode()
            print(f"Received from client: {data}")
            # Send a secure response to client
            sslsocket.send(b"Hello, Client 2! This is a secure message from Client 1.")
            print("Response sent to client.")

if __name__ == "__main__":
    start_server("localhost", 8443)