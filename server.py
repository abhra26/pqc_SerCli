import socket
import oqs
from x509 import CustomX509Certificate

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(1)

signer = oqs.Signature('Dilithium3')
pubKey = signer.generate_keypair()

server_cert = CustomX509Certificate(
    subject="CN=Server,O=My Organization,C=US",
    issuer="CN=My CA,O=My Organization,C=US",
    public_key=pubKey,
    signer=signer,
    validity_days=365
)

print("Server is listening for connections...")


def start_server():
    global server_socket
    global server_cert

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        
        server_cert.add_extension("2.5.29.17", "DNS:www.myserver.com", critical=False)  # SAN example
        
        # Sign and serialize the certificate
        signature = server_cert.sign()
        
        # Send server's certificate to client
        conn.sendall(server_cert.serialize().encode())
        
        # Receive client's certificate
        client_cert_data = conn.recv(1024).decode()
        print("Received Client Certificate:")
        print(client_cert_data)
        
        conn.close()


if __name__ == "__main__":
    start_server()