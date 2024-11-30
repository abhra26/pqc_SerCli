import socket
import oqs
from x509 import CustomX509Certificate
import json
import time
import threading

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

server_cert.add_extension("2.5.29.17", "DNS:www.myserver.com", critical=False)  # SAN example

server_cert.sign()

print("Server is listening for connections...")


def start_server():
    global server_socket
    global server_cert
    start_time = time.time()
    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        
        # Sign and serialize the certificate
        
        # Send server's certificate to client
        conn.sendall(server_cert.serialize_json().encode())
        
        # Receive client's certificate
        client_cert_data = server_socket.recv(2048).decode().strip()

        print("Received Client Certificate:")
        print(client_cert_data)

        kem = oqs.KeyEncapsulation('Kyber768')
        kemPubKey = kem.generate_keypair()

        kem_cert = CustomX509Certificate(
            subject="CN=Server,O=My Organization,C=US",
            issuer="CN=My CA,O=My Organization,C=US",
            public_key=kemPubKey,
            signer=signer,
            validity_days=365
        )

        kem_cert.sign()

        conn.sendall(kem_cert.serialize_json().encode())

        if time.time() - start_time > 600:
            break
        
    conn.close()


if __name__ == "__main__":
    start_server()
