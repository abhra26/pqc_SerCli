import socket
import oqs
from x509 import CustomX509Certificate
import os
import json


signerUSR = oqs.Signature('Dilithium3')
pubKeyUSR = signerUSR.generate_keypair()

client_cert = CustomX509Certificate(
    subject="CN=Client,O=My Organization,C=US",
    issuer="CN=My CA,O=My Organization,C=US",
    public_key=pubKeyUSR,
    signer=signerUSR,
    validity_days=365 
)

client_cert.add_extension("2.5.29.17", "DNS:www.myclient.com", critical=False)
client_cert.sign()


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    client_socket.connect(('localhost', 65432))
    
    # Receive server's certificate from server
    server_cert_data = client_socket.recv(2048).decode().strip()
    
    print("Received Server Certificate:")
    print(server_cert_data)

    # Send client's certificate to the server
    client_socket.sendall(client_cert.serialize_json().encode())

    server_kem_cert = client_socket.recv(2048).decode().strip()

    print('Server kem Cert:')
    print(server_kem_cert)

    client_socket.close()


if __name__ == "__main__":
     start_client()
