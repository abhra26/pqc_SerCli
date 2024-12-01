import socket
import oqs
from x509 import CustomX509Certificate
import json
import time
import threading
import hashlib
import base64

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
        print("Connection obj", conn)
        
        # Sign and serialize the certificate
        
        # Send server's certificate to client
        conn.sendall(server_cert.serialize_json().encode())
        
        # Receive client's certificate

        client_cert_data = json.loads(conn.recv(65536).decode())

        client_pubKey_sign = base64.b64decode(client_cert_data['Public Key'].encode())

        kem = oqs.KeyEncapsulation('Kyber768')
        kemPubKey = kem.generate_keypair()

        kem_cert = CustomX509Certificate(
            subject="CN=Server,O=My Organization,C=US",
            issuer="CN=My CA,O=My Organization,C=US",
            public_key=kemPubKey,
            signer=signer,
            validity_days=365
        )
        kem_cert.add_extension("2.5.29.17", "DNS:www.myserver.com", critical=False)  # SAN example
        kem_cert.sign()

        # time.sleep(0.5)
        conn.sendall(kem_cert.serialize_json().encode())

        shared_secret_data = json.loads(conn.recv(65536).decode())
        signature = base64.b64decode(shared_secret_data['Signature'].encode())
        cipher = base64.b64decode(shared_secret_data['Shared Secret Cipher'].encode())
        hash_data = hashlib.sha256(cipher).hexdigest()
        print(' ')
        print(' ')
        print("Verification/AUTH:", signer.verify(hash_data.encode(),signature,client_pubKey_sign))
        print('shared secret:', base64.b64encode(kem.decap_secret(cipher)).decode())

        if time.time() - start_time > 600:
            break
        
    conn.close()


if __name__ == "__main__":
    start_server()
    # print(kem_cert.serialize_json())
