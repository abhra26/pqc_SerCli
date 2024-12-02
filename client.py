import socket
import oqs
from x509 import CustomX509Certificate
import os
import json
import aes
import base64
import hashlib


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

shared_secret = os.urandom(32)
kemobj = oqs.KeyEncapsulation('Kyber768')

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    client_socket.connect(('192.168.137.197', 65432))
    
    # Receive server's certificate from server

    buffer =""

    while True:
         parts = client_socket.recv(65432).decode()
         if parts == '\0':
              break
         buffer += parts

    server_cert_data = json.loads(buffer)
    
    print("Server Signature Public Key:")
    print(base64.b64decode(server_cert_data['Public Key'].encode()))

    server_signPubKey = base64.b64decode(server_cert_data['Public Key'].encode())

    # # Send client's certificate to the server
    client_socket.sendall(client_cert.serialize_json().encode())
    client_socket.sendall('\0'.encode())

    buffer = ""
    while True:
         parts = client_socket.recv(65432).decode()
         if parts == '\0':
              break
         buffer += parts

    server_kem_cert = json.loads(buffer)

    server_kemPubKey = base64.b64decode(server_kem_cert['Public Key'].encode())
    print('Server Encap Public Key:')
    print(server_kemPubKey)

    ciphertext, shared_secret = kemobj.encap_secret(server_kemPubKey)
    print("Shared Secret:")
    print(base64.b64encode(shared_secret).decode())
    hashdata = hashlib.sha256(ciphertext).hexdigest()
    signature = signerUSR.sign(hashdata.encode())

    data = {
         'Shared Secret Cipher' : base64.b64encode(ciphertext).decode(),
         'Signature' : base64.b64encode(signature).decode()
    }

    client_socket.sendall(json.dumps(data).encode())
    client_socket.sendall('\0'.encode())

    buffer = ""
    while True:
         parts = client_socket.recv(65432).decode()
         if parts == '\0':
              break
         buffer += parts

    encrypted = json.loads(buffer)

    ciphertext = encrypted['Ciphertext']
    iv = encrypted['iv']
    tag = encrypted['tag']
    Signature = encrypted['Signature']

    plaintext = aes.decrypt_txt(buffer,shared_secret,signerUSR,server_signPubKey)

    print(plaintext)
    

    client_socket.close()


if __name__ == "__main__":
     start_client()
