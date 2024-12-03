import os
from x509 import CustomX509Certificate
import aes
import hashlib
import base64
import json

def registration(conn,addr,shared_secret, Signer):
    ip, port = addr
    name = input("Enter Name: ")
    email = input("Enter Email ID: ")
    username = input("Enter Username: ")
    while True:
        password = input("Input Password: ")
        verify_password = input("Confirm Password: ")

        if password == verify_password:
            filename = name+'.txt'
            token = os.urandom(16)
            data_stored = {
                'IP' : ip,
                'Name' : name,
                'Email' : email,
                'Username' : username,
                'Password' : hashlib.sha3_256(password).hexdigest(),
                'AuthTOK' : base64.b64encode(token.decode()).decode(),
                'Shared Secret': base64.b64encode(shared_secret).decode(),
                'Devices_INFO' : {}
            }
            with open(filename,'w') as f:
                f.write(json.dumps(data_stored))

            data_shared = aes.encrypt(token,shared_secret,Signer)

            conn.sendall(data_shared.encode())
            conn.sendall('\0'.encode())
            break

        else:
            print("Wrong Password")