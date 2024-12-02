import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_image(image_path, key, signer):
    """Encrypt an image using AES-256-GCM."""
    # Generate a random 96-bit IV (12 bytes)
    iv = os.urandom(12)
    
    # Read the image data
    with open(image_path, 'rb') as f:
        plaintext = f.read()
    
    # Create a cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag

    hash = hashlib.sha256(ciphertext.encode()).hexdigest()
    signature =  signer.sign(hash.encode())

    data = {
        'iv' : iv,
        'tag' : tag,
        'Ciphertext' : base64.b64encode(ciphertext).decode(),
        'Signature' : base64.b64encode(signature).decode()
    }
    
    return json.dumps(data)

def encrypt_txt(file_path, key, signer):
    iv = os.urandom(12)

    with open(file_path,'r') as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    tag = encryptor.tag

    hash = hashlib.sha256(ciphertext.encode()).hexdigest()
    signature =  signer.sign(hash.encode())

    data = {
    'iv' : iv,
    'tag' : tag,
    'Ciphertext' : base64.b64encode(ciphertext).decode(),
    'Signature' : base64.b64encode(signature).decode()
    }

    return json.dumps(data)

def decrypt_txt(encrypted_data_json, key, verifier,SignPubKey):
    # Load encrypted data from JSON
    data = json.loads(encrypted_data_json)
    
    iv = data['iv']
    tag = data['tag']
    ciphertext = base64.b64decode(data['Ciphertext'].encode())
    signature = base64.b64decode(data['Signature'].encode())

    # Verify the signature
    hash = hashlib.sha256(ciphertext).hexdigest()
    if not verifier.verify(hash.encode(),signature,SignPubKey):
        raise ValueError("Signature verification failed!")

    # Decrypt the ciphertext using AES-256-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode('utf-8')
