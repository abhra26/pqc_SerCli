import base64
import hashlib
import random
import time
import oqs
import json

class X509Extension:
    def __init__(self, oid, value, critical=False):
        self.oid = oid  # Object Identifier for the extension
        self.value = value  # Value of the extension
        self.critical = critical  # Whether the extension is critical

    def serialize(self):
        """Serialize the extension to a string format."""
        critical_str = "critical" if self.critical else "non-critical"
        return f"{self.oid} : {self.value} [{critical_str}]"
    
class CustomX509Certificate:
    def __init__(self, subject, issuer, public_key, signer, validity_days):
        self.version = 3  # X.509 v3
        self.serial_number = self.generate_serial_number()
        self.issuer = issuer
        self.subject = subject
        self.public_key = public_key
        self.not_before = int(time.time())
        self.not_after = self.not_before + (validity_days * 86400)  # validity in seconds
        self.extensions = []  # List to hold extensions
        self.signer = signer
        self.signature = b''

    def generate_serial_number(self):
        """Generate a random serial number for the certificate."""
        return random.randint(1, 2**160)

    def add_extension(self, oid, value, critical=False):
        """Add an extension to the certificate."""
        extension = X509Extension(oid, value, critical)
        self.extensions.append(extension)

    def sign(self):
        """Sign the certificate with the provided private key."""
        cert_data = self.serialize()
        hash_value = hashlib.sha256(cert_data.encode()).hexdigest()
        
        # Simulate signing by returning the hash value (in practice, you'd use the private key).
        self.signature = self.signer.sign(hash_value.encode())

    def serialize(self):
        """Serialize the certificate data into a string format."""
        cert_data = f"""
        Version: {self.version}
        Serial Number: {self.serial_number}
        Issuer: {self.issuer}
        Subject: {self.subject}
        Validity:
            Not Before: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.not_before))}
            Not After: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.not_after))}
        Public Key: {base64.b64encode(self.public_key).decode()}
        Extensions:
            {self.serialize_extensions()}
        """
        return cert_data.strip()
    def serialize_with_signature(self):
        cert_data = f"""
        Version: {self.version}
        Serial Number: {self.serial_number}
        Issuer: {self.issuer}
        Subject: {self.subject}
        Validity:
            Not Before: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.not_before))}
            Not After: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.not_after))}
        Public Key: {base64.b64encode(self.public_key).decode()}
        Signature: {base64.b64encode(self.signature).decode()}
        Extensions:
            {self.serialize_extensions()}
        """
        return cert_data.strip()
    
    def serialize_json(self):
        cert_data = {
            'Version' : self.version,
            'Serial Number': self.serial_number,
            'Issuer' : self.issuer,
            'subject' : self.subject,
            'validity' : {
                'Not Before' : time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.not_before)),
                'Not After' :  time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.not_after))                            
            },
            'Public Key' : base64.b64encode(self.public_key).decode(),
            'Signature' : base64.b64encode(self.signature).decode(),
            'Extentions' : json.loads(self.serialize_extensions_json())
        }

        return json.dumps(cert_data,indent=4)
    
    def serialize_extensions_json(self):
        """Serialize all extensions into a JSON format."""
        extensions_json = {ext.oid: {"value": ext.value, "critical": ext.critical} for ext in self.extensions}
        return json.dumps(extensions_json)

    def serialize_extensions(self):
        """Serialize all extensions into a string format."""
        return "\n            ".join(ext.serialize() for ext in self.extensions)

    def __str__(self):
        return self.serialize()


class CustomCSR:
    def __init__(self, subject, public_key, signer,signerUSR):
        self.subject = subject
        self.public_key = public_key
        self.signer = signer
        self.signature = b''
        self.signerUSR = signerUSR

    def create_cert(self):
        cert = CustomX509Certificate(
            subject=self.subject,
            issuer="CN=My CA,O=My Organization,C=US",  # Example issuer
            public_key=self.public_key,
            signer=self.signerUSR,
            validity_days=365  # Valid for one year
        )

        return cert
    
    def sign(self,cert):
        """Create and sign a CSR."""
        
        # Create an instance of CustomX509Certificate for CSR
        cert = cert.sign()
        
        hash_value = hashlib.sha256(cert.encode()).hexdigest()
        self.signature = self.signer.sign(hash_value.encode())
        
        return cert, self.serialize()

    def serialize(self):
        """Serialize CSR data into a string format."""
        
        csr_data = f"""
            Subject: {self.subject}
            Public Key: {base64.b64encode(self.public_key).decode()}
            Signature: {base64.b64encode(self.signature).decode()}
            """
        
        return csr_data.strip()

def main():
    signerUSR = oqs.Signature('Dilithium3')
    pubKeyUSR = signerUSR.generate_keypair()

    subject = "CN=My Company,O=My Organization,C=US"
    #self_signing
    signer = oqs.Signature('Dilithium3')
    pubKey = signer.generate_keypair()

    # Create a CSR instance
    csr_builder = CustomCSR(subject=subject, public_key=pubKeyUSR, signer=signer, signerUSR=signerUSR)
    cert = csr_builder.create_cert()

    # Add extensions to the certificate
    cert.add_extension("2.5.29.17", "DNS:www.mycompany.com", critical=False)  # Subject Alternative Name (SAN)
    cert.add_extension("2.5.29.15", "Digital Signature,keyEncipherment", critical=True)  # Key Usage
    cert.add_extension("2.5.29.37", "serverAuth", critical=False)  # Extended Key Usage
    cert.add_extension("2.5.29.19", "CA:FALSE", critical=True)  # Basic Constraints

    # Sign the CSR and get certificate and signature
    certificate, cert = csr_builder.sign(cert)

    print("Generated X.509 Certificate:")
    print(certificate)
    print(' ')
    print("Generated CSR:")
    print(cert)

if __name__ == "__main__":
    main()
