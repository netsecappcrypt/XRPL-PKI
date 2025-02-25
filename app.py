from flask import Flask, request, jsonify
from flask_cors import CORS
from flask import render_template
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import base64
import os

app = Flask(__name__)
# Configure CORS with specific options
CORS(app, resources={
    r"/*": {
        "origins": ["http://127.0.0.1:3000"],
        "methods": ["POST", "OPTIONS"],
        "allow_headers": ["Content-Type"],
        "max_age": 3600,
        "supports_credentials": True
    }
})

# Directory to store certificates and keys
CERT_DIR = 'certificates'
os.makedirs(CERT_DIR, exist_ok=True)

class CertificateManager:
    def __init__(self):
        self.private_key = None
        self.certificate = None

    def generate_certificate(self, common_name, organization, country):
        try:
            print("Inside generate_certificate")

            # Generate private key for the new certificate
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            print("Private key generated")

            # Create certificate signing request (CSR)
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()),
            ])).sign(private_key, hashes.SHA256())
            print("CSR generated")

            # Load the Root CA's private key and certificate
            with open("rootCA.key", "rb") as key_file:
                root_private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            with open("rootCA.crt", "rb") as cert_file:
                root_certificate = x509.load_pem_x509_certificate(cert_file.read())

            # Sign the CSR with the Root CA's private key to create the new certificate
            certificate = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                root_certificate.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(root_private_key, hashes.SHA256())
            print("Certificate signed by Root CA")

            # Save the new certificate and private key
            cert_path = os.path.join(CERT_DIR, f"{common_name}.crt")
            key_path = os.path.join(CERT_DIR, f"{common_name}.key")

            with open(cert_path, "wb") as cert_file:
                cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            print("Certificate and private key saved")

            return {
                "certificate": certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                "private_key": private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode("utf-8")
            }

        except Exception as e:
            print(f"Error in generate_certificate: {str(e)}")
            raise ValueError(f"Certificate generation failed: {str(e)}")
            
    def encrypt_message(self, message, certificate_pem):
        # Load certificate and extract public key
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        public_key = cert.public_key()

        # Encrypt message
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_message(self, encrypted_message, private_key_pem):
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )

        # Decrypt message
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_message), padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')

cert_manager = CertificateManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt-decrypt')
def encrypt_decrypt():
    return render_template('encrypt-decrypt.html')

@app.route('/generate-certificate', methods=['POST'])
def generate_certificate():
    data = request.json
    print("data",data)
    try:
        result = cert_manager.generate_certificate(
            data['commonName'],
            data['organization'],
            data['country']
        )
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    try:
        encrypted = cert_manager.encrypt_message(
            data['message'],
            data['certificate']
        )
        return jsonify({
            'success': True,
            'encrypted': encrypted
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    try:
        decrypted = cert_manager.decrypt_message(
            data['encryptedMessage'],
            data['privateKey']
        )
        return jsonify({
            'success': True,
            'decrypted': decrypted
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)

# Created/Modified files during execution:
print("Created directory:", CERT_DIR)
print("Certificate files will be created as: <common_name>.crt and <common_name>.key")