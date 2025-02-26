from flask import Flask, request, jsonify
from flask_cors import CORS
from flask import render_template, send_file
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import base64
import os
import hashlib
import json
import time
# import threading
from typing import List, Dict

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import ssl
from email.mime.application import MIMEApplication
from cryptography.x509 import load_pem_x509_certificate


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


class BlockchainStorage:
    BLOCKCHAIN_FILE = 'blockchain_data.json'

    @staticmethod
    def save_blockchain(chain_data: List[Dict]):
        try:
            with open(BlockchainStorage.BLOCKCHAIN_FILE, 'w') as f:
                json.dump(chain_data, f, indent=4)
        except Exception as e:
            print(f"Error saving blockchain: {e}")

    @staticmethod
    def load_blockchain() -> List[Dict]:
        try:
            if os.path.exists(BlockchainStorage.BLOCKCHAIN_FILE):
                with open(BlockchainStorage.BLOCKCHAIN_FILE, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            return []

class CertificateManager:
    def __init__(self):
        self.private_key = None
        self.certificate = None
        self.blockchain = CertificateBlockchain()

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
            with open("root_cred/rootCA.key", "rb") as key_file:
                root_private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            with open("root_cred/rootCA.crt", "rb") as cert_file:
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


    def generate_and_store_certificate(self, common_name, organization, country, email):
        try:
            # Check if certificate already exists for this email
            existing_cert = self.blockchain.get_certificate_by_email(email)
            if existing_cert:
                raise ValueError(f"Certificate already exists for email: {email}")

            # Generate certificate as before
            cert_data = self.generate_certificate(common_name, organization, country)

            # Store in blockchain
            certificate_data = {
                'email': email,
                'certificate': cert_data['certificate'],
                'common_name': common_name,
                'organization': organization,
                'country': country,
                'timestamp': time.time()
            }

            self.blockchain.add_block(certificate_data)
            return cert_data

        except Exception as e:
            raise ValueError(f"Certificate generation and storage failed: {str(e)}")

    def get_certificate_from_blockchain(self, email):
        return self.blockchain.get_certificate_by_email(email)

    def get_all_certificates(self):
        return self.blockchain.get_all_certificates()

class EmailEncryption:
    def __init__(self):
        # Configure your email settings
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "gajendrh@tcd.ie"  # Replace with your email
        self.sender_password = "npyc oksi zwso ulta"   # Replace with your app password
        self.cert_manager = cert_manager  # Add reference to certificate manager

    def encrypt_and_send_email(self, recipient_email, subject, message):
        try:
            # Retrieve certificate from blockchain
            cert_data = self.cert_manager.get_certificate_from_blockchain(recipient_email)
            if not cert_data:
                return False, "Recipient certificate not found in blockchain"

            certificate_pem = cert_data['certificate']

            # Load the recipient's certificate
            certificate = load_pem_x509_certificate(certificate_pem.encode())
            public_key = certificate.public_key()

            # Encrypt the message
            encrypted_message = public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Convert to base64 for email transmission
            encrypted_base64 = base64.b64encode(encrypted_message).decode()

            # Create the email
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            msg['Subject'] = subject

            # Add encrypted message as attachment
            encrypted_part = MIMEApplication(encrypted_base64.encode(), _subtype='enc')
            encrypted_part.add_header('Content-Disposition', 'attachment', filename='encrypted_message.enc')
            msg.attach(encrypted_part)

            # Add a plain text part explaining this is an encrypted email
            msg.attach(MIMEText("This is an encrypted email. Please use your private key to decrypt the attachment.", 'plain'))

            # Send the email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=ssl.create_default_context())
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            return True, "Email sent successfully"

        except Exception as e:
            return False, f"Failed to send encrypted email: {str(e)}"

    def decrypt_email(self, encrypted_base64, private_key_pem):
        try:
            # Load the private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )

            # Decode base64 and decrypt
            encrypted_message = base64.b64decode(encrypted_base64)
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return True, decrypted_message.decode()

        except Exception as e:
            return False, f"Failed to decrypt message: {str(e)}"

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self) -> Dict:
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'hash': self.hash
        }


class CertificateBlockchain:
    def __init__(self):
        self.chain = []
        self.load_blockchain()


    def load_blockchain(self):
        """Load blockchain from file"""
        chain_data = BlockchainStorage.load_blockchain()
        if chain_data:
            self.chain = [
                Block(
                    block['index'],
                    block['timestamp'],
                    block['data'],
                    block['previous_hash']
                ) for block in chain_data
            ]
        else:
            # Create genesis block if chain is empty
            self.chain = [self.create_genesis_block()]
            self.save_blockchain()

    def save_blockchain(self):
        """Save blockchain to file"""
        chain_data = [block.to_dict() for block in self.chain]
        BlockchainStorage.save_blockchain(chain_data)

    def _auto_save(self):
        """Automatically save blockchain periodically"""
        while True:
            time.sleep(60)  # Save every minute
            self.save_blockchain()

    def create_genesis_block(self) -> Block:
        return Block(0, time.time(), {"message": "Genesis Block"}, "0")

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, certificate_data: Dict) -> bool:
        print("Adding block")   
        
        block = Block(
            len(self.chain),
            time.time(),
            certificate_data,
            self.get_latest_block().hash
        )
        self.chain.append(block)
        self.save_blockchain()
        return True

    def get_certificate_by_email(self, email: str) -> str:
        for block in reversed(self.chain):  # Search from newest to oldest
            if block.data.get('email') == email:
                return block.data.get('certificate')
        return None

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            print(current_block.hash)
            print(current_block.calculate_hash())
            print(previous_block.hash)
            print(current_block.previous_hash)  
            # if current_block.hash != current_block.calculate_hash():
            #     return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def get_all_certificates(self) -> List[Dict]:
        """Get all certificates in the blockchain"""
        certificates = []
        for block in self.chain[1:]:  # Skip genesis block
            if 'certificate' in block.data:
                certificates.append({
                    'email': block.data.get('email'),
                    'common_name': block.data.get('common_name'),
                    'organization': block.data.get('organization'),
                    'country': block.data.get('country'),
                    'timestamp': block.timestamp
                })
        return certificates

cert_manager = CertificateManager()

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/generate')
def generate():
    return render_template('index.html')

@app.route('/encrypt-decrypt')
def encrypt_decrypt():
    return render_template('encrypt-decrypt.html')

@app.route('/email-encryption')
def email_encryption_page():
    return render_template('email_encryption.html')


# # Add a route to redirect root to dashboard
# @app.route('/')
# def index():
#     return redirect(url_for('dashboard'))


# Add these routes to your Flask app
@app.route('/send-encrypted-email', methods=['POST'])
def send_encrypted_email():
    data = request.json
    email_handler = EmailEncryption()
    success, message = email_handler.encrypt_and_send_email(
        data['recipient_email'],
        data['subject'],
        data['message'],
        # data['certificate']
    )
    return jsonify({'success': success, 'message': message})

@app.route('/decrypt-email', methods=['POST'])
def decrypt_email():
    data = request.json
    email_handler = EmailEncryption()
    success, message = email_handler.decrypt_email(
        data['encrypted_message'],
        data['private_key']
    )
    return jsonify({'success': success, 'message': message})



@app.route('/generate-certificate', methods=['POST'])
def generate_certificate():
    data = request.json
    print("data",data)
    try:
        # result = cert_manager.generate_certificate(
        #     data['commonName'],
        #     data['organization'],
        #     data['country']
        # )
        result = cert_manager.generate_and_store_certificate(
            data['commonName'],
            data['organization'],
            data['country'],
            data['email']  # Add email to the request
        )
        print("result",result)

        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/get-certificate', methods=['POST'])
def get_certificate():
    data = request.json
    try:
        cert_data = cert_manager.get_certificate_from_blockchain(data['email'])
        if cert_data:
            return jsonify({
                'success': True,
                'data': cert_data
            })
        return jsonify({
            'success': False,
            'error': 'Certificate not found'
        }), 404
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

@app.route('/blockchain-status')
def blockchain_status():
    certificates = cert_manager.get_all_certificates()
    return jsonify({
        'success': True,
        'total_certificates': len(certificates),
        'certificates': certificates
    })

@app.route('/verify-blockchain')
def verify_blockchain():
    is_valid = cert_manager.blockchain.is_chain_valid()
    return jsonify({
        'success': True,
        'is_valid': is_valid
    })

@app.route('/blockchain', methods=['GET'])
def get_blockchain():
    try:
        # Convert chain to dictionary format using existing to_dict method
        blockchain_data = [block.to_dict() for block in cert_manager.blockchain.chain]
        return jsonify({
            'success': True,
            'blockchain': blockchain_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/block/<int:index>', methods=['GET'])
def get_block(index):
    try:
        if index < 0 or index >= len(cert_manager.blockchain.chain):
            return jsonify({
                'success': False,
                'error': 'Block index out of range'
            }), 404

        block = cert_manager.blockchain.chain[index]
        return jsonify({
            'success': True,
            'block': block.to_dict()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/blockchain-stats', methods=['GET'])
def get_blockchain_stats():
    try:
        latest_block = cert_manager.blockchain.get_latest_block()
        certificates = cert_manager.blockchain.get_all_certificates()

        return jsonify({
            'success': True,
            'stats': {
                'total_blocks': len(cert_manager.blockchain.chain),
                'total_certificates': len(certificates),
                'latest_block': latest_block.to_dict(),
                'chain_valid': cert_manager.blockchain.is_chain_valid()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/blockchain-explorer')
def blockchain_explorer():
    return render_template('blockchain_explorer.html')
    
if __name__ == '__main__':
    app.run(debug=True)

# Created/Modified files during execution:
print("Created directory:", CERT_DIR)
print("Certificate files will be created as: <common_name>.crt and <common_name>.key")