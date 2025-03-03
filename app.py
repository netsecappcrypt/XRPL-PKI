from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import base64
import json
import os
from xrpl_ledger import XRPLedgerManager, CertificateEncoder
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import ssl
from email.mime.application import MIMEApplication
from cryptography.x509 import load_pem_x509_certificate

# Directory to store certificates
CERT_DIR = "certificates"
os.makedirs(CERT_DIR, exist_ok=True)

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize XRP Ledger components
xrpl_manager = XRPLedgerManager()
cert_encoder = CertificateEncoder()

# CertificateManager handles certificate generation, storage, and encryption/decryption
class CertificateManager:
    def __init__(self):
        pass

    def generate_certificate(self, common_name, organization, country):
        """
        Generate a certificate signed by a Root CA using ECC.
        """
        try:
            print("[INFO] Generating certificate with ECC...")

            # Generate ECC private key
            private_key = ec.generate_private_key(ec.SECP256R1())  # Using P-256 curve
            print("[INFO] ECC Private key generated")

            # Create certificate signing request (CSR)
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()),
            ])).sign(private_key, hashes.SHA256())
            print("[INFO] CSR generated")

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
            print("[INFO] Certificate signed by Root CA")

            # Save the new certificate and private key
            cert_dir = "certificates"
            os.makedirs(cert_dir, exist_ok=True)

            cert_path = os.path.join(cert_dir, f"{common_name}.crt")
            key_path = os.path.join(cert_dir, f"{common_name}.key")

            with open(cert_path, "wb") as cert_file:
                cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            print("[SUCCESS] Certificate and private key saved")

            # Return the certificate and private key
            return {
                "certificate": certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                "private_key": private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode("utf-8")
            }

        except Exception as e:
            print(f"[ERROR] Error in generate_certificate: {str(e)}")
            raise ValueError(f"Certificate generation failed: {str(e)}")
            
    def store_certificate_xrpl(self, email, cert_pem):
        """
        Store the certificate in the XRP Ledger with size tracking.
        """
        try:
            print(f"Storing certificate for email: {email} in the XRP Ledger...")

            # Track original size
            original_size = len(cert_pem)
            print(f"[INFO] Original certificate size: {original_size} bytes")

            # Compress certificate
            print("[INFO] Compressing certificate...")
            compressed_cert = cert_encoder.compress_cert(cert_pem)
            compressed_size = len(compressed_cert if isinstance(compressed_cert, str) else compressed_cert)
            print(f"[INFO] Compressed certificate size: {compressed_size} bytes (Reduction: {(1 - compressed_size/original_size)*100:.2f}%)")

            # Encode for ledger
            print("[INFO] Encoding data for ledger storage...")
            encoded_data = base64.b64encode(compressed_cert).decode('utf-8')
            encoded_size = len(encoded_data if isinstance(encoded_data, str) else encoded_data)
            print(f"[INFO] Encoded data size: {encoded_size} bytes")

            # Hash email
            print("[INFO] Hashing email address...")
            email_hash = cert_encoder.hash_email(email)

            # Create data package
            data_package = json.dumps({
                'email_hash': email_hash,
                'cert_data': encoded_data
            })
            package_size = len(data_package)
            print(f"[INFO] Final data package size: {package_size} bytes")


            # Store on ledger
            print("[INFO] Preparing to store data in the XRP Ledger...")
            tx_hash = xrpl_manager.store_data(data_package)

            print(f"[SUCCESS] Certificate stored successfully with transaction hash: {tx_hash}")
            return tx_hash

        except Exception as e:
            print(f"[ERROR] Failed to store certificate: {str(e)}")
            raise

    def retrieve_certificate_xrpl(self, email):
        """
        Retrieve the certificate from the XRP Ledger.
        """
        print(f"Retrieving certificate for email: {email} from the XRP Ledger...")
        email_hash = cert_encoder.hash_email(email)
        all_data = xrpl_manager.retrieve_data()
        for data in all_data:
            try:
                package = json.loads(data)
                if package.get('email_hash') == email_hash:
                    decoded = cert_encoder.decode_from_ledger(package['cert_data'])
                    print("Certificate retrieved successfully.")
                    return cert_encoder.decompress_cert(decoded)
            except Exception as e:
                print(f"Error while retrieving certificate: {str(e)}")
                continue
        print("Certificate not found.")
        return None

    def encrypt_message(self, message, certificate_pem):
        """
        Encrypt a message using the public key from a certificate.
        """
        print("Encrypting message using the recipient's certificate...")
        cert = x509.load_pem_x509_certificate(certificate_pem)
        public_key = cert.public_key()
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Message encrypted successfully.")
        return encrypted

    def decrypt_message(self, encrypted_message, private_key_pem):
        """
        Decrypt a message using the private key.
        """
        print("Decrypting message using the private key...")
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        decrypted = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Message decrypted successfully.")
        return decrypted.decode()

# EmailEncryption handles email encryption and decryption
class EmailEncryption:
    def __init__(self):
        # Configure your email settings
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "your_email@gmail.com"  # Replace with your email
        self.sender_password = "your_app_password"  # Replace with your app password

    def encrypt_and_send_email(self, recipient_email, subject, message):
        """
        Encrypt and send an email.
        """
        print(f"Encrypting and sending email to: {recipient_email}...")
        try:
            # Retrieve the recipient's certificate from the XRP Ledger
            cert_pem = cert_manager.retrieve_certificate_xrpl(recipient_email)
            if not cert_pem:
                print("Recipient certificate not found in XRP Ledger.")
                return False, "Recipient certificate not found in XRP Ledger"

            # Load the recipient's certificate
            certificate = load_pem_x509_certificate(cert_pem)
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

            print("Email sent successfully.")
            return True, "Email sent successfully"

        except Exception as e:
            print(f"Failed to send encrypted email: {str(e)}")
            return False, f"Failed to send encrypted email: {str(e)}"

    def decrypt_email(self, encrypted_base64, private_key_pem):
        """
        Decrypt an encrypted email.
        """
        print("Decrypting the email...")
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

            print("Email decrypted successfully.")
            return True, decrypted_message.decode()

        except Exception as e:
            print(f"Failed to decrypt message: {str(e)}")
            return False, f"Failed to decrypt message: {str(e)}"

# Initialize CertificateManager
cert_manager = CertificateManager()

# Routes for rendering HTML pages
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

# Route to send encrypted email
@app.route('/send-encrypted-email', methods=['POST'])
def send_encrypted_email():
    data = request.json
    email_handler = EmailEncryption()
    success, message = email_handler.encrypt_and_send_email(
        data['recipient_email'],
        data['subject'],
        data['message']
    )
    return jsonify({'success': success, 'message': message})

# Route to decrypt email
@app.route('/decrypt-email', methods=['POST'])
def decrypt_email():
    data = request.json
    email_handler = EmailEncryption()
    success, message = email_handler.decrypt_email(
        data['encrypted_message'],
        data['private_key']
    )
    return jsonify({'success': success, 'message': message})

# Route to generate a certificate and store it in the XRP Ledger
@app.route('/generate-certificate', methods=['POST'])
def generate_certificate():
    data = request.json
    try:
        cert_data = cert_manager.generate_certificate(
            data['commonName'],
            data['organization'],
            data['country']
        )

        tx_hash = cert_manager.store_certificate_xrpl(
            data['email'],
            cert_data['certificate'].encode()
        )

        return jsonify({
            'success': True,
            'tx_hash': tx_hash,
            'certificate': cert_data['certificate'],
            'private_key': cert_data['private_key']
        })
    except Exception as e:
        print(f"Error generating certificate: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Route to retrieve a certificate from the XRP Ledger
@app.route('/get-certificate', methods=['POST'])
def get_certificate():
    data = request.json
    try:
        cert_pem = cert_manager.retrieve_certificate_xrpl(data['email'])
        if cert_pem:
            return jsonify({
                'success': True,
                'certificate': cert_pem.decode()
            })
        print("Certificate not found.")
        return jsonify({'success': False, 'error': 'Certificate not found'}), 404
    except Exception as e:
        print(f"Error retrieving certificate: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Route to encrypt a message
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    try:
        encrypted = cert_manager.encrypt_message(
            data['message'],
            data['certificate'].encode()
        )
        return jsonify({
            'success': True,
            'encrypted': base64.b64encode(encrypted).decode()
        })
    except Exception as e:
        print(f"Error encrypting message: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Route to decrypt a message
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    try:
        decrypted = cert_manager.decrypt_message(
            base64.b64decode(data['encryptedMessage']),
            data['privateKey']
        )
        return jsonify({
            'success': True,
            'decrypted': decrypted
        })
    except Exception as e:
        print(f"Error decrypting message: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting the Flask application...")
    app.run(debug=True, port=5003)