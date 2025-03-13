import xrpl
from xrpl.clients import JsonRpcClient
from xrpl.wallet import generate_faucet_wallet, Wallet
from xrpl.models.requests import AccountInfo
from xrpl.models.transactions import AccountSet, Memo
from xrpl.utils import drops_to_xrp
from xrpl.transaction import submit_and_wait, sign_and_submit
from xrpl.models.requests import AccountTx
from xrpl.models.response import Response

from hashlib import sha256
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime
import gzip
import os
import base64
import json
import time

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(message):
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== {message} ==={Colors.ENDC}")

def print_success(message):
    print(f"{Colors.GREEN}✓ {message}{Colors.ENDC}")

def print_error(message):
    print(f"{Colors.RED}✖ {message}{Colors.ENDC}")

def print_info(message):
    print(f"{Colors.BLUE}ℹ {message}{Colors.ENDC}")

def str_to_hex(s):
    """Convert string to hex string"""
    return ''.join([hex(ord(c))[2:].zfill(2) for c in s])

class XRPLedgerManager:
    def __init__(self):
        print_info("Connecting to XRP Testnet...")
        self.client = JsonRpcClient("https://s.altnet.rippletest.net:51234")
        self.wallet = None
        self.wallet_file = "xrp_wallet.json"
        self.load_or_create_wallet()

    def load_or_create_wallet(self):
        try:
            if os.path.exists(self.wallet_file):
                with open(self.wallet_file, 'r') as f:
                    wallet_data = json.load(f)
                    self.wallet = Wallet.from_seed(wallet_data['seed'])
                    print_success(f"Loaded existing wallet: {self.wallet.classic_address}")
            else:
                print_info("Creating new XRP Testnet wallet...")
                self.wallet = generate_faucet_wallet(self.client)
                wallet_data = {
                    'seed': self.wallet.seed,
                    'public_key': self.wallet.public_key.hex(),
                    'private_key': self.wallet.private_key.hex(),
                    'classic_address': self.wallet.classic_address
                }
                with open(self.wallet_file, 'w') as f:
                    json.dump(wallet_data, f, indent=4)
                print_success(f"Created new wallet: {self.wallet.classic_address}")
                time.sleep(5)
        except Exception as e:
            print_error(f"Error with wallet: {str(e)}")
            raise

    def check_balance(self):
        try:
            acct_info = AccountInfo(
                account=self.wallet.classic_address,
                ledger_index="validated"
            )
            response = self.client.request(acct_info)
            balance = drops_to_xrp(response.result['account_data']['Balance'])
            return float(balance)
        except Exception as e:
            print_error(f"Error checking balance: {str(e)}")
            return 0

class CertificateManager:
    def __init__(self, xrpl_manager):
        self.xrpl_manager = xrpl_manager
        self.cert_file = "certificates.json"
        self.certificates = self.load_certificates()

    def load_certificates(self):
        if os.path.exists(self.cert_file):
            with open(self.cert_file, 'r') as f:
                return json.load(f)
        return {}

    def save_certificates(self):
        with open(self.cert_file, 'w') as f:
            json.dump(self.certificates, f, indent=4)

    def generate_certificate(self, common_name, organization, country):
        """
        Generate a certificate signed by a Root CA using RSA.
        """
        try:
            print("[INFO] Generating certificate with RSA...")

            # Verify Root CA files exist
            if not os.path.exists("root_cred/rootCA.key") or not os.path.exists("root_cred/rootCA.crt"):
                raise FileNotFoundError("Root CA credentials not found. Please set up the Root CA first.")

            # Generate RSA private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024  # Increased from 1024 for better security
            )
            print("[INFO] RSA Private key generated")

            # Create certificate signing request (CSR)
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
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

            # Sign the CSR with the Root CA's private key
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

            # Save to certificates dictionary
            self.certificates[common_name] = {
                'organization': organization,
                'country': country,
                'creation_date': datetime.datetime.utcnow().isoformat(),
                'certificate': certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                'private_key': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode("utf-8")
            }
            self.save_certificates()

            return certificate, private_key

        except Exception as e:
            print_error(f"Error in generate_certificate: {str(e)}")
            raise

    def hash_email(self, email):
        """Create SHA-256 hash of email address"""
        return sha256(email.encode()).hexdigest()

    def store_certificate_in_xrp_ledger(self, certificate, email):
        try:
            balance = self.xrpl_manager.check_balance()
            print_info(f"Current balance: {balance} XRP")

            if balance < 2:  # Need minimum 2 XRP for two transactions
                raise ValueError("Insufficient XRP balance")

            email_hash = self.hash_email(email)
            print_info(f"Email hash created: {email_hash}")

            # Convert certificate to PEM format and compress
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
            print_info(f"Original certificate size: {len(cert_pem)} bytes")

            compressed_cert = gzip.compress(cert_pem, compresslevel=9)
            print_info(f"Compressed certificate size: {len(compressed_cert)} bytes")

            compressed_cert_b64 = base64.b64encode(compressed_cert).decode('utf-8')
            print_info(f"Base64 encoded certificate size: {len(compressed_cert_b64)} bytes")

            # Split the certificate data into chunks of 2000 bytes
            chunk_size = 500
            cert_chunks = [compressed_cert_b64[i:i+chunk_size]
                         for i in range(0, len(compressed_cert_b64), chunk_size)]

            print_info(f"Certificate split into {len(cert_chunks)} chunks")

            tx_hashes = []
            for idx, chunk in enumerate(cert_chunks):
                memo_data = {
                    'email_hash': email_hash,
                    'chunk_index': idx,
                    'total_chunks': len(cert_chunks),
                    'cert_data': chunk
                }

                memo_json = json.dumps(memo_data)
                print_info(f"Chunk {idx+1} JSON size: {len(memo_json)} bytes")

                memo_hex = str_to_hex(memo_json)
                print_info(f"Chunk {idx+1} hex size: {len(memo_hex)} bytes")

                memo = Memo(
                    memo_data=memo_hex,
                    memo_format=str_to_hex("text/plain"),
                    memo_type=str_to_hex(f"certificate_chunk_{idx}")
                )

                transaction = AccountSet(
                    account=self.xrpl_manager.wallet.classic_address,
                    memos=[memo]
                )

                print_info(f"Submitting chunk {idx+1} of {len(cert_chunks)}...")
                result = submit_and_wait(
                    transaction=transaction,
                    client=self.xrpl_manager.client,
                    wallet=self.xrpl_manager.wallet
                )

                if result.is_successful():
                    tx_hash = result.result['hash']
                    tx_hashes.append(tx_hash)
                    print_success(f"Chunk {idx+1} transaction successful: {tx_hash}")
                else:
                    raise Exception(f"Transaction failed for chunk {idx+1}: {result.result}")

                # Wait between transactions
                time.sleep(2)

            return tx_hashes

        except Exception as e:
            print_error(f"Error storing certificate: {str(e)}")
            raise

    def retrieve_certificate_from_xrp_ledger(self, email):
        try:
            email_hash = self.hash_email(email)
            print_info(f"Searching for certificate chunks with email hash: {email_hash}")

            request = AccountTx(
                account=self.xrpl_manager.wallet.classic_address,
                ledger_index_min=-1,
                ledger_index_max=-1,
                limit=100  # Increased limit to handle multiple chunks
            )

            response = self.xrpl_manager.client.request(request)
            transactions = response.result.get("transactions", [])

            # Dictionary to store chunks
            certificate_chunks = {}
            total_chunks = None

            print_info(f"Processing {len(transactions)} transactions...")

            for tx in transactions:
                tx_data = tx.get("tx_json", {}) if isinstance(tx, dict) else tx.tx_json
                memos = tx_data.get("Memos", [])

                for memo in memos:
                    try:
                        memo_data = memo.get("Memo", {}).get("MemoData", "")
                        if memo_data:
                            memo_str = ''.join([chr(int(memo_data[i:i+2], 16))
                                            for i in range(0, len(memo_data), 2)])
                            memo_json = json.loads(memo_str)

                            print_info(f"Processing memo: {memo_json}")

                            if memo_json.get('email_hash') == email_hash:
                                if "chunk_index" not in memo_json or "cert_data" not in memo_json:
                                    continue
                                chunk_index = memo_json.get('chunk_index')
                                total_chunks = memo_json.get('total_chunks')
                                cert_data = memo_json.get('cert_data')

                                if chunk_index is not None and cert_data:
                                    certificate_chunks[chunk_index] = cert_data
                                    print_info(f"Found chunk {chunk_index + 1} of {total_chunks}")

                    except Exception as memo_error:
                        print_info(f"Error processing memo: {str(memo_error)}")
                        continue

            if not certificate_chunks or total_chunks is None:
                raise ValueError(f"Certificate not found for email: {email}")

            # Verify we have all chunks
            if len(certificate_chunks) != total_chunks:
                raise ValueError(f"Missing certificate chunks. Found {len(certificate_chunks)} of {total_chunks}")

            # Reconstruct the certificate
            print_info("Reconstructing certificate from chunks...")
            combined_b64 = ''
            for i in range(total_chunks):
                if i not in certificate_chunks:
                    raise ValueError(f"Missing chunk {i}")
                combined_b64 += certificate_chunks[i]

            # Decode and decompress
            compressed_data = base64.b64decode(combined_b64)
            decompressed_cert = gzip.decompress(compressed_data)

            print_success("Certificate successfully reconstructed")
            return decompressed_cert

        except Exception as e:
            print_error(f"Error retrieving certificate: {str(e)}")
            raise

    def encrypt_message(self, message, cert):
        try:
            public_key = cert.public_key()
            ciphertext = public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        except Exception as e:
            print_error(f"Error encrypting message: {str(e)}")
            raise

    def decrypt_message(self, ciphertext, common_name):
        try:
            if common_name not in self.certificates:
                raise ValueError(f"No private key found for {common_name}")

            private_key_pem = self.certificates[common_name]['private_key']
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )

            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()
        except Exception as e:
            print_error(f"Error decrypting message: {str(e)}")
            raise

def setup_root_ca():
    """
    Set up Root CA if it doesn't exist
    """
    try:
        if not os.path.exists("root_cred"):
            os.makedirs("root_cred")

        if not os.path.exists("root_cred/rootCA.key") or not os.path.exists("root_cred/rootCA.crt"):
            print_info("Generating Root CA credentials...")

            # Generate Root CA private key
            root_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            # Generate Root CA certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            ])

            root_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                root_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).sign(root_key, hashes.SHA256())

            # Save Root CA private key and certificate
            with open("root_cred/rootCA.key", "wb") as f:
                f.write(root_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open("root_cred/rootCA.crt", "wb") as f:
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))

            print_success("Root CA setup completed")
    except Exception as e:
        print_error(f"Error setting up Root CA: {str(e)}")
        raise

def main():
    try:
        # Setup Root CA
        # setup_root_ca()

        print_header("Initializing XRP Ledger Connection")
        xrpl_manager = XRPLedgerManager()

        print_header("Checking Initial Balance")
        initial_balance = xrpl_manager.check_balance()
        print_info(f"Initial balance: {initial_balance} XRP")

        cert_manager = CertificateManager(xrpl_manager)

        print_header("Generating Test Certificate")
        common_name = "abc@example.com"
        organization = "abc Organization"
        country = "IE"

        # certificate, private_key = cert_manager.generate_certificate(
        #     common_name,
        #     organization,
        #     country
        # )
        # print_success("Certificate generated successfully")

        # print_header("Storing Certificate Chunks in XRP Ledger")
        # tx_hashes = cert_manager.store_certificate_in_xrp_ledger(
        #     certificate,
        #     common_name
        # )
        # print_success(f"Certificate stored in {len(tx_hashes)} transactions")

        # # Wait for transactions to be processeds
        # time.sleep(5)

        print_header("Retrieving Certificate")
        retrieved_cert = cert_manager.retrieve_certificate_from_xrp_ledger(common_name)
        print_success("Certificate retrieved successfully")

        # Verify the retrieved certificate matches the original
        if retrieved_cert == certificate.public_bytes(serialization.Encoding.PEM):
            print_success("Retrieved certificate matches the original")
        else:
            print_error("Retrieved certificate does not match the original")

        decoded_cert = x509.load_pem_x509_certificate(retrieved_cert)
        print_info(f"Common Name: {decoded_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)}")
        print_info(f"Organization: {decoded_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)}")       
        print_info(f"Country: {decoded_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)}")

        print_header("Testing Encryption/Decryption")
        test_message = "Hello, XRP Ledger Harsha!"
        encrypted_message = cert_manager.encrypt_message(test_message, decoded_cert)
        print_success(f"Message encrypted: {encrypted_message}")

        decrypted_message = cert_manager.decrypt_message(encrypted_message, common_name)
        print_success("Message decrypted")

        print(f"\nOriginal message: {test_message}")
        print(f"Decrypted message: {decrypted_message}")

        print_header("Final Balance Check")
        final_balance = xrpl_manager.check_balance()
        print_info(f"Total XRP spent: {initial_balance - final_balance} XRP")

    except Exception as e:
        print_error(f"Main execution failed: {str(e)}")

if __name__ == "__main__":
    main()