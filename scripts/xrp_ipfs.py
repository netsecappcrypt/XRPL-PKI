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
import os
import json
import time
import ipfshttpclient

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

class IPFSManager:
    def __init__(self):
        try:
            # Connect to local IPFS daemon
            self.client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
            print_success("Connected to IPFS")
        except Exception as e:
            print_error(f"Failed to connect to IPFS: {str(e)}")
            raise

    def store_certificate(self, certificate):
        """Store certificate in IPFS and return the hash"""
        try:
            # Convert certificate to PEM format
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

            # Add to IPFS
            result = self.client.add_bytes(cert_pem)
            print_success(f"Certificate stored in IPFS with hash: {result}")
            return result
        except Exception as e:
            print_error(f"Failed to store certificate in IPFS: {str(e)}")
            raise

    def retrieve_certificate(self, ipfs_hash):
        """Retrieve certificate from IPFS using its hash"""
        try:
            # Get the certificate data from IPFS
            cert_data = self.client.cat(ipfs_hash)
            return cert_data
        except Exception as e:
            print_error(f"Failed to retrieve certificate from IPFS: {str(e)}")
            raise

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
        self.ipfs_manager = IPFSManager()
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
        """Generate a certificate signed by a Root CA using RSA."""
        try:
            print_info("Generating certificate with RSA...")

            if not os.path.exists("root_cred/rootCA.key") or not os.path.exists("root_cred/rootCA.crt"):
                raise FileNotFoundError("Root CA credentials not found. Please set up the Root CA first.")

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            print_info("RSA Private key generated")

            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            ])).sign(private_key, hashes.SHA256())
            print_info("CSR generated")

            with open("root_cred/rootCA.key", "rb") as key_file:
                root_private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            with open("root_cred/rootCA.crt", "rb") as cert_file:
                root_certificate = x509.load_pem_x509_certificate(cert_file.read())

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
            print_info("Certificate signed by Root CA")

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
            print_success("Certificate and private key saved")

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

            if balance < 1:
                raise ValueError("Insufficient XRP balance")

            email_hash = self.hash_email(email)
            print_info(f"Email hash created: {email_hash}")

            # Store certificate in IPFS
            ipfs_hash = self.ipfs_manager.store_certificate(certificate)
            print_info(f"Certificate stored in IPFS with hash: {ipfs_hash}")

            # Create memo data with email hash and IPFS hash
            memo_data = {
                'email_hash': email_hash,
                'ipfs_hash': ipfs_hash
            }

            memo_json = json.dumps(memo_data)
            memo_hex = str_to_hex(memo_json)

            memo = Memo(
                memo_data=memo_hex,
                memo_format=str_to_hex("text/plain"),
                memo_type=str_to_hex("certificate")
            )

            transaction = AccountSet(
                account=self.xrpl_manager.wallet.classic_address,
                memos=[memo]
            )

            print_info("Signing and submitting transaction...")
            result = submit_and_wait(
                transaction=transaction,
                client=self.xrpl_manager.client,
                wallet=self.xrpl_manager.wallet
            )

            if result.is_successful():
                tx_hash = result.result['hash']
                print_success(f"Transaction successful: {tx_hash}")
                return tx_hash
            else:
                raise Exception(f"Transaction failed: {result.result}")

        except Exception as e:
            print_error(f"Error storing certificate: {str(e)}")
            raise

    def retrieve_certificate_from_xrp_ledger(self, email):
        try:
            email_hash = self.hash_email(email)
            print_info(f"Searching for certificate with email hash: {email_hash}")

            request = AccountTx(
                account=self.xrpl_manager.wallet.classic_address,
                ledger_index_min=-1,
                ledger_index_max=-1,
                limit=20
            )

            response = self.xrpl_manager.client.request(request)
            transactions = response.result.get("transactions", [])

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

                            if memo_json.get('email_hash') == email_hash:
                                ipfs_hash = memo_json['ipfs_hash']
                                return self.ipfs_manager.retrieve_certificate(ipfs_hash)

                    except Exception as memo_error:
                        print_info(f"Error processing memo: {str(memo_error)}")
                        continue

            raise ValueError(f"Certificate not found for email: {email}")

        except Exception as e:
            print_error(f"Error retrieving certificate: {str(e)}")
            raise

def setup_root_ca():
    """Set up Root CA if it doesn't exist"""
    try:
        if not os.path.exists("root_cred"):
            os.makedirs("root_cred")

        if not os.path.exists("root_cred/rootCA.key") or not os.path.exists("root_cred/rootCA.crt"):
            print_info("Generating Root CA credentials...")

            root_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )

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
        setup_root_ca()

        print_header("Initializing XRP Ledger Connection")
        xrpl_manager = XRPLedgerManager()

        print_header("Checking Initial Balance")
        initial_balance = xrpl_manager.check_balance()
        print_info(f"Initial balance: {initial_balance} XRP")

        cert_manager = CertificateManager(xrpl_manager)

        print_header("Generating Test Certificate")
        common_name = "test@example.com"
        organization = "Test Organization"
        country = "US"

        certificate, private_key = cert_manager.generate_certificate(
            common_name,
            organization,
            country
        )
        print_success("Certificate generated successfully")

        print_header("Storing Certificate in XRP Ledger")
        tx_hash = cert_manager.store_certificate_in_xrp_ledger(
            certificate,
            common_name
        )

        time.sleep(5)

        print_header("Retrieving Certificate")
        retrieved_cert = cert_manager.retrieve_certificate_from_xrp_ledger(common_name)
        print_success("Certificate retrieved successfully")

        print_header("Final Balance Check")
        final_balance = xrpl_manager.check_balance()
        print_info(f"Balance change: {initial_balance - final_balance} XRP")

    except Exception as e:
        print_error(f"Main execution failed: {str(e)}")

if __name__ == "__main__":
    main()