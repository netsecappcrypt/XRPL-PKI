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
                    # Create wallet from seed
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
                # Wait for faucet funding
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
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024
            )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country)
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=1)
            ).sign(private_key, hashes.SHA256())

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            compressed_cert = gzip.compress(cert_pem)

            # Save certificate details
            self.certificates[common_name] = {
                'organization': organization,
                'country': country,
                'creation_date': datetime.datetime.utcnow().isoformat(),
                'private_key': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
            }
            self.save_certificates()

            return compressed_cert, cert

        except Exception as e:
            print_error(f"Error generating certificate: {str(e)}")
            raise

    # Add this function to the CertificateManager class
    def hash_email(self, email):
        """Create SHA-256 hash of email address"""
        return sha256(email.encode()).hexdigest()
        
    # Update the store_certificate_in_xrp_ledger method
    def store_certificate_in_xrp_ledger(self, compressed_cert, email):
        try:
            balance = self.xrpl_manager.check_balance()
            print_info(f"Current balance: {balance} XRP")

            if balance < 1:
                raise ValueError("Insufficient XRP balance")

            # Hash the email
            email_hash = self.hash_email(email)
            print_info(f"Email hash created: {email_hash}")

            # Convert compressed certificate to base64 string
            compressed_cert_b64 = base64.b64encode(compressed_cert).decode('utf-8')

            # Create memo data with hashed email
            memo_data = {
                'email_hash': email_hash,
                'cert_data': compressed_cert_b64
            }

            # Convert to JSON and then to hex
            memo_json = json.dumps(memo_data)
            memo_hex = str_to_hex(memo_json)

            print_info(f"Memo data created successfully")

            # Create memo with hex-encoded strings
            memo = Memo(
                memo_data=memo_hex,
                memo_format=str_to_hex("text/plain"),
                memo_type=str_to_hex("certificate")
            )

            # Create transaction
            transaction = AccountSet(
                account=self.xrpl_manager.wallet.classic_address,
                memos=[memo]
            )

            print_info(f"Transaction details: {transaction.to_dict()}")

            try:
                print_info("Signing and submitting transaction...")
                # Sign and submit the transaction
                response = sign_and_submit(
                    transaction=transaction,
                    wallet=self.xrpl_manager.wallet,
                    client=self.xrpl_manager.client
                )

                print_info("Waiting for validation...")
                # Wait for validation
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

            except Exception as submit_error:
                print_error(f"Transaction submission error: {str(submit_error)}")
                raise

        except Exception as e:
            print_error(f"Error storing certificate: {str(e)}")
            raise

    # Update the retrieve_certificate_from_xrp_ledger method
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
            result = response.result if hasattr(response, 'result') else response
            transactions = result.get("transactions", [])

            if not transactions:
                print_error("No transactions found in response")
                raise ValueError("No transactions found")

            print_info(f"Found {len(transactions)} transactions to process")

            for idx, tx in enumerate(transactions):
                tx_data = tx.get("tx_json", {}) if isinstance(tx, dict) else tx.tx_json
                memos = tx_data.get("Memos", [])

                for memo_idx, memo in enumerate(memos):
                    try:
                        if isinstance(memo, dict):
                            memo_data = memo.get("Memo", {}).get("MemoData", "")
                        else:
                            memo_data = getattr(getattr(memo, "Memo", {}), "MemoData", "")

                        if memo_data:
                            memo_str = ''.join([chr(int(memo_data[i:i+2], 16))
                                            for i in range(0, len(memo_data), 2)])

                            try:
                                memo_json = json.loads(memo_str)
                                stored_hash = memo_json.get('email_hash')

                                if stored_hash == email_hash:
                                    print_success(f"Found certificate for email hash: {email_hash}")
                                    return memo_json.get('cert_data', '')
                            except json.JSONDecodeError:
                                continue
                    except Exception as memo_error:
                        print_info(f"Error processing memo {memo_idx + 1}: {str(memo_error)}")

            raise ValueError(f"Certificate not found for email: {email}")

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

def main():
    try:
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

        compressed_cert, cert = cert_manager.generate_certificate(
            common_name,
            organization,
            country
        )
        print_success("Certificate generated successfully")

        print_header("Storing Certificate in XRP Ledger")
        tx_hash = cert_manager.store_certificate_in_xrp_ledger(
            compressed_cert,
            common_name
        )

        # Wait for transaction to be processed
        time.sleep(5)

        print_header("Retrieving Certificate")
        retrieved_cert_pem = cert_manager.retrieve_certificate_from_xrp_ledger(common_name)
        print_success("Certificate retrieved successfully")

        print_header("Testing Encryption/Decryption")
        test_message = "Hello, XRP Ledger!"
        encrypted_message = cert_manager.encrypt_message(test_message, cert)
        print_success("Message encrypted")

        decrypted_message = cert_manager.decrypt_message(encrypted_message, common_name)
        print_success("Message decrypted")

        print(f"\nOriginal message: {test_message}")
        print(f"Decrypted message: {decrypted_message}")

        print_header("Final Balance Check")
        final_balance = xrpl_manager.check_balance()
        print_info(f"Balance change: {initial_balance - final_balance} XRP")

    except Exception as e:
        print_error(f"Main execution failed: {str(e)}")

if __name__ == "__main__":
    main()