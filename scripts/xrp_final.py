import xrpl
from xrpl.clients import JsonRpcClient
from xrpl.wallet import generate_faucet_wallet, Wallet
from xrpl.models.requests import AccountInfo, AccountTx
from xrpl.models.transactions import AccountSet, Memo
from xrpl.utils import drops_to_xrp
from xrpl.transaction import submit_and_wait, sign_and_submit
from xrpl.models.response import Response

import hashlib
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
import logging
from typing import Optional, List, Dict, Tuple
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('xrp_certificate_manager.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class Colors:
    """ANSI color codes for terminal output styling"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Config:
    """Configuration settings for the application"""
    TESTNET_URL = "https://s.altnet.rippletest.net:51234"
    MAINNET_URL = "https://xrplcluster.com"
    MIN_XRP_BALANCE = 2
    CHUNK_SIZE = 500
    TRANSACTION_WAIT_TIME = 2
    RSA_KEY_SIZE = 2048
    CERTIFICATE_VALIDITY_DAYS = 365
    ROOT_CA_VALIDITY_DAYS = 3650
    MAX_RETRY_ATTEMPTS = 3
    RETRY_DELAY = 5  # seconds
    TRANSACTION_TIMEOUT = 30  # seconds

    @staticmethod
    def get_network_url(is_testnet: bool = True) -> str:
        return Config.TESTNET_URL if is_testnet else Config.MAINNET_URL

def print_header(message: str) -> None:
    """Print a formatted header message"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*50}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}    {message}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*50}{Colors.ENDC}\n")
    logger.info(f"HEADER: {message}")

def print_success(message: str) -> None:
    """Print a success message"""
    print(f"{Colors.GREEN}✓ SUCCESS: {message}{Colors.ENDC}")
    logger.info(f"SUCCESS: {message}")

def print_error(message: str) -> None:
    """Print an error message"""
    print(f"{Colors.RED}✖ ERROR: {message}{Colors.ENDC}")
    logger.error(f"ERROR: {message}")

def print_info(message: str) -> None:
    """Print an information message"""
    print(f"{Colors.BLUE}ℹ INFO: {message}{Colors.ENDC}")
    logger.info(f"INFO: {message}")

def print_warning(message: str) -> None:
    """Print a warning message"""
    print(f"{Colors.YELLOW}⚠ WARNING: {message}{Colors.ENDC}")
    logger.warning(f"WARNING: {message}")

def print_debug(message: str) -> None:
    """Print a debug message"""
    print(f"{Colors.CYAN}🔍 DEBUG: {message}{Colors.ENDC}")
    logger.debug(f"DEBUG: {message}")

def str_to_hex(s: str) -> str:
    """Convert string to hex string"""
    return ''.join([hex(ord(c))[2:].zfill(2) for c in s])

class RetryableError(Exception):
    """Exception class for errors that can be retried"""
    pass

class XRPLedgerManager:
    def __init__(self, is_testnet: bool = True):
        print_header("Initializing XRP Ledger Connection")
        self.is_testnet = is_testnet
        self.network_url = Config.get_network_url(is_testnet)
        print_info(f"Connecting to {'Testnet' if is_testnet else 'Mainnet'} at {self.network_url}")

        try:
            self.client = JsonRpcClient(self.network_url)
            print_success("Successfully connected to XRP Ledger")
        except Exception as e:
            print_error(f"Failed to connect to XRP Ledger: {str(e)}")
            raise

        self.wallet = None
        self.wallet_file = "xrp_wallet.json"
        self.load_or_create_wallet()

    def load_or_create_wallet(self) -> None:
        """Load existing wallet or create a new one"""
        print_info("Checking for existing wallet...")
        try:
            if os.path.exists(self.wallet_file):
                self._load_existing_wallet()
            else:
                self._create_new_wallet()
        except Exception as e:
            print_error(f"Wallet initialization failed: {str(e)}")
            raise

    def _load_existing_wallet(self) -> None:
        """Load an existing wallet from file"""
        print_info(f"Found existing wallet file: {self.wallet_file}")
        try:
            with open(self.wallet_file, 'r') as f:
                wallet_data = json.load(f)
                self.wallet = Wallet.from_seed(wallet_data['seed'])
                print_success(f"Loaded existing wallet with address: {self.wallet.classic_address}")

                # Verify wallet access
                print_info("Verifying wallet access...")
                balance = self.check_balance()
                print_success(f"Wallet verified with balance: {balance} XRP")

                # Verify network matches
                stored_network = wallet_data.get('network', 'testnet')
                if (stored_network == 'testnet') != self.is_testnet:
                    raise ValueError(f"Wallet network mismatch. Wallet is for {stored_network}")

        except Exception as e:
            print_error(f"Failed to load existing wallet: {str(e)}")
            raise

    def _create_new_wallet(self) -> None:
        """Create a new wallet"""
        print_info("Creating new wallet...")
        if not self.is_testnet:
            raise ValueError("Cannot auto-generate wallet on mainnet")

        try:
            self.wallet = generate_faucet_wallet(self.client)
            wallet_data = {
                'seed': self.wallet.seed,
                'public_key': self.wallet.public_key.hex(),
                'private_key': self.wallet.private_key.hex(),
                'classic_address': self.wallet.classic_address,
                'creation_date': datetime.datetime.utcnow().isoformat(),
                'network': 'testnet' if self.is_testnet else 'mainnet'
            }

            # Save wallet information
            print_info("Saving wallet information...")
            with open(self.wallet_file, 'w') as f:
                json.dump(wallet_data, f, indent=4)
            print_success(f"Created and saved new wallet with address: {self.wallet.classic_address}")

            # Wait for faucet funding
            print_info("Waiting for faucet funding...")
            self._wait_for_funding()

        except Exception as e:
            print_error(f"Failed to create new wallet: {str(e)}")
            raise

    def _wait_for_funding(self, timeout: int = 30) -> None:
        """Wait for wallet to be funded"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            balance = self.check_balance()
            if balance > 0:
                print_success(f"Wallet funded with {balance} XRP")
                return
            print_info("Waiting for funding...")
            time.sleep(5)
        raise TimeoutError("Wallet funding timeout")

    def check_balance(self) -> float:
        """Check the XRP balance of the wallet"""
        try:
            print_info(f"Checking balance for {self.wallet.classic_address}")
            acct_info = AccountInfo(
                account=self.wallet.classic_address,
                ledger_index="validated"
            )
            response = self.client.request(acct_info)

            if response.is_successful():
                balance = drops_to_xrp(response.result['account_data']['Balance'])
                print_success(f"Balance retrieved: {balance} XRP")
                return float(balance)
            else:
                raise Exception(f"Failed to get balance: {response.result}")

        except Exception as e:
            print_error(f"Error checking balance: {str(e)}")
            if "Account not found" in str(e):
                print_info("Account does not exist in the ledger yet")
                return 0.0
            raise

    def wait_for_balance_update(self, initial_balance: float, timeout: int = 30) -> float:
        """Wait for balance to update after a transaction"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            current_balance = self.check_balance()
            if current_balance != initial_balance:
                return current_balance
            print_info("Waiting for balance update...")
            time.sleep(5)
        raise TimeoutError("Balance update timeout")
class CertificateManager:
    """Manages digital certificate operations and storage on XRP Ledger"""

    def __init__(self, xrpl_manager: XRPLedgerManager):
        self.xrpl_manager = xrpl_manager
        self.cert_file = "certificates.json"
        self.certificates = self.load_certificates()
        self.root_ca_path = "root_cred"
        self.cert_storage_path = "certificates"

        # Ensure required directories exist
        os.makedirs(self.root_ca_path, exist_ok=True)
        os.makedirs(self.cert_storage_path, exist_ok=True)

    def load_certificates(self) -> Dict:
        """Load certificates from local storage"""
        try:
            if os.path.exists(self.cert_file):
                with open(self.cert_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print_error(f"Failed to load certificates: {str(e)}")
            return {}

    def save_certificates(self) -> None:
        """Save certificates to local storage"""
        try:
            with open(self.cert_file, 'w') as f:
                json.dump(self.certificates, f, indent=4)
            print_success("Certificates saved successfully")
        except Exception as e:
            print_error(f"Failed to save certificates: {str(e)}")
            raise
    def hash_email(self, email: str) -> str:
        """Create a hash of the email address"""
        try:
            # Normalize email (convert to lowercase)
            normalized_email = email.lower().strip()

            # Create SHA-256 hash
            email_hash = hashlib.sha256(normalized_email.encode()).hexdigest()

            # Take first 32 characters of the hash
            truncated_hash = email_hash[:32]

            print_debug(f"Created hash for email {email}: {truncated_hash}")
            return truncated_hash

        except Exception as e:
            print_error(f"Failed to hash email: {str(e)}")
            raise

    def verify_email_hash(self, email: str, hash_value: str) -> bool:
        """Verify if a hash matches an email address"""
        try:
            computed_hash = self.hash_email(email)
            matches = computed_hash == hash_value
            print_debug(f"Email hash verification: {'matched' if matches else 'failed'}")
            return matches

        except Exception as e:
            print_error(f"Failed to verify email hash: {str(e)}")
            raise
    def generate_certificate(
        self,
        common_name: str,
        organization: str,
        country: str,
        validity_days: int = Config.CERTIFICATE_VALIDITY_DAYS
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generate a new certificate signed by the Root CA"""

        print_header(f"Generating Certificate for {common_name}")
        try:
            # Verify Root CA exists
            self._verify_root_ca()

            # Generate RSA private key
            print_info(f"Generating RSA private key (size: {Config.RSA_KEY_SIZE} bits)...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=Config.RSA_KEY_SIZE
            )
            print_success("RSA Private key generated")

            # Create certificate signing request (CSR)
            print_info("Generating Certificate Signing Request (CSR)...")
            csr = self._create_csr(private_key, common_name, organization, country)
            print_success("CSR generated successfully")

            # Load Root CA credentials
            root_private_key, root_certificate = self._load_root_ca_credentials()
            print_success("Root CA credentials loaded")

            # Generate certificate
            print_info("Generating certificate...")
            certificate = self._create_certificate(
                csr,
                root_private_key,
                root_certificate,
                validity_days
            )
            print_success("Certificate generated successfully")

            # Save certificate and private key
            self._save_certificate_files(
                certificate,
                private_key,
                common_name
            )

            # Update certificates dictionary
            self._update_certificate_record(
                common_name,
                organization,
                country,
                certificate,
                private_key
            )

            return certificate, private_key

        except Exception as e:
            print_error(f"Certificate generation failed: {str(e)}")
            raise

    def _verify_root_ca(self) -> None:
        """Verify Root CA exists and is valid"""
        root_key_path = os.path.join(self.root_ca_path, "rootCA.key")
        root_cert_path = os.path.join(self.root_ca_path, "rootCA.crt")

        if not os.path.exists(root_key_path) or not os.path.exists(root_cert_path):
            raise FileNotFoundError("Root CA credentials not found. Please set up the Root CA first.")

    def _create_csr(
        self,
        private_key: rsa.RSAPrivateKey,
        common_name: str,
        organization: str,
        country: str
    ) -> x509.CertificateSigningRequest:
        """Create a Certificate Signing Request"""
        return x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            ])
        ).sign(private_key, hashes.SHA256())

    def _load_root_ca_credentials(self) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Load Root CA private key and certificate"""
        try:
            with open(os.path.join(self.root_ca_path, "rootCA.key"), "rb") as key_file:
                root_private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )

            with open(os.path.join(self.root_ca_path, "rootCA.crt"), "rb") as cert_file:
                root_certificate = x509.load_pem_x509_certificate(cert_file.read())

            return root_private_key, root_certificate

        except Exception as e:
            print_error(f"Failed to load Root CA credentials: {str(e)}")
            raise

    def _create_certificate(
        self,
        csr: x509.CertificateSigningRequest,
        root_private_key: rsa.RSAPrivateKey,
        root_certificate: x509.Certificate,
        validity_days: int
    ) -> x509.Certificate:
        """Create a certificate from CSR"""
        return x509.CertificateBuilder().subject_name(
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
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(root_private_key, hashes.SHA256())

    def _save_certificate_files(
        self,
        certificate: x509.Certificate,
        private_key: rsa.RSAPrivateKey,
        common_name: str
    ) -> None:
        """Save certificate and private key to files"""
        try:
            cert_path = os.path.join(self.cert_storage_path, f"{common_name}.crt")
            key_path = os.path.join(self.cert_storage_path, f"{common_name}.key")

            with open(cert_path, "wb") as cert_file:
                cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

            with open(key_path, "wb") as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            print_success(f"Certificate and private key saved to {self.cert_storage_path}")

        except Exception as e:
            print_error(f"Failed to save certificate files: {str(e)}")
            raise

    def _update_certificate_record(
        self,
        common_name: str,
        organization: str,
        country: str,
        certificate: x509.Certificate,
        private_key: rsa.RSAPrivateKey
    ) -> None:
        """Update the certificates dictionary with new certificate information"""
        try:
            self.certificates[common_name] = {
                'organization': organization,
                'country': country,
                'creation_date': datetime.datetime.utcnow().isoformat(),
                'certificate': certificate.public_bytes(
                    serialization.Encoding.PEM
                ).decode("utf-8"),
                'private_key': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode("utf-8")
            }
            self.save_certificates()
            print_success(f"Certificate record updated for {common_name}")

        except Exception as e:
            print_error(f"Failed to update certificate record: {str(e)}")
            raise


    def store_certificate_in_xrp_ledger(
        self,
        certificate: x509.Certificate,
        email: str,
        retry_attempts: int = Config.MAX_RETRY_ATTEMPTS
    ) -> List[str]:
        """Store certificate in XRP Ledger using chunked data"""
        print_header(f"Storing Certificate for {email} in XRP Ledger")

        try:
            # Verify sufficient balance
            balance = self.xrpl_manager.check_balance()
            print_info(f"Current balance: {balance} XRP")

            if balance < Config.MIN_XRP_BALANCE:
                raise ValueError(f"Insufficient XRP balance. Required: {Config.MIN_XRP_BALANCE}, Available: {balance}")

            # Create email hash
            email_hash = self.hash_email(email)
            print_info(f"Generated email hash: {email_hash}")

            # Prepare certificate data
            cert_data = self._prepare_certificate_data(certificate)
            print_info(f"Certificate prepared for storage: {len(cert_data)} bytes")

            # Split into chunks
            chunks = self._split_into_chunks(cert_data)
            print_info(f"Certificate split into {len(chunks)} chunks")

            # Store chunks
            return self._store_chunks(chunks, email_hash, retry_attempts)

        except Exception as e:
            print_error(f"Failed to store certificate: {str(e)}")
            raise

    def _prepare_certificate_data(self, certificate: x509.Certificate) -> str:
        """Prepare certificate data for storage"""
        try:
            # Convert to PEM format
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
            print_info(f"Original certificate size: {len(cert_pem)} bytes")

            # Compress data
            compressed_cert = gzip.compress(cert_pem, compresslevel=9)
            print_info(f"Compressed certificate size: {len(compressed_cert)} bytes")

            # Encode to base64
            compressed_cert_b64 = base64.b64encode(compressed_cert).decode('utf-8')
            print_info(f"Base64 encoded certificate size: {len(compressed_cert_b64)} bytes")

            return compressed_cert_b64

        except Exception as e:
            print_error(f"Failed to prepare certificate data: {str(e)}")
            raise

    def _split_into_chunks(self, data: str) -> List[str]:
        """Split data into chunks of specified size"""
        return [data[i:i + Config.CHUNK_SIZE] for i in range(0, len(data), Config.CHUNK_SIZE)]

    def _store_chunks(
        self,
        chunks: List[str],
        email_hash: str,
        retry_attempts: int
    ) -> List[str]:
        """Store chunks in XRP Ledger with retry mechanism"""
        tx_hashes = []

        for idx, chunk in enumerate(chunks):
            attempt = 0
            while attempt < retry_attempts:
                try:
                    tx_hash = self._store_single_chunk(chunk, idx, len(chunks), email_hash)
                    tx_hashes.append(tx_hash)
                    print_success(f"Chunk {idx + 1}/{len(chunks)} stored successfully")
                    break
                except Exception as e:
                    attempt += 1
                    if attempt == retry_attempts:
                        raise
                    print_warning(f"Attempt {attempt}/{retry_attempts} failed: {str(e)}")
                    time.sleep(Config.RETRY_DELAY)

            # Wait between chunks to avoid rate limiting
            if idx < len(chunks) - 1:
                time.sleep(Config.TRANSACTION_WAIT_TIME)

        return tx_hashes

    def _store_single_chunk(
        self,
        chunk: str,
        chunk_index: int,
        total_chunks: int,
        email_hash: str
    ) -> str:
        """Store a single chunk in XRP Ledger"""
        memo_data = {
            'email_hash': email_hash,
            'chunk_index': chunk_index,
            'total_chunks': total_chunks,
            'cert_data': chunk,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }

        memo_json = json.dumps(memo_data)
        print_debug(f"Chunk {chunk_index + 1} memo size: {len(memo_json)} bytes")

        memo_hex = str_to_hex(memo_json)
        memo = Memo(
            memo_data=memo_hex,
            memo_format=str_to_hex("text/plain"),
            memo_type=str_to_hex(f"certificate_chunk_{chunk_index}")
        )

        transaction = AccountSet(
            account=self.xrpl_manager.wallet.classic_address,
            memos=[memo]
        )

        result = submit_and_wait(
            transaction=transaction,
            client=self.xrpl_manager.client,
            wallet=self.xrpl_manager.wallet
        )

        if not result.is_successful():
            raise Exception(f"Transaction failed: {result.result}")

        return result.result['hash']

    def retrieve_certificate_from_xrp_ledger(
        self,
        email: str,
        retry_attempts: int = Config.MAX_RETRY_ATTEMPTS
    ) -> x509.Certificate:
        """Retrieve certificate from XRP Ledger"""
        print_header(f"Retrieving Certificate for {email}")

        try:
            email_hash = self.hash_email(email)
            print_info(f"Searching for certificate with email hash: {email_hash}")

            # Retrieve transactions
            chunks = self._retrieve_certificate_chunks(email_hash, retry_attempts)

            # Reconstruct certificate
            cert_data = self._reconstruct_certificate(chunks)

            # Convert back to certificate object
            return self._bytes_to_certificate(cert_data)

        except Exception as e:
            print_error(f"Failed to retrieve certificate: {str(e)}")
            raise

    def _retrieve_certificate_chunks(
        self,
        email_hash: str,
        retry_attempts: int
    ) -> Dict[int, str]:
        """Retrieve all certificate chunks from XRP Ledger"""
        chunks = {}
        total_chunks = None
        attempt = 0

        while attempt < retry_attempts:
            try:
                request = AccountTx(
                    account=self.xrpl_manager.wallet.classic_address,
                    ledger_index_min=-1,
                    ledger_index_max=-1,
                    limit=100
                )

                response = self.xrpl_manager.client.request(request)
                transactions = response.result.get("transactions", [])
                print_info(f"Processing {len(transactions)} transactions...")

                chunks, total_chunks = self._process_transactions(
                    transactions,
                    email_hash,
                    chunks,
                    total_chunks
                )

                if total_chunks is not None and len(chunks) == total_chunks:
                    break

                attempt += 1
                if attempt == retry_attempts:
                    raise ValueError(f"Certificate chunks incomplete: {len(chunks)}/{total_chunks}")

                print_warning(f"Attempt {attempt}/{retry_attempts}: Missing chunks")
                time.sleep(Config.RETRY_DELAY)

            except Exception as e:
                print_error(f"Error retrieving chunks: {str(e)}")
                raise

        return chunks

    def _process_transactions(
        self,
        transactions: List[Dict],
        email_hash: str,
        chunks: Dict[int, str],
        total_chunks: Optional[int]
    ) -> Tuple[Dict[int, str], Optional[int]]:
        """Process transactions to extract certificate chunks"""
        for tx in transactions:
            tx_data = tx.get("tx_json", {}) if isinstance(tx, dict) else tx.tx_json
            memos = tx_data.get("Memos", [])

            for memo in memos:
                try:
                    memo_data = memo.get("Memo", {}).get("MemoData", "")
                    if not memo_data:
                        continue

                    memo_str = ''.join([chr(int(memo_data[i:i+2], 16))
                                    for i in range(0, len(memo_data), 2)])
                    memo_json = json.loads(memo_str)

                    if memo_json.get('email_hash') != email_hash:
                        continue

                    chunk_index = memo_json.get('chunk_index')
                    current_total_chunks = memo_json.get('total_chunks')
                    cert_data = memo_json.get('cert_data')

                    if None in (chunk_index, current_total_chunks, cert_data):
                        continue

                    if total_chunks is None:
                        total_chunks = current_total_chunks
                    elif total_chunks != current_total_chunks:
                        print_warning(f"Inconsistent total chunks: {total_chunks} != {current_total_chunks}")
                        continue

                    chunks[chunk_index] = cert_data
                    print_info(f"Found chunk {chunk_index + 1} of {total_chunks}")

                except Exception as e:
                    print_warning(f"Error processing memo: {str(e)}")
                    continue

        return chunks, total_chunks

    def _reconstruct_certificate(self, chunks: Dict[int, str]) -> bytes:
        """Reconstruct certificate from chunks"""
        try:
            # Combine chunks
            combined_b64 = ''
            for i in range(len(chunks)):
                if i not in chunks:
                    raise ValueError(f"Missing chunk {i}")
                combined_b64 += chunks[i]

            # Decode and decompress
            compressed_data = base64.b64decode(combined_b64)
            decompressed_cert = gzip.decompress(compressed_data)

            print_success("Certificate successfully reconstructed")
            return decompressed_cert

        except Exception as e:
            print_error(f"Failed to reconstruct certificate: {str(e)}")
            raise

    def _bytes_to_certificate(self, cert_bytes: bytes) -> x509.Certificate:
        """Convert bytes to certificate object"""
        try:
            certificate = x509.load_pem_x509_certificate(cert_bytes)
            print_success("Certificate successfully loaded")
            return certificate

        except Exception as e:
            print_error(f"Failed to convert bytes to certificate: {str(e)}")
            raise

    def encrypt_message(
        self,
        message: str,
        certificate: x509.Certificate,
        chunk_size: int = 190  # Maximum size for RSA-2048 with OAEP padding
    ) -> bytes:
        """Encrypt a message using the certificate's public key"""
        print_header(f"Encrypting Message (length: {len(message)})")
        try:
            public_key = certificate.public_key()

            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Certificate does not contain an RSA public key")

            # For longer messages, split into chunks and encrypt each chunk
            message_bytes = message.encode()
            chunks = [message_bytes[i:i+chunk_size] for i in range(0, len(message_bytes), chunk_size)]

            encrypted_chunks = []
            for idx, chunk in enumerate(chunks):
                print_info(f"Encrypting chunk {idx + 1}/{len(chunks)}")
                encrypted_chunk = public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_chunks.append(encrypted_chunk)

            # Combine encrypted chunks
            result = len(encrypted_chunks).to_bytes(4, byteorder='big')
            for chunk in encrypted_chunks:
                result += len(chunk).to_bytes(4, byteorder='big') + chunk

            print_success("Message encrypted successfully")
            return result

        except Exception as e:
            print_error(f"Encryption failed: {str(e)}")
            raise

    def decrypt_message(
        self,
        ciphertext: bytes,
        common_name: str
    ) -> str:
        """Decrypt a message using the private key"""
        print_header(f"Decrypting Message for {common_name}")
        try:
            if common_name not in self.certificates:
                raise ValueError(f"No private key found for {common_name}")

            # Load private key
            private_key_pem = self.certificates[common_name]['private_key']
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )

            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("Stored key is not an RSA private key")

            # Extract number of chunks
            num_chunks = int.from_bytes(ciphertext[:4], byteorder='big')
            print_info(f"Decrypting {num_chunks} chunks")

            # Extract and decrypt each chunk
            pos = 4
            decrypted_chunks = []
            for i in range(num_chunks):
                chunk_size = int.from_bytes(ciphertext[pos:pos+4], byteorder='big')
                pos += 4
                encrypted_chunk = ciphertext[pos:pos+chunk_size]
                pos += chunk_size

                print_info(f"Decrypting chunk {i + 1}/{num_chunks}")
                decrypted_chunk = private_key.decrypt(
                    encrypted_chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted_chunk)

            # Combine decrypted chunks
            result = b''.join(decrypted_chunks).decode()
            print_success("Message decrypted successfully")
            return result

        except Exception as e:
            print_error(f"Decryption failed: {str(e)}")
            raise

def setup_root_ca() -> None:
    """Set up Root CA if it doesn't exist"""
    print_header("Setting up Root CA")
    try:
        root_cred_path = "root_cred"
        os.makedirs(root_cred_path, exist_ok=True)

        root_key_path = os.path.join(root_cred_path, "rootCA.key")
        root_cert_path = os.path.join(root_cred_path, "rootCA.crt")

        if os.path.exists(root_key_path) and os.path.exists(root_cert_path):
            print_info("Root CA already exists")
            return

        print_info("Generating Root CA credentials...")

        # Generate Root CA private key
        root_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096  # Using 4096 bits for Root CA
        )
        print_success("Root CA private key generated")

        # Generate Root CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"XRP Ledger Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"XRP Certificate Authority"),
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
            datetime.datetime.utcnow() + datetime.timedelta(days=Config.ROOT_CA_VALIDITY_DAYS)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(root_key, hashes.SHA256())

        print_success("Root CA certificate generated")

        # Save Root CA private key and certificate
        with open(root_key_path, "wb") as f:
            f.write(root_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(root_cert_path, "wb") as f:
            f.write(root_cert.public_bytes(serialization.Encoding.PEM))

        print_success("Root CA credentials saved successfully")

    except Exception as e:
        print_error(f"Root CA setup failed: {str(e)}")
        raise

def main():
    """Main execution flow"""
    try:
        print_header("XRP Ledger Certificate Management System")

        # Setup Root CA
        # setup_root_ca()

        # Initialize XRP Ledger connection
        print_header("Initializing XRP Ledger Connection")
        xrpl_manager = XRPLedgerManager(is_testnet=True)

        # Check initial balance
        initial_balance = xrpl_manager.check_balance()
        print_info(f"Initial balance: {initial_balance} XRP")

        # Initialize Certificate Manager
        cert_manager = CertificateManager(xrpl_manager)

        # Example usage
        print_header("Certificate Management Demo")

        # Generate test certificate
        common_name = "new2@example.com"
        organization = "new2 Organization"
        country = "IE"

        certificate, private_key = cert_manager.generate_certificate(
            common_name,
            organization,
            country
        )

        # Store certificate in XRP Ledger
        tx_hashes = cert_manager.store_certificate_in_xrp_ledger(
            certificate,
            common_name
        )
        print_success(f"Certificate stored in {len(tx_hashes)} transactions")

        # Wait for transactions to be processed
        time.sleep(Config.TRANSACTION_WAIT_TIME * 2)

        # Retrieve certificate
        retrieved_cert = cert_manager.retrieve_certificate_from_xrp_ledger(common_name)
        print_success("Certificate retrieved successfully")

        # Verify certificate contents
        print_info("Certificate Details:")
        print_info(f"Common Name: {retrieved_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        print_info(f"Organization: {retrieved_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value}")
        print_info(f"Country: {retrieved_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value}")

        # Test encryption/decryption
        test_message = "Hello, XRP Ledger Certificate Management System!"
        print_header("Testing Encryption/Decryption")

        encrypted_message = cert_manager.encrypt_message(test_message, retrieved_cert)
        print_success("Message encrypted")

        decrypted_message = cert_manager.decrypt_message(encrypted_message, common_name)
        print_success("Message decrypted")

        print_info(f"Original message: {test_message}")
        print_info(f"Encrypted message: {encrypted_message}")
        print_info(f"Decrypted message: {decrypted_message}")

        # Verify message integrity
        if test_message == decrypted_message:
            print_success("Message integrity verified")
        else:
            print_error("Message integrity check failed")

        # Check final balance
        final_balance = xrpl_manager.check_balance()
        print_header("Transaction Summary")
        print_info(f"Initial balance: {initial_balance} XRP")
        print_info(f"Final balance: {final_balance} XRP")
        print_info(f"Total XRP spent: {initial_balance - final_balance} XRP")

    except Exception as e:
        print_error(f"Program execution failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()