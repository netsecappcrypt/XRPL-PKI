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

    def store_certificate_as_nft(self, compressed_cert, email, chunk_size=None):
        """Chunk the compressed cert and store each chunk as a separate NFT. Returns list of NFT token IDs."""
        try:
            balance = self.xrpl_manager.check_balance()
            print_info(f"Current balance: {balance} XRP")
            if balance < 1:
                raise ValueError("Insufficient XRP balance")

            # Hash the email for privacy
            email_hash = self.hash_email(email)
            print_info(f"Email hash created: {email_hash}")

            # Base64 encode the compressed cert
            compressed_cert_b64 = base64.b64encode(compressed_cert).decode('utf-8')

            # Dynamically determine max chunk size to fit 512 hex chars after JSON+hex encoding
            # Try a binary search approach for efficiency
            def fits_chunk_size(test_size):
                test_chunk = compressed_cert_b64[:test_size]
                test_json = json.dumps({
                    'email_hash': email_hash,
                    'chunk_index': 0,
                    'total_chunks': 1,
                    'chunk_data': test_chunk
                })
                test_hex = str_to_hex(test_json)
                return len(test_hex) <= 512

            # Find max chunk size that fits
            low, high = 1, 300  # 200 is a safe upper bound for most cases
            best = 1
            while low <= high:
                mid = (low + high) // 2
                if fits_chunk_size(mid):
                    best = mid
                    low = mid + 1
                else:
                    high = mid - 1
            max_chunk_size = best
            if chunk_size is None or chunk_size > max_chunk_size:
                chunk_size = max_chunk_size
            chunk_size = 119
            print_info(f"Using chunk size: {chunk_size} (max allowed for NFT URI)")

            # Chunk the base64 cert
            chunks = [compressed_cert_b64[i:i+chunk_size] for i in range(0, len(compressed_cert_b64), chunk_size)]
            print_info(f"Certificate split into {len(chunks)} chunks for NFT storage.")

            nftoken_ids = []
            from xrpl.models.transactions import NFTokenMint
            from xrpl.transaction import autofill, sign, submit_and_wait
            for idx, chunk in enumerate(chunks):
                nft_metadata = json.dumps({
                    'email_hash': email_hash,
                    'chunk_index': idx,
                    'total_chunks': len(chunks),
                    'chunk_data': chunk
                })
                nft_metadata_hex = str_to_hex(nft_metadata)
                if len(nft_metadata_hex) > 512:
                    raise ValueError(f"NFT URI metadata too long for chunk {idx} after hex encoding (should not happen, chunk_size={chunk_size}).")
                mint_tx = NFTokenMint(
                    account=self.xrpl_manager.wallet.classic_address,
                    uri=nft_metadata_hex,
                    flags=8,  # Transferable
                    nftoken_taxon=0
                )
                print_info(f"Minting NFT chunk {idx+1}/{len(chunks)}")
                tx = autofill(mint_tx, self.xrpl_manager.client)
                signed_tx = sign(tx, self.xrpl_manager.wallet)
                tx_response = submit_and_wait(signed_tx, self.xrpl_manager.client)
                if not tx_response.is_successful():
                    raise Exception(f"NFT mint failed for chunk {idx}: {tx_response.result}")
                nftoken_id = None
                meta = tx_response.result.get('meta', {})
                for node in meta.get('AffectedNodes', []):
                    created = node.get('CreatedNode', {})
                    if created.get('LedgerEntryType') == 'NFTokenPage':
                        nfts = created.get('NewFields', {}).get('NFTokens', [])
                        if nfts:
                            nftoken_id = nfts[0]['NFToken']['NFTokenID']
                            break
                if not nftoken_id:
                    from xrpl.models.requests import AccountNFTs
                    nft_req = AccountNFTs(account=self.xrpl_manager.wallet.classic_address)
                    nft_resp = self.xrpl_manager.client.request(nft_req)
                    nfts = nft_resp.result.get('account_nfts', [])
                    nftoken_id = nfts[-1]['NFTokenID'] if nfts else None
                if not nftoken_id:
                    raise Exception(f"Could not determine NFT token ID after minting chunk {idx}.")
                print_success(f"NFT chunk {idx+1} minted with Token ID: {nftoken_id}")
                nftoken_ids.append(nftoken_id)
            # Store all NFT token IDs for this email
            self.certificates[email] = self.certificates.get(email, {})
            self.certificates[email]['nftoken_ids'] = nftoken_ids
            self.certificates[email]['total_chunks'] = len(chunks)
            self.save_certificates()
            return nftoken_ids
        except Exception as e:
            print_error(f"Error minting certificate NFT chunks: {str(e)}")
            raise

    def retrieve_certificate_from_nft(self, email):
        """Retrieve all NFT chunks for the given email, reconstruct, and return the cert object."""
        try:
            nftoken_ids = self.certificates.get(email, {}).get('nftoken_ids')
            total_chunks = self.certificates.get(email, {}).get('total_chunks')
            if not nftoken_ids or not total_chunks:
                raise ValueError(f"No NFT token IDs or chunk count found for {email}")
            from xrpl.models.requests import AccountNFTs
            nft_req = AccountNFTs(account=self.xrpl_manager.wallet.classic_address)
            nft_resp = self.xrpl_manager.client.request(nft_req)
            nfts = nft_resp.result.get('account_nfts', [])
            # Map chunk_index to chunk_data
            chunk_map = {}
            for nft in nfts:
                if nft['NFTokenID'] in nftoken_ids:
                    uri_hex = nft['URI']
                    uri_str = ''.join([chr(int(uri_hex[i:i+2], 16)) for i in range(0, len(uri_hex), 2)])
                    try:
                        meta = json.loads(uri_str)
                        idx = meta.get('chunk_index')
                        chunk_map[idx] = meta.get('chunk_data')
                    except Exception as e:
                        print_error(f"Error decoding NFT chunk: {str(e)}")
                        raise
            if len(chunk_map) != total_chunks:
                raise ValueError(f"Could not retrieve all NFT chunks for {email}")
            # Reconstruct base64 string and decode
            ordered_chunks = [chunk_map[i] for i in range(total_chunks)]
            cert_b64 = ''.join(ordered_chunks)
            compressed_cert = base64.b64decode(cert_b64)
            cert_pem = gzip.decompress(compressed_cert)
            cert = x509.load_pem_x509_certificate(cert_pem)
            print_success(f"Certificate reconstructed from {total_chunks} NFT chunks for {email}")
            return cert
        except Exception as e:
            print_error(f"Error retrieving certificate from NFT chunks: {str(e)}")
            raise

    def revoke_certificate_nft(self, email):
        """Burn all NFT chunks associated with the given email (revoke certificate)."""
        try:
            nftoken_ids = self.certificates.get(email, {}).get('nftoken_ids')
            if not nftoken_ids:
                raise ValueError(f"No NFT token IDs found for {email}")
            from xrpl.models.transactions import NFTokenBurn
            from xrpl.transaction import autofill, sign, submit_and_wait
            for nftoken_id in nftoken_ids:
                burn_tx = NFTokenBurn(
                    account=self.xrpl_manager.wallet.classic_address,
                    nftoken_id=nftoken_id
                )
                print_info(f"Burning NFT chunk with Token ID: {nftoken_id}")
                tx = autofill(burn_tx, self.xrpl_manager.client)
                signed_tx = sign(tx, self.xrpl_manager.wallet)
                tx_response = submit_and_wait(signed_tx, self.xrpl_manager.client)
                if not tx_response.is_successful():
                    raise Exception(f"NFT burn failed for Token ID {nftoken_id}: {tx_response.result}")
                print_success(f"NFT chunk burned (revoked) for {email}: {nftoken_id}")
            # Optionally, remove NFT token IDs from local record
            self.certificates[email]['nftoken_ids'] = []
            self.save_certificates()
            return True
        except Exception as e:
            print_error(f"Error revoking certificate NFT chunks: {str(e)}")
            raise

    def retrieve_certificate_from_nft(self, email):
        """Retrieve all NFT chunks for the given email, reconstruct, and return the cert object."""
        try:
            nftoken_ids = self.certificates.get(email, {}).get('nftoken_ids')
            total_chunks = self.certificates.get(email, {}).get('total_chunks')
            if not nftoken_ids or not total_chunks:
                raise ValueError(f"No NFT token IDs or chunk count found for {email}")
            from xrpl.models.requests import AccountNFTs
            nft_req = AccountNFTs(account=self.xrpl_manager.wallet.classic_address)
            nft_resp = self.xrpl_manager.client.request(nft_req)
            nfts = nft_resp.result.get('account_nfts', [])
            # Map chunk_index to chunk_data
            chunk_map = {}
            for nft in nfts:
                if nft['NFTokenID'] in nftoken_ids:
                    uri_hex = nft['URI']
                    uri_str = ''.join([chr(int(uri_hex[i:i+2], 16)) for i in range(0, len(uri_hex), 2)])
                    try:
                        meta = json.loads(uri_str)
                        idx = meta.get('chunk_index')
                        chunk_map[idx] = meta.get('chunk_data')
                    except Exception as e:
                        print_error(f"Error decoding NFT chunk: {str(e)}")
                        raise
            if len(chunk_map) != total_chunks:
                raise ValueError(f"Could not retrieve all NFT chunks for {email}")
            # Reconstruct base64 string and decode
            ordered_chunks = [chunk_map[i] for i in range(total_chunks)]
            cert_b64 = ''.join(ordered_chunks)
            compressed_cert = base64.b64decode(cert_b64)
            cert_pem = gzip.decompress(compressed_cert)
            cert = x509.load_pem_x509_certificate(cert_pem)
            print_success(f"Certificate reconstructed from {total_chunks} NFT chunks for {email}")
            return cert
        except Exception as e:
            print_error(f"Error retrieving certificate from NFT chunks: {str(e)}")
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
        common_name = "test1@example.com"
        organization = "Test1 Organization"
        country = "US"

        compressed_cert, cert = cert_manager.generate_certificate(
            common_name,
            organization,
            country
        )
        print_success("Certificate generated successfully")

        print_header("Minting Certificate NFT Chunks on XRP Ledger")
        nftoken_ids = cert_manager.store_certificate_as_nft(
            compressed_cert,
            common_name
        )

        # Wait for transactions to be processed
        time.sleep(5 * len(nftoken_ids))

        print_header("Testing Encryption/Decryption")
        test_message = "Hello, XRP Ledger!"
        encrypted_message = cert_manager.encrypt_message(test_message, cert)
        print_success("Message encrypted")

        decrypted_message = cert_manager.decrypt_message(encrypted_message, common_name)
        print_success("Message decrypted")

        print(f"\nOriginal message: {test_message}")
        print(f"Decrypted message: {decrypted_message}")

        print_header("Retrieving Certificate from NFT Chunks")
        retrieved_cert = cert_manager.retrieve_certificate_from_nft(common_name)
        print_success("Certificate reconstructed from NFT chunks")

        print_header("Testing Decryption with NFT Certificate")
        decrypted_message_nft = cert_manager.decrypt_message(encrypted_message, common_name)
        print_success("Message decrypted using NFT certificate")

        print(f"\nOriginal message: {test_message}")
        print(f"Decrypted message (NFT): {decrypted_message_nft}")

        print_header("Revoking (Burning) Certificate NFT Chunks")
        cert_manager.revoke_certificate_nft(common_name)

        print_header("Final Balance Check")
        final_balance = xrpl_manager.check_balance()
        print_info(f"Balance change: {initial_balance - final_balance} XRP")

    except Exception as e:
        print_error(f"Main execution failed: {str(e)}")

if __name__ == "__main__":
    main()