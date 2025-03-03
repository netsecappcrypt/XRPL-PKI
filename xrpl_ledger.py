import xrpl
from xrpl.clients import JsonRpcClient
from xrpl.wallet import generate_faucet_wallet, Wallet
from xrpl.models.requests import AccountInfo
from xrpl.models.transactions import AccountSet, Memo
from xrpl.utils import drops_to_xrp
from xrpl.transaction import submit_and_wait, sign_and_submit

from xrpl.models.requests import AccountTx
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

class XRPLedgerManager:
    """
    A class to manage interactions with the XRP Ledger, including wallet creation,
    balance checking, and storing/retrieving data using memos.
    """
    def __init__(self, network_url="https://s.altnet.rippletest.net:51234"):
        """
        Initialize the XRPLedgerManager with a connection to the XRP Testnet.
        """
        print("[INFO] Connecting to XRP Testnet...")
        self.client = JsonRpcClient(network_url)
        self.wallet = None
        self.wallet_file = "xrp_wallet.json"
        self._initialize_wallet()

    def _initialize_wallet(self):
        """
        Load an existing wallet from a file or create a new one if it doesn't exist.
        """
        try:
            if os.path.exists(self.wallet_file):
                print("[INFO] Wallet file found. Loading wallet...")
                with open(self.wallet_file, 'r') as f:
                    wallet_data = json.load(f)
                    self.wallet = Wallet.from_seed(wallet_data['seed'])
                print(f"[SUCCESS] Wallet loaded. Address: {self.wallet.classic_address}")
            else:
                print("[INFO] Wallet file not found. Creating a new wallet...")
                self.wallet = generate_faucet_wallet(self.client)
                self._save_wallet()
                print(f"[SUCCESS] New wallet created. Address: {self.wallet.classic_address}")
                print("[INFO] Waiting for faucet funding...")
                time.sleep(5)  # Wait for the faucet to fund the wallet
        except Exception as e:
            print(f"[ERROR] Failed to initialize wallet: {str(e)}")
            raise

    def _save_wallet(self):
        """
        Save the wallet details (seed and address) to a file for future use.
        """
        try:
            wallet_data = {
                'seed': self.wallet.seed,
                'classic_address': self.wallet.classic_address
            }

            # Only add these if they're bytes objects, not strings
            if hasattr(self.wallet, 'public_key') and not isinstance(self.wallet.public_key, str):
                wallet_data['public_key'] = self.wallet.public_key.hex()

            if hasattr(self.wallet, 'private_key') and not isinstance(self.wallet.private_key, str):
                wallet_data['private_key'] = self.wallet.private_key.hex()

            with open(self.wallet_file, 'w') as f:
                json.dump(wallet_data, f, indent=4)
            print("[INFO] Wallet details saved to file.")
        except Exception as e:
            print(f"[ERROR] Failed to save wallet: {str(e)}")
            raise
            
    def get_balance(self):
        """
        Check the XRP balance of the wallet.
        Returns:
            float: The balance in XRP.
        """
        try:
            print("[INFO] Checking wallet balance...")
            acct_info = AccountInfo(
                account=self.wallet.classic_address,
                ledger_index="validated"
            )
            response = self.client.request(acct_info)
            balance = drops_to_xrp(response.result['account_data']['Balance'])
            print(f"[SUCCESS] Wallet balance: {balance} XRP")
            return float(balance)
        except Exception as e:
            print(f"[ERROR] Failed to retrieve balance: {str(e)}")
            raise

    def store_data(self, data, memo_type="certificate"):
        """
        Store data in the XRP Ledger using memos.
        Args:
            data (str): The data to store.
            memo_type (str): The type of memo (default is "certificate").
        Returns:
            str: The transaction hash of the submitted transaction.
        """
        try:
            print("[INFO] Preparing to store data in the XRP Ledger...")

            # Check balance before proceeding
            balance = self.get_balance()
            if balance < 1:
                raise ValueError("Insufficient XRP balance")

            memo = Memo(
                memo_data=self._str_to_hex(data),
                memo_format=self._str_to_hex("text/plain"),
                memo_type=self._str_to_hex(memo_type)
            )

            transaction = AccountSet(
                account=self.wallet.classic_address,
                memos=[memo]
            )

            print("[INFO] Preparing transaction...")
            # Prepare the transaction (autofill)
            from xrpl.transaction import autofill
            prepared_tx = autofill(transaction, self.client)

            print("[INFO] Signing transaction...")
            # Sign the transaction
            from xrpl.transaction import sign
            signed_tx = sign(prepared_tx, self.wallet)

            print("[INFO] Submitting transaction...")
            # Submit the transaction
            from xrpl.transaction import submit
            response = submit(signed_tx, self.client)

            if response.is_successful():
                tx_hash = response.result.get("hash", "")
                print(f"[SUCCESS] Transaction submitted. Hash: {tx_hash}")

                print("[INFO] Waiting for validation...")
                # Wait for validation (optional)
                import time
                time.sleep(5)  # Simple wait, or implement a more sophisticated check

                return tx_hash
            else:
                error_message = response.result.get("engine_result_message", str(response.result))
                raise Exception(f"Transaction submission failed: {error_message}")

        except Exception as e:
            print(f"[ERROR] Failed to store data: {str(e)}")
            raise

    def retrieve_data(self, memo_type="certificate"):
        """
        Retrieve data from the XRP Ledger by memo type.
        Args:
            memo_type (str): The type of memo to search for (default is "certificate").
        Returns:
            list: A list of data strings retrieved from the ledger.
        """
        try:
            print("[INFO] Retrieving data from the XRP Ledger...")
            request = AccountTx(
                account=self.wallet.classic_address,
                ledger_index_min=-1,
                ledger_index_max=-1,
                limit=20
            )

            response = self.client.request(request)
            result = response.result if hasattr(response, 'result') else response
            transactions = result.get("transactions", [])

            if not transactions:
                print("[INFO] No transactions found")
                return []

            print(f"[INFO] Found {len(transactions)} transactions. Processing memos...")

            data_list = []

            for tx in transactions:
                tx_data = tx.get("tx_json", {}) if isinstance(tx, dict) else tx.get("tx", {})
                memos = tx_data.get("Memos", [])

                for memo in memos:
                    try:
                        if isinstance(memo, dict):
                            memo_type_hex = memo.get("Memo", {}).get("MemoType", "")
                            memo_data_hex = memo.get("Memo", {}).get("MemoData", "")
                        else:
                            memo_type_hex = getattr(getattr(memo, "Memo", {}), "MemoType", "")
                            memo_data_hex = getattr(getattr(memo, "Memo", {}), "MemoData", "")

                        if memo_type_hex and memo_data_hex:
                            # Convert hex to string
                            memo_type_str = self._hex_to_str(memo_type_hex)

                            if memo_type_str == memo_type:
                                memo_data_str = self._hex_to_str(memo_data_hex)
                                data_list.append(memo_data_str)
                    except Exception as memo_error:
                        print(f"[INFO] Error processing memo: {str(memo_error)}")
                        continue

            print(f"[SUCCESS] Retrieved {len(data_list)} data entries from the ledger.")
            return data_list
        except Exception as e:
            print(f"[ERROR] Failed to retrieve data: {str(e)}")
            raise

    def _str_to_hex(self, s):
        """
        Convert a string to a hex string.
        Args:
            s (str): The string to convert.
        Returns:
            str: The hex representation of the string.
        """
        return s.encode().hex()

    def _hex_to_str(self, h):
        """
        Convert a hex string back to a regular string.
        Args:
            h (str): The hex string to convert.
        Returns:
            str: The decoded string.
        """
        try:
            return bytes.fromhex(h).decode('utf-8')
        except Exception:
            # Fallback for handling different hex formats
            return ''.join([chr(int(h[i:i+2], 16)) for i in range(0, len(h), 2)])

class CertificateEncoder:
    """
    A utility class for encoding, compressing, and hashing certificates.
    """
    @staticmethod
    def compress_cert(cert_pem):
        """
        Compress a certificate using gzip.
        Args:
            cert_pem (bytes): The PEM-encoded certificate.
        Returns:
            bytes: The compressed certificate.
        """
        print("[INFO] Compressing certificate...")
        return gzip.compress(cert_pem)

    @staticmethod
    def decompress_cert(compressed_cert):
        """
        Decompress a certificate.
        Args:
            compressed_cert (bytes): The compressed certificate.
        Returns:
            bytes: The decompressed certificate.
        """
        print("[INFO] Decompressing certificate...")
        return gzip.decompress(compressed_cert)

    @staticmethod
    def encode_for_ledger(data):
        """
        Encode data for storage in the XRP Ledger.
        Args:
            data (bytes): The data to encode.
        Returns:
            str: The Base64-encoded string.
        """
        print("[INFO] Encoding data for ledger storage...")
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def decode_from_ledger(encoded_data):
        """
        Decode data retrieved from the XRP Ledger.
        Args:
            encoded_data (str): The Base64-encoded string.
        Returns:
            bytes: The decoded data.
        """
        print("[INFO] Decoding data from ledger...")
        return base64.b64decode(encoded_data)

    @staticmethod
    def hash_email(email):
        """
        Hash an email address using SHA-256.
        Args:
            email (str): The email address to hash.
        Returns:
            str: The SHA-256 hash of the email.
        """
        print("[INFO] Hashing email address...")
        return hashlib.sha256(email.encode()).hexdigest()