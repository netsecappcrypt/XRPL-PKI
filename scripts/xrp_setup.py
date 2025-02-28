import json
import os
import sys
import traceback
from xrpl.clients import JsonRpcClient
from xrpl.wallet import generate_faucet_wallet, Wallet
from xrpl.models.requests import AccountInfo
from xrpl.utils import drops_to_xrp
import time

# ANSI color codes for output
class Colors:
    SUCCESS = '\033[92m'
    ERROR = '\033[91m'
    INFO = '\033[94m'
    DEBUG = '\033[95m'
    END = '\033[0m'

def print_success(message):
    print(f"{Colors.SUCCESS}✓ {message}{Colors.END}")

def print_error(message):
    print(f"{Colors.ERROR}✖ {message}{Colors.END}")

def print_info(message):
    print(f"{Colors.INFO}ℹ {message}{Colors.END}")

def print_debug(message):
    print(f"{Colors.DEBUG}🔍 DEBUG: {message}{Colors.END}")

class XRPLManager:
    def __init__(self):
        print("\n=== Initializing XRP Ledger Connection ===\n")
        try:
            self.client = JsonRpcClient("https://s.altnet.rippletest.net:51234/")
            print_debug("XRPL Client initialized successfully")
        except Exception as e:
            print_error(f"Failed to initialize XRPL Client: {str(e)}")
            raise
        self.wallet = None
        self.wallet_file = "xrp_wallet.json"
        self.setup_wallet()

    def setup_wallet(self):
        """Set up the XRP wallet, either loading existing or creating new"""
        try:
            if os.path.exists(self.wallet_file):
                print_info("Loading existing wallet...")
                with open(self.wallet_file, 'r') as f:
                    wallet_data = json.load(f)
                self.wallet = Wallet(seed=wallet_data['seed'])
                print_success(f"Wallet loaded successfully: {self.wallet.classic_address}")
            else:
                print_info("Creating new XRP Testnet wallet...")
                self.create_new_wallet()
        except Exception as e:
            print_error(f"Error setting up wallet: {str(e)}")
            print_debug(f"Full traceback: {traceback.format_exc()}")
            raise

    def create_new_wallet(self):
        """Create a new XRP Testnet wallet"""
        try:
            print_debug("Attempting to generate faucet wallet...")
            self.wallet = generate_faucet_wallet(self.client, debug=True)
            print_debug(f"Wallet generated with address: {self.wallet.classic_address}")

            # Save wallet details to file
            wallet_data = {
                'seed': self.wallet.seed,
                'public_key': self.wallet.public_key,
                'private_key': self.wallet.private_key,
                'classic_address': self.wallet.classic_address
            }

            print_debug("Saving wallet details to file...")
            with open(self.wallet_file, 'w') as f:
                json.dump(wallet_data, f, indent=4)

            print_success(f"New wallet created and funded: {self.wallet.classic_address}")
            print_info("Waiting for faucet transaction to complete...")
            time.sleep(5)

        except Exception as e:
            print_error(f"Error creating new wallet: {str(e)}")
            print_debug(f"Full traceback: {traceback.format_exc()}")
            raise

    def check_balance(self):
        """Check the XRP balance of the wallet"""
        try:
            print_debug("Requesting account info...")
            acct_info = AccountInfo(
                account=self.wallet.classic_address,
                ledger_index="validated"
            )
            response = self.client.request(acct_info)
            balance = drops_to_xrp(response.result['account_data']['Balance'])
            print_info(f"Current balance: {balance} XRP")
            return float(balance)
        except Exception as e:
            print_error(f"Error checking balance: {str(e)}")
            print_debug(f"Full traceback: {traceback.format_exc()}")
            return 0

def main():
    try:
        print_debug(f"Python version: {sys.version}")
        print_debug("Starting XRPL setup...")

        # Initialize XRPL connection and wallet
        xrpl_manager = XRPLManager()

        # Check the balance
        balance = xrpl_manager.check_balance()

        if balance > 0:
            print_success(f"Setup completed successfully with {balance} XRP")
        else:
            print_error("Wallet has no balance")

    except Exception as e:
        print_error(f"Main execution failed: {str(e)}")
        print_debug(f"Full traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    main()