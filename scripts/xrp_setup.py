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
                    'public_key': self.wallet.public_key,
                    'private_key': self.wallet.private_key,
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