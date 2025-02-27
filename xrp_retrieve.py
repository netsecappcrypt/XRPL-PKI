import json
import base64
import gzip
from xrpl.clients import JsonRpcClient
from xrpl.models.requests import Tx

class Colors:
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    ERROR = '\033[91m'
    END = '\033[0m'

def print_info(msg): print(f"{Colors.INFO}ℹ {msg}{Colors.END}")
def print_success(msg): print(f"{Colors.SUCCESS}✓ {msg}{Colors.END}")
def print_error(msg): print(f"{Colors.ERROR}✖ {msg}{Colors.END}")

WALLET_ADDRESS = "r4YMnv8wCJyoE52ZJdnj1G8YeUG2SCUF86"
TRANSACTION_HASH = "06DD7609DC5624074A8F2B9756CBD7200668EA9DB72CCD69F21BC4E907E425DE"

def hex_to_str(hex_str):
    """Convert hex string to regular string"""
    try:
        # Remove '0x' prefix if present
        hex_str = hex_str.replace('0x', '')
        # Convert hex to bytes and then to string
        return bytes.fromhex(hex_str).decode('utf-8')
    except Exception as e:
        print_error(f"Error converting hex to string: {str(e)}")
        return None

def extract_certificate_from_memo(memo):
    """Extract and decode certificate data from memo"""
    try:
        # Convert memo data from hex to string
        memo_str = hex_to_str(memo.get('Memo', {}).get('MemoData', ''))
        if not memo_str:
            return None

        # Parse the JSON string
        memo_data = json.loads(memo_str)
        print_info("Memo data decoded successfully")
        print("\nMemo Contents:")
        print(json.dumps(memo_data, indent=2))

        # Extract and decode the certificate data
        cert_data_b64 = memo_data.get('cert_data')
        if not cert_data_b64:
            print_error("No certificate data found in memo")
            return None

        # Decode base64 and decompress
        compressed_cert = base64.b64decode(cert_data_b64)
        decompressed_cert = gzip.decompress(compressed_cert)

        return {
            'common_name': memo_data.get('common_name'),
            'timestamp': memo_data.get('timestamp'),
            'certificate': decompressed_cert.decode('utf-8')
        }

    except json.JSONDecodeError as e:
        print_error(f"Error decoding memo JSON: {str(e)}")
        print("Raw memo string:", memo_str)
        return None
    except Exception as e:
        print_error(f"Error processing memo: {str(e)}")
        import traceback
        print_error(traceback.format_exc())
        return None

def retrieve_certificate():
    try:
        print_info("Connecting to XRP Testnet...")
        client = JsonRpcClient("https://s.altnet.rippletest.net:51234")

        print_info(f"Requesting transaction: {TRANSACTION_HASH}")
        tx_request = Tx(transaction=TRANSACTION_HASH)

        try:
            response = client.request(tx_request)

            # Extract the result from the response
            if hasattr(response, 'result'):
                tx_data = response.result
            else:
                tx_data = response

            print_info("Transaction retrieved successfully")

            # Check for Memos in the transaction
            if 'Memos' in tx_data:
                print_info(f"Found {len(tx_data['Memos'])} memos in transaction")

                for idx, memo in enumerate(tx_data['Memos']):
                    print_info(f"\nProcessing Memo {idx + 1}:")
                    cert_data = extract_certificate_from_memo(memo)

                    if cert_data:
                        print_success("Certificate extracted successfully")
                        return cert_data
            else:
                print_error("No memos found in transaction")
                print("\nTransaction data:")
                print(json.dumps(tx_data, indent=2, default=str))

        except Exception as request_error:
            print_error(f"Error during request: {str(request_error)}")
            import traceback
            print_error(traceback.format_exc())

    except Exception as e:
        print_error(f"Error: {str(e)}")
        import traceback
        print_error(traceback.format_exc())

    return None

def display_certificate(cert_data):
    """Display the certificate details in a formatted way"""
    if not cert_data:
        return

    print("\n=== Certificate Details ===")
    print(f"\nCommon Name: {cert_data.get('common_name')}")
    print(f"Timestamp: {cert_data.get('timestamp')}")
    print("\nCertificate Content:")
    print("-" * 40)
    print(cert_data.get('certificate'))
    print("-" * 40)

def main():
    print("\n=== Certificate Retrieval and Decoding ===")
    cert_data = retrieve_certificate()

    if cert_data:
        print_success("Certificate retrieved and decoded successfully")
        display_certificate(cert_data)
    else:
        print_error("Failed to retrieve or decode certificate")

if __name__ == "__main__":
    main()