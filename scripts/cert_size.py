from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidKey
import datetime
import gzip
import os
import hashlib
import time
import base64
from typing import Tuple, Dict

# ANSI color codes for prettier console output
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

def print_info(message):
    print(f"{Colors.BLUE}ℹ {message}{Colors.ENDC}")

def print_warning(message):
    print(f"{Colors.YELLOW}⚠ {message}{Colors.ENDC}")

def print_error(message):
    print(f"{Colors.RED}✖ {message}{Colors.ENDC}")

class CertificateManager:
    def __init__(self):
        self.metrics = {
            'generation_time': 0,
            'compression_ratio': 0,
            'encryption_time': 0,
            'decryption_time': 0
        }
        self.file_hashes = {}

    def calculate_file_hash(self, filename: str) -> str:
        """Calculate SHA-256 hash of a file."""
        try:
            with open(filename, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            self.file_hashes[filename] = file_hash
            return file_hash
        except Exception as e:
            print_error(f"Error calculating hash for {filename}: {str(e)}")
            return None

    def verify_file_integrity(self, filename: str) -> bool:
        """Verify file integrity using stored hash."""
        if filename not in self.file_hashes:
            print_warning(f"No stored hash found for {filename}")
            return False
        current_hash = self.calculate_file_hash(filename)
        return current_hash == self.file_hashes[filename]

    def generate_small_cert(self) -> Tuple[bytes, bytes]:
        """Generates a minimal RSA certificate and private key."""
        print_header("Generating Certificate")
        start_time = time.time()

        try:
            print_info("Generating RSA key pair...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024,
            )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"example"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Org"),
            ])

            print_info("Building certificate...")
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
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).sign(private_key, hashes.SHA256())

            # Save certificate
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            with open("small_certificate.pem", "wb") as f:
                f.write(cert_pem)

            # Save private key
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open("small_private_key.pem", "wb") as f:
                f.write(key_pem)

            self.calculate_file_hash("small_certificate.pem")
            self.calculate_file_hash("small_private_key.pem")

            self.metrics['generation_time'] = time.time() - start_time
            print_success(f"Certificate generated in {self.metrics['generation_time']:.2f} seconds")

            return cert_pem, key_pem

        except Exception as e:
            print_error(f"Certificate generation failed: {str(e)}")
            raise

    def compress_certificate(self, compression_level: int = 9) -> None:
        """Compresses the certificate with specified compression level."""
        print_header("Compressing Certificate")
        print_info(f"Using compression level: {compression_level}")

        try:
            original_size = os.path.getsize("small_certificate.pem")

            with open("small_certificate.pem", "rb") as f_in:
                with gzip.open("small_certificate.pem.gz", "wb", compresslevel=compression_level) as f_out:
                    f_out.write(f_in.read())

            compressed_size = os.path.getsize("small_certificate.pem.gz")
            self.metrics['compression_ratio'] = original_size / compressed_size

            self.calculate_file_hash("small_certificate.pem.gz")
            print_success(f"Compression complete - Ratio: {self.metrics['compression_ratio']:.2f}x")
            print_info(f"Original size: {original_size} bytes")
            print_info(f"Compressed size: {compressed_size} bytes")

        except Exception as e:
            print_error(f"Compression failed: {str(e)}")
            raise

    def decompress_certificate(self) -> None:
        """Decompresses the certificate with integrity verification."""
        print_header("Decompressing Certificate")

        try:
            with gzip.open("small_certificate.pem.gz", "rb") as f_in:
                with open("decompressed_certificate.pem", "wb") as f_out:
                    f_out.write(f_in.read())

            self.calculate_file_hash("decompressed_certificate.pem")

            if self.verify_file_integrity("small_certificate.pem"):
                print_success("Decompression complete - Integrity verified")
            else:
                print_warning("Decompression complete but integrity check failed")

        except Exception as e:
            print_error(f"Decompression failed: {str(e)}")
            raise

    def encrypt_decrypt_test(self, test_message: bytes = b"Secret Message") -> Dict:
        """Tests encryption and decryption with the certificate."""
        print_header("Testing Encryption/Decryption")
        results = {}

        try:
            print_info("Loading certificate and private key...")
            with open("decompressed_certificate.pem", "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            with open("small_private_key.pem", "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            # Encryption test
            print_info("Encrypting test message...")
            start_time = time.time()
            ciphertext = cert.public_key().encrypt(
                test_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.metrics['encryption_time'] = time.time() - start_time
            results['ciphertext'] = base64.b64encode(ciphertext).decode('utf-8')
            print_success(f"Encryption completed in {self.metrics['encryption_time']:.3f} seconds")

            # Decryption test
            print_info("Decrypting message...")
            start_time = time.time()
            decrypted_message = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.metrics['decryption_time'] = time.time() - start_time
            print_success(f"Decryption completed in {self.metrics['decryption_time']:.3f} seconds")

            results.update({
                'original_message': test_message.decode('utf-8'),
                'decrypted_message': decrypted_message.decode('utf-8'),
                'encryption_time': self.metrics['encryption_time'],
                'decryption_time': self.metrics['decryption_time']
            })

            return results

        except Exception as e:
            print_error(f"Encryption/Decryption failed: {str(e)}")
            raise

    def print_summary(self) -> None:
        """Prints a detailed summary of all operations and metrics."""
        print_header("Operation Summary")

        # File sizes and hashes
        files = {
            "Original Certificate": "small_certificate.pem",
            "Private Key": "small_private_key.pem",
            "Compressed Certificate": "small_certificate.pem.gz",
            "Decompressed Certificate": "decompressed_certificate.pem"
        }

        print_info("File Sizes and Hashes:")
        for desc, filename in files.items():
            if os.path.exists(filename):
                size = os.path.getsize(filename)
                file_hash = self.file_hashes.get(filename, "Not calculated")
                print(f"  {desc}:")
                print(f"    - Size: {size} bytes")
                print(f"    - SHA-256: {file_hash}")

        print_info("\nPerformance Metrics:")
        print(f"  - Certificate Generation Time: {self.metrics['generation_time']:.3f} seconds")
        print(f"  - Compression Ratio: {self.metrics['compression_ratio']:.2f}x")
        print(f"  - Encryption Time: {self.metrics['encryption_time']:.3f} seconds")
        print(f"  - Decryption Time: {self.metrics['decryption_time']:.3f} seconds")

def main():
    cert_manager = CertificateManager()

    try:
        # Generate certificate
        cert_manager.generate_small_cert()

        # Compress
        cert_manager.compress_certificate(compression_level=9)

        # Decompress
        cert_manager.decompress_certificate()

        # Test encryption/decryption
        test_results = cert_manager.encrypt_decrypt_test(
            b"This is a test message for encryption and decryption!"
        )

        # Print encryption/decryption results
        print_header("Encryption/Decryption Results")
        print_info(f"Original Message: {test_results['original_message']}")
        print_info(f"Ciphertext (base64): {test_results['ciphertext'][:50]}...")
        print_info(f"Decrypted Message: {test_results['decrypted_message']}")

        # Print final summary
        cert_manager.print_summary()

    except Exception as e:
        print_error(f"Operation failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()

    print_header("Files Created")
    for filename in ["small_certificate.pem", "small_private_key.pem",
                    "small_certificate.pem.gz", "decompressed_certificate.pem"]:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print_info(f"{filename} ({size} bytes)")