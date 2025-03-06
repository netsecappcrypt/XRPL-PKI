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
import random
from typing import Tuple, Dict

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

def generate_random_details():
    companies = ['Tech', 'Solutions', 'Systems', 'Corp', 'Inc', 'Ltd', 'Global']
    domains = ['com', 'net', 'org', 'io', 'tech', 'dev', 'cloud']
    countries = ['US', 'GB', 'DE', 'FR', 'JP', 'CA', 'AU', 'BR', 'IN']

    company = f"{random.choice(['Alpha', 'Beta', 'Delta', 'Gamma', 'Omega', 'Nova', 'Nexus'])}"
    company += f"{random.choice(companies)}"

    domain = f"{company.lower()}.{random.choice(domains)}"
    country = random.choice(countries)

    return {
        'common_name': domain,
        'organization': company,
        'country': country
    }

class CertificateTest:
    def __init__(self):
        self.test_results = {
            'total_tests': 0,
            'size_tests_passed': 0,
            'decrypt_tests_passed': 0,
            'min_size': float('inf'),
            'max_size': 0,
            'avg_size': 0,
            'total_size': 0,
            'cert_details': []
        }
        self.root_ca_cert = None
        self.root_ca_key = None
        self.create_root_ca()

    def create_root_ca(self):
        # Generate root CA private key
        self.root_ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )

        # Create subject for the root CA
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])

        # Create self-signed root CA certificate
        self.root_ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            self.root_ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self.root_ca_key, hashes.SHA256())

        # Save root CA certificate
        with open("root_ca_cert.pem", "wb") as f:
            f.write(self.root_ca_cert.public_bytes(serialization.Encoding.PEM))

    def generate_and_test_certificate(self, test_number: int) -> bool:
        try:
            details = generate_random_details()
            self.test_results['cert_details'].append(details)

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024,
            )

            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, details['common_name']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, details['organization']),
                x509.NameAttribute(NameOID.COUNTRY_NAME, details['country'])
            ])

            # Build certificate signed by the root CA
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.root_ca_cert.subject
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=1)
            ).sign(self.root_ca_key, hashes.SHA256())

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            with open("test_cert.pem", "wb") as f:
                f.write(cert_pem)

            with open("test_cert.pem", "rb") as f_in:
                with gzip.open("test_cert.gz", "wb", compresslevel=9) as f_out:
                    f_out.write(f_in.read())

            compressed_size = os.path.getsize("test_cert.gz")

            self.test_results['min_size'] = min(self.test_results['min_size'], compressed_size)
            self.test_results['max_size'] = max(self.test_results['max_size'], compressed_size)
            self.test_results['total_size'] += compressed_size

            test_message = f"Test message {test_number} for {details['common_name']}".encode()

            ciphertext = cert.public_key().encrypt(
                test_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            decrypted_message = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            os.remove("test_cert.pem")
            os.remove("test_cert.gz")

            if compressed_size < 1000:
                self.test_results['size_tests_passed'] += 1
            if decrypted_message == test_message:
                self.test_results['decrypt_tests_passed'] += 1

            return True

        except Exception as e:
            print_error(f"Test {test_number} failed: {str(e)}")
            return False

    def run_tests(self, num_tests: int = 1000):
        print_header(f"Starting {num_tests} Certificate Tests")
        print(f"Testing certificate generation with random details, compression, and encryption/decryption...")

        start_time = time.time()
        self.test_results['total_tests'] = num_tests

        for i in range(num_tests):
            self.generate_and_test_certificate(i + 1)
            progress = (i + 1) / num_tests
            bar_length = 50
            filled_length = int(bar_length * progress)
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            print(f'\rProgress: |{bar}| {progress*100:.1f}% Complete', end='')
        print()

        self.test_results['avg_size'] = self.test_results['total_size'] / num_tests
        self.print_test_results(time.time() - start_time)

    def print_test_results(self, duration: float):
        print_header("Test Results")

        size_pass_rate = (self.test_results['size_tests_passed'] / self.test_results['total_tests']) * 100
        if size_pass_rate == 100:
            print_success(f"Size Test: {size_pass_rate:.2f}% of certificates were under 1000 bytes")
        else:
            print_error(f"Size Test: Only {size_pass_rate:.2f}% of certificates were under 1000 bytes")

        decrypt_pass_rate = (self.test_results['decrypt_tests_passed'] / self.test_results['total_tests']) * 100
        if decrypt_pass_rate == 100:
            print_success(f"Encryption Test: {decrypt_pass_rate:.2f}% of messages were correctly encrypted/decrypted")
        else:
            print_error(f"Encryption Test: Only {decrypt_pass_rate:.2f}% of messages were correctly encrypted/decrypted")

        print("\nCompressed Certificate Size Statistics:")
        print(f"  Minimum size: {self.test_results['min_size']} bytes")
        print(f"  Maximum size: {self.test_results['max_size']} bytes")
        print(f"  Average size: {self.test_results['avg_size']:.2f} bytes")

        print(f"\nTotal test duration: {duration:.2f} seconds")
        print(f"Average time per test: {(duration/self.test_results['total_tests'])*1000:.2f} ms")

        print("\nSample Certificate Details (first 5 and last 5):")
        print("\nFirst 5 certificates:")
        for i, details in enumerate(self.test_results['cert_details'][:5]):
            print(f"\nCertificate {i+1}:")
            print(f"  Common Name: {details['common_name']}")
            print(f"  Organization: {details['organization']}")
            print(f"  Country: {details['country']}")

        print("\nLast 5 certificates:")
        for i, details in enumerate(self.test_results['cert_details'][-5:]):
            print(f"\nCertificate {len(self.test_results['cert_details'])-4+i}:")
            print(f"  Common Name: {details['common_name']}")
            print(f"  Organization: {details['organization']}")
            print(f"  Country: {details['country']}")

def main():
    try:
        tester = CertificateTest()
        tester.run_tests(1000)
    except Exception as e:
        print_error(f"Test suite failed: {str(e)}")

if __name__ == "__main__":
    main()