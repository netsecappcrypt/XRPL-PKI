import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import datetime

def create_root_ca():
    """
    Create a fresh Root CA key and certificate using ECC.
    """
    try:
        print("[INFO] Creating new Root CA with ECC...")
        
        # Create directory for Root CA credentials
        root_dir = "root_cred"
        os.makedirs(root_dir, exist_ok=True)
        
        # Generate ECC private key for Root CA
        root_key = ec.generate_private_key(ec.SECP384R1())  # Using P-384 curve for Root CA (stronger)
        print("[INFO] Root CA ECC private key generated")
        
        # Create self-signed Root CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Blockchain Certificate Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Blockchain Certificate Authority"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
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
            # Root CA certificates typically have a longer validity period
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).sign(root_key, hashes.SHA256())
        
        print("[INFO] Root CA certificate created")
        
        # Save Root CA private key
        key_path = os.path.join(root_dir, "rootCA.key")
        with open(key_path, "wb") as key_file:
            key_file.write(root_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()  # No password protection for simplicity
            ))
        
        # Save Root CA certificate
        cert_path = os.path.join(root_dir, "rootCA.crt")
        with open(cert_path, "wb") as cert_file:
            cert_file.write(root_cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"[SUCCESS] Root CA key saved to: {key_path}")
        print(f"[SUCCESS] Root CA certificate saved to: {cert_path}")
        
        return {
            "key_path": key_path,
            "cert_path": cert_path
        }
    
    except Exception as e:
        print(f"[ERROR] Failed to create Root CA: {str(e)}")
        raise

if __name__ == "__main__":
    create_root_ca()