from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

def load_keys():
    # Load the certificate (for encryption)
    with open("certificate_decompressed.pem", "rb") as cert_file:
        cert = load_pem_x509_certificate(cert_file.read())
        public_key = cert.public_key()

    # Load the private key (for decryption)
    with open("private_key_decompressed.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    
    return public_key, private_key

def encrypt_message(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def main():
    # Load the keys
    print("Loading keys...")
    public_key, private_key = load_keys()

    # Original message
    original_message = "Hello, this is a secret message!"
    print(f"\nOriginal message: {original_message}")

    # Encrypt the message
    print("\nEncrypting message...")
    encrypted_message = encrypt_message(public_key, original_message)
    print(f"Encrypted message (hex): {encrypted_message.hex()}")

    # Decrypt the message
    print("\nDecrypting message...")
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"Decrypted message: {decrypted_message}")

    # Save encrypted message to file for demonstration
    with open("encrypted_message.bin", "wb") as f:
        f.write(encrypted_message)
    
    # Verify file sizes
    import os
    print("\nFile sizes:")
    print(f"Original message length: {len(original_message)} bytes")
    print(f"Encrypted message length: {len(encrypted_message)} bytes")
    print(f"Encrypted message file size: {os.path.getsize('encrypted_message.bin')} bytes")

if __name__ == "__main__":
    main()

# Created/Modified files during execution:
print("\nFiles created/modified:")
print("- encrypted_message.bin")