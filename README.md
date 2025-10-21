# Cert Encryption App

A Flask-based demo that:
- Generates X.509 certificates signed by a local Root CA
- Stores/retrieves certificates on the XRP Ledger Testnet (via memos)
- Encrypts/decrypts messages using the certificate public/private keys
- Optionally sends encrypted emails
- Includes an alternate local JSON “blockchain” demo


## Prerequisites
- Python 3.10+ (tested with 3.12)
- pip
- Internet access for XRPL Testnet faucet funding


## Install
1) Create Root CA (writes to `root_cred/`):
- python createroot.py

2) Install Python deps:
- python -m venv .venv
- source .venv/bin/activate
- pip install -r requirements.txt


## Run
- Flask app (XRPL-backed, port 5003):
- python app.py

- Alternate demo (local JSON blockchain, default port 5000):
- python blockchain_app.py

Open in a browser:
- http://127.0.0.1:5003/ (dashboard)
- http://127.0.0.1:5003/generate (generate certificate)
- http://127.0.0.1:5003/encrypt-decrypt (message tools)
- http://127.0.0.1:5003/email-encryption (email tools)


## API (XRPL-backed app.py)
- POST /generate-certificate
  Body: { commonName, organization, country, email }
  Creates cert signed by local Root CA and stores it on XRPL Testnet.

- POST /get-certificate
  Body: { email }
  Retrieves the PEM from XRPL (if present).

- POST /encrypt
  Body: { message, certificate }
  Returns base64 of ciphertext using cert public key.

- POST /decrypt
  Body: { encryptedMessage, privateKey }
  Returns plaintext using provided private key.

- POST /send-encrypted-email
  Body: { recipient_email, subject, message }
  Encrypts with recipient’s cert from XRPL and emails as an attachment.

- POST /decrypt-email
  Body: { encrypted_message, private_key }
  Decrypts a base64 ciphertext payload using the provided private key.


## Email setup
Update sender settings in `app.py` (class `EmailEncryption`):
- self.sender_email = "your_email@gmail.com"
- self.sender_password = "your_app_password" (use an App Password)


## XRPL notes
- A testnet wallet is created automatically on first run and saved to `xrp_wallet.json`.
- Requires connectivity to https://s.altnet.rippletest.net:51234.
- Storing larger memos costs more fees; certificates are compressed and base64-encoded.


## Project layout (key files)
- app.py — Flask app using XRPL Testnet for cert storage
- xrpl_ledger.py — XRPL helpers and compression/encoding utilities
- createroot.py — creates local Root CA in `root_cred/`
- blockchain_app.py — alternate local JSON blockchain demo
- certificates/ — generated certs/keys
- templates/ — HTML pages
- scripts/ — experiments/utilities (optional)


## Security
- Never commit real private keys or email passwords.
- This is a demo; review before using in production.