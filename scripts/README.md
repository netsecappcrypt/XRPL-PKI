# Scripts

Utilities and experiments for certificates and the XRP Ledger. Run from the repo root:

- python scripts/<script>.py

## Contents
- xrp_final.py — End-to-end XRPL manager: wallet bootstrap, cert generation (needs Root CA), XRPL memo storage/retrieval, rich CLI and logs.
- xrp_setup.py — Creates/loads a Testnet wallet and prints balance; verifies wallet JSON.
- xrp_retrieve.py — Retrieves a transaction by hash and decodes memo contents to extract certificate data.
- x_cert_test.py — Stores compressed certificate chunks across multiple memos and reconstructs them; includes encrypt/decrypt test.
- xrp_cert.py — Streamlined chunked memo storage and retrieval demo.
- xrp_ipfs.py — Stores certificate in IPFS, writes IPFS hash to XRPL memo; requires a local IPFS daemon on 127.0.0.1:5001.
- xrp_nft_cert.py — Experimental: chunk certificate and mint chunks as NFTs (memo/URI-size constrained).
- cert_test.py — Stress test: generate many certs, measure compressed sizes and crypto operations.
- cert_size.py — Minimal cert generation, compression, and encrypt/decrypt with metrics.
- encrypt_decompressed.py — Loads decompressed PEMs and demonstrates encryption/decryption round-trip.

## Prerequisites
- Python deps installed from project requirements.txt
- Root CA in `root_cred/` for scripts that sign certs (run `python createroot.py` once)
- XRPL Testnet access (default endpoint https://s.altnet.rippletest.net:51234)
- Optional: Local IPFS daemon for `xrp_ipfs.py`

## Quick start
- python scripts/xrp_setup.py
- python scripts/xrp_final.py

Artifacts will be written under `certificates/`, `root_cred/`, and local JSON/log files. Treat keys and certs as sensitive.
