#!/usr/bin/env python3
"""
AES-256-GCM file tool.

    aesgcm.py --keygen --key K.bin
    aesgcm.py --key K.bin --encrypt plain.txt --data meta.bin --out sealed.bin
    aesgcm.py --key K.bin --decrypt sealed.bin --out plain.txt [--data meta.bin]

Sealed format:  nonce(12) || tag(16) || aad_len(4 BE) || aad || ciphertext
The AAD is authenticated AND stored in the blob, so the recipient only
needs the shared key. On --decrypt, --data is optional; if given, the
recovered AAD bytes are written to that file.
"""
import argparse, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE   = 12
TAG     = 16
AAD_LEN = 4  # big-endian uint32

def read(p):  return open(p, "rb").read()
def write(p, b):
    with open(p, "wb") as f: f.write(b)
    try: os.chmod(p, 0o600)
    except OSError: pass

def keygen(path):
    write(path, AESGCM.generate_key(bit_length=256))

def encrypt(key, plain_path, aad_path, out_path):
    aad = read(aad_path) if aad_path else b""
    if len(aad) >= 1 << (8 * AAD_LEN):
        sys.exit(f"{aad_path}: AAD too large ({len(aad)} bytes)")
    nonce = os.urandom(NONCE)
    ct_and_tag = AESGCM(key).encrypt(nonce, read(plain_path), aad)
    ct, tag = ct_and_tag[:-TAG], ct_and_tag[-TAG:]
    header = nonce + tag + len(aad).to_bytes(AAD_LEN, "big")
    write(out_path, header + aad + ct)

def decrypt(key, sealed_path, aad_out_path, out_path):
    blob = read(sealed_path)
    if len(blob) < NONCE + TAG + AAD_LEN:
        sys.exit(f"{sealed_path}: too short to be a sealed blob")
    nonce = blob[:NONCE]
    tag   = blob[NONCE:NONCE+TAG]
    alen  = int.from_bytes(blob[NONCE+TAG:NONCE+TAG+AAD_LEN], "big")
    rest  = blob[NONCE+TAG+AAD_LEN:]
    if len(rest) < alen:
        sys.exit(f"{sealed_path}: truncated (AAD length {alen} exceeds remaining {len(rest)})")
    aad, ct = rest[:alen], rest[alen:]
    plain = AESGCM(key).decrypt(nonce, ct + tag, aad)
    write(out_path, plain)
    if aad_out_path: write(aad_out_path, aad)

def main():
    ap = argparse.ArgumentParser(description="AES-256-GCM file tool")
    ap.add_argument("--key", help="key file (32 bytes)")
    ap.add_argument("--keygen", action="store_true", help="generate a fresh key at --key")
    ap.add_argument("--encrypt", metavar="PLAIN",  help="plaintext input")
    ap.add_argument("--decrypt", metavar="SEALED", help="sealed input")
    ap.add_argument("--data",    metavar="AAD",    help="associated data file (authenticated, not encrypted)")
    ap.add_argument("--out",     metavar="OUT",    help="output file")
    a = ap.parse_args()

    if a.keygen:
        if not a.key: ap.error("--keygen requires --key")
        keygen(a.key); return

    if not a.key: ap.error("--key is required")
    key = read(a.key)
    if len(key) != 32: sys.exit(f"{a.key}: expected 32-byte key, got {len(key)}")

    if a.encrypt and a.decrypt: ap.error("pick one of --encrypt or --decrypt")
    if not a.out: ap.error("--out is required")

    if a.encrypt:   encrypt(key, a.encrypt, a.data, a.out)
    elif a.decrypt: decrypt(key, a.decrypt, a.data, a.out)
    else: ap.error("need --encrypt or --decrypt")

if __name__ == "__main__":
    main()
