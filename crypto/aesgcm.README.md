# aesgcm.py

A small AES-256-GCM file tool. Encrypts a file under a shared 32-byte key,
authenticates (but does not encrypt) an associated-data file, and bundles
everything into a single sealed blob that can be decrypted with just the
shared key.

## Install

```sh
python3 -m pip install --user cryptography
```

## Commands

```sh
# generate a fresh 256-bit key
aesgcm.py --keygen --key K.bin

# encrypt: seal plain.txt with meta.json as associated data
aesgcm.py --key K.bin --encrypt plain.txt --data meta.json --out sealed.bin

# decrypt: only the key is needed
aesgcm.py --key K.bin --decrypt sealed.bin --out plain.txt

# decrypt and also recover the embedded associated data
aesgcm.py --key K.bin --decrypt sealed.bin --out plain.txt --data meta.json
```

## Sealed blob layout

```
nonce(12) || tag(16) || aad_len(4 BE) || aad || ciphertext
```

- `nonce` — fresh 96-bit random value per call. Never reuse a nonce under
  the same key; generate a new one for every encryption.
- `tag` — 128-bit GCM authentication tag covering nonce, AAD, and
  ciphertext.
- `aad_len || aad` — the `--data` bytes, stored in the clear but
  integrity-protected by the tag.
- `ciphertext` — AES-CTR output of the plaintext.

Any single-bit change anywhere in the blob causes decryption to fail with
`InvalidTag`.

## Typical case: a shared pool of sealed records

You have a directory of records you want to ship to a peer who holds the
same key. Each record has a payload and some metadata (owner, timestamp,
content type) that the recipient wants to read *and* know hasn't been
swapped between records.

```sh
# one-time: generate the key, share it out-of-band
aesgcm.py --keygen --key K.bin
scp K.bin peer:~/.secrets/K.bin

# seal every record in the pool
for f in pool/*.raw; do
  aesgcm.py --key K.bin \
            --encrypt "$f" \
            --data    "$f.meta" \
            --out     "$f.gcm"
done

# ship only the .gcm files
rsync -av pool/*.gcm peer:pool/
```

On the receiving side:

```sh
for s in pool/*.gcm; do
  base="${s%.gcm}"
  aesgcm.py --key ~/.secrets/K.bin \
            --decrypt "$s" \
            --out     "$base.raw" \
            --data    "$base.meta"
done
```

The recipient gets back both the payload and the metadata, and knows the
pairing is authentic: an attacker cannot take the ciphertext from record A
and glue it to the metadata of record B without the tag check failing.

## Notes and caveats

- The key file is written with mode `0600`. Treat it like an SSH private
  key — anyone who reads it can decrypt every blob ever sealed under it.
- GCM's security collapses if a nonce is ever reused under the same key.
  This tool uses a fresh random 96-bit nonce per call; do not modify that.
- AAD must fit in 4 GiB (the 4-byte length header). For larger metadata,
  hash it and store the digest as AAD instead.
- This tool is aimed at coursework and small pipelines, not high-volume
  production use. For general file encryption prefer [`age`](https://age-encryption.org).
