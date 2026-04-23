#!/bin/sh
# End-to-end tests for mkaesgcm: round-trip, tamper detection.
# Usage: sh test_roundtrip.sh
# Runs from the crypto/ directory.

set -eu

: "${MKAESGCM:=./mkaesgcm}"

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t mkaesgcm)
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "roundtrip tests in $TMP"

# Various plaintext sizes to exercise partial last block.
for sz in 0 1 15 16 17 64 1000; do
    printf '' > "$TMP/plain.bin"
    if [ "$sz" -gt 0 ]; then
        # Fill with pseudo-random bytes
        dd if=/dev/urandom of="$TMP/plain.bin" bs=1 count="$sz" 2>/dev/null
    fi
    printf 'metadata for size %s' "$sz" > "$TMP/meta.bin"

    "$MKAESGCM" --keygen --key "$TMP/K.bin"
    "$MKAESGCM" --key "$TMP/K.bin" --encrypt "$TMP/plain.bin" --data "$TMP/meta.bin" --out "$TMP/sealed.bin"
    "$MKAESGCM" --key "$TMP/K.bin" --decrypt "$TMP/sealed.bin" --data "$TMP/out.meta" --out "$TMP/out.bin"

    cmp "$TMP/plain.bin" "$TMP/out.bin"  || { echo "FAIL: plaintext mismatch (size=$sz)"; exit 1; }
    cmp "$TMP/meta.bin"  "$TMP/out.meta" || { echo "FAIL: aad mismatch (size=$sz)"; exit 1; }
    echo "  ok   round-trip size=$sz"
done

# Tamper: flip last byte of sealed blob, decryption must fail.
"$MKAESGCM" --keygen --key "$TMP/K.bin"
echo "payload" > "$TMP/plain.bin"
"$MKAESGCM" --key "$TMP/K.bin" --encrypt "$TMP/plain.bin" --out "$TMP/sealed.bin"
cp "$TMP/sealed.bin" "$TMP/bad.bin"
# Portable last-byte flip (no python, no gnu-specific tools).
sz=$(wc -c < "$TMP/bad.bin")
last=$((sz - 1))
# Read last byte, xor 0x01, write it back using dd
orig=$(dd if="$TMP/bad.bin" bs=1 skip="$last" count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
new=$(( orig ^ 1 ))
printf "$(printf '\\%03o' "$new")" | dd of="$TMP/bad.bin" bs=1 seek="$last" count=1 conv=notrunc 2>/dev/null

if "$MKAESGCM" --key "$TMP/K.bin" --decrypt "$TMP/bad.bin" --out "$TMP/should_not.bin" 2>/dev/null; then
    echo "FAIL: decrypt accepted tampered blob"
    exit 1
fi
echo "  ok   tamper rejected"

echo "roundtrip tests passed"
