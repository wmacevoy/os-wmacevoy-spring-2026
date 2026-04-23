CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
LDFLAGS ?=

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  LDFLAGS += -framework Security
endif

ifeq ($(OS),Windows_NT)
  LDFLAGS += -lbcrypt
  EXE := .exe
else
  EXE :=
endif

# ---- Optional OpenSSL acceleration --------------------------------------
#   By default, AES-GCM uses a pure-C fallback (no external dependency).
#   To use OpenSSL's hardware-accelerated AES-NI path, build with:
#       make AES_GCM_USE_OPENSSL=1
#   Set OPENSSL_PREFIX to override auto-detection (homebrew on macOS).
ifdef AES_GCM_USE_OPENSSL
  ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
  endif
  ifneq ($(OPENSSL_PREFIX),)
    AES_GCM_CFLAGS := -DAES_GCM_USE_OPENSSL -I$(OPENSSL_PREFIX)/include
    AES_GCM_LIBS   := -L$(OPENSSL_PREFIX)/lib -lcrypto
  else
    AES_GCM_CFLAGS := -DAES_GCM_USE_OPENSSL
    AES_GCM_LIBS   := -lcrypto
  endif
else
  AES_GCM_CFLAGS :=
  AES_GCM_LIBS   :=
endif

all: mkpass$(EXE) mksha256$(EXE) mkaesgcm$(EXE)

mkpass$(EXE): mkpass.c secure_random.c secure_random.h
	$(CC) $(CFLAGS) mkpass.c secure_random.c -o $@ $(LDFLAGS)

mksha256$(EXE): mksha256.c hash_sha256.c hash_sha256.h
	$(CC) $(CFLAGS) mksha256.c hash_sha256.c -o $@ $(LDFLAGS)

mkaesgcm$(EXE): mkaesgcm.c aes_gcm.c aes_gcm.h secure_random.c secure_random.h
	$(CC) $(CFLAGS) $(AES_GCM_CFLAGS) mkaesgcm.c aes_gcm.c secure_random.c -o $@ $(LDFLAGS) $(AES_GCM_LIBS)

test_aes_gcm$(EXE): test_aes_gcm.c aes_gcm.c aes_gcm.h
	$(CC) $(CFLAGS) $(AES_GCM_CFLAGS) test_aes_gcm.c aes_gcm.c -o $@ $(LDFLAGS) $(AES_GCM_LIBS)

test: test_aes_gcm$(EXE) mkaesgcm$(EXE)
	./test_aes_gcm$(EXE)
	sh ./test_roundtrip.sh

clean:
	rm -f mkpass mksha256 mkaesgcm test_aes_gcm mkpass.exe mksha256.exe mkaesgcm.exe test_aes_gcm.exe

.PHONY: all clean test
