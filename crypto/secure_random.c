#include "secure_random.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

int secure_random_bytes(void *out, size_t n) {
    if (n == 0) {
        return 0;
    }
    if (out == NULL || n > ULONG_MAX) {
        return -1;
    }

    NTSTATUS status = BCryptGenRandom(
        NULL,
        (PUCHAR)out,
        (ULONG)n,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    return (status == STATUS_SUCCESS) ? 0 : -1;
}

#elif defined(__APPLE__)
#include <Security/SecRandom.h>

int secure_random_bytes(void *out, size_t n) {
    if (n == 0) {
        return 0;
    }
    if (out == NULL) {
        return -1;
    }

    return (SecRandomCopyBytes(kSecRandomDefault, n, (uint8_t *)out) == errSecSuccess)
               ? 0
               : -1;
}

#else
#include <fcntl.h>
#include <unistd.h>

#if defined(SECURE_RANDOM_USE_OPENSSL)
#include <openssl/rand.h>
#endif

#if defined(__linux__)
#include <sys/random.h>
#endif

#if defined(SECURE_RANDOM_USE_OPENSSL)
static int fill_with_openssl(void *out, size_t n) {
    if (n > (size_t)INT_MAX) {
        return -1;
    }
    return (RAND_bytes((unsigned char *)out, (int)n) == 1) ? 0 : -1;
}
#endif

static int fill_with_urandom(void *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    uint8_t *p = (uint8_t *)out;
    size_t remaining = n;

    while (remaining > 0) {
        ssize_t r = read(fd, p, remaining);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (r == 0) {
            close(fd);
            return -1;
        }
        p += (size_t)r;
        remaining -= (size_t)r;
    }

    close(fd);
    return 0;
}

int secure_random_bytes(void *out, size_t n) {
    if (n == 0) {
        return 0;
    }
    if (out == NULL) {
        return -1;
    }

#if defined(__linux__)
    uint8_t *p = (uint8_t *)out;
    size_t remaining = n;

    while (remaining > 0) {
        ssize_t r = getrandom(p, remaining, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ENOSYS) {
#if defined(SECURE_RANDOM_USE_OPENSSL)
                if (fill_with_openssl(out, n) == 0) {
                    return 0;
                }
#endif
                return fill_with_urandom(out, n);
            }
            return -1;
        }
        p += (size_t)r;
        remaining -= (size_t)r;
    }

    return 0;
#else
#if defined(SECURE_RANDOM_USE_OPENSSL)
    if (fill_with_openssl(out, n) == 0) {
        return 0;
    }
#endif
    return fill_with_urandom(out, n);
#endif
}
#endif
