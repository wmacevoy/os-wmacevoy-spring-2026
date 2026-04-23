#ifndef SECURE_RANDOM_H
#define SECURE_RANDOM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Fills `out` with `n` cryptographically secure random bytes.
 *
 * Returns:
 *   0 on success
 *  -1 on failure
 */
int secure_random_bytes(void *out, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_RANDOM_H */
