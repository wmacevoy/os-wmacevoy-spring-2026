#ifndef AES_GCM_H
#define AES_GCM_H

#include <stddef.h>

#define AES_GCM_TAG_MAX_LEN  16
#define AES_GCM_TAG_LEN      16   /* recommended full-strength tag */
#define AES_GCM_IV_LEN       12   /* recommended 96-bit nonce       */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * One-shot AES-GCM.
 *
 *   key_len   must be 16, 24, or 32.
 *   iv_len    must be >= 1; 12 is recommended.
 *   aad/pt/ct may be NULL iff the corresponding length is 0.
 *   tag_len   must be in 1..AES_GCM_TAG_MAX_LEN; 16 is recommended.
 *   ct        receives exactly pt_len bytes (GCM is length-preserving).
 *
 * Returns 0 on success, -1 on failure.
 *
 * WARNING: Never reuse (key, iv). A single nonce collision under the
 * same key destroys confidentiality AND authenticity for every message
 * encrypted under that key.
 */
int aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const void *aad,          size_t aad_len,
                    const void *pt,           size_t pt_len,
                    unsigned char *ct,
                    unsigned char *tag,       size_t tag_len);

/*
 * One-shot AES-GCM decrypt with tag verification.
 *
 * On success (return 0) pt receives exactly ct_len bytes of plaintext.
 * On failure (return -1) pt is left in an undefined state and MUST NOT
 * be used — authentication failure or any other error is indistinguishable
 * from the caller's perspective.
 */
int aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const void *aad,          size_t aad_len,
                    const void *ct,           size_t ct_len,
                    const unsigned char *tag, size_t tag_len,
                    unsigned char *pt);

#ifdef __cplusplus
}
#endif

#endif /* AES_GCM_H */
