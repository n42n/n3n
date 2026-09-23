/**
 * SPDX-License-Identifier: GPL-3.0-only
 * SPDX-FileCopyrightText: Copyright ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "config.h"     // for HAVE_LIBCRYPTO

#include <n3n/logging.h> // for traceEvent
#include <stdint.h>  // for uint32_t, uint8_t
#include <stdlib.h>  // for calloc, free
#include <string.h>  // for memcpy, size_t
#include "aes.h"     // for AES_BLOCK_SIZE, aes_context_t, AES128_KEY_BYTES
#include "portable_endian.h"  // for be32toh, htobe32


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ---------------------------------------------------------------------

#include <openssl/err.h>    // for ERR_print_errors
#include <openssl/evp.h>    // for EVP_EncryptInit_ex, EVP_CIPHER_CTX_set_p...

// get any erorr message out of openssl
// taken from https://en.wikibooks.org/wiki/OpenSSL/Error_handling
static char *openssl_err_as_string (void) {

    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *) calloc(1, 1 + len);

    if(ret)
        memcpy(ret, buf, len);

    BIO_free(bio);

    return ret;
}


int aes_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx) {

    int evp_len;
    int evp_ciphertext_len;

    if(1 == EVP_EncryptInit_ex(ctx->enc_ctx, ctx->cipher, NULL, ctx->key, iv)) {
        if(1 == EVP_CIPHER_CTX_set_padding(ctx->enc_ctx, 0)) {
            if(1 == EVP_EncryptUpdate(ctx->enc_ctx, out, &evp_len, in, in_len)) {
                evp_ciphertext_len = evp_len;
                if(1 == EVP_EncryptFinal_ex(ctx->enc_ctx, out + evp_len, &evp_len)) {
                    evp_ciphertext_len += evp_len;
                    if(evp_ciphertext_len != in_len)
                        traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl encryption: encrypted %u bytes where %u were expected",
                                   evp_ciphertext_len, in_len);
                } else
                    traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl final encryption: %s",
                               openssl_err_as_string());
            } else
                traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl encrpytion: %s",
                           openssl_err_as_string());
        } else
            traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl padding setup: %s",
                       openssl_err_as_string());
    } else
        traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl init: %s",
                   openssl_err_as_string());

    EVP_CIPHER_CTX_reset(ctx->enc_ctx);

    return 0;
}


// encrypts several packets, each with its own CBC chain (see the AES-NI code for
// why this exists); without AES-NI there is nothing to interleave, so this is a loop
int aes_cbc_encrypt_multi (unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                           const unsigned char *iv, aes_context_t *ctx, int count) {

    int i;

    for(i = 0; i < count; i++) {
        aes_cbc_encrypt(out[i], in[i], in_len[i], iv, ctx);
    }

    return 0;
}


int aes_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx) {

    int evp_len;
    int evp_plaintext_len;

    if(1 == EVP_DecryptInit_ex(ctx->dec_ctx, ctx->cipher, NULL, ctx->key, iv)) {
        if(1 == EVP_CIPHER_CTX_set_padding(ctx->dec_ctx, 0)) {
            if(1 == EVP_DecryptUpdate(ctx->dec_ctx, out, &evp_len, in, in_len)) {
                evp_plaintext_len = evp_len;
                if(1 == EVP_DecryptFinal_ex(ctx->dec_ctx, out + evp_len, &evp_len)) {
                    evp_plaintext_len += evp_len;
                    if(evp_plaintext_len != in_len)
                        traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl decryption: decrypted %u bytes where %u were expected",
                                   evp_plaintext_len, in_len);
                } else
                    traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl final decryption: %s",
                               openssl_err_as_string());
            } else
                traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl decrpytion: %s",
                           openssl_err_as_string());
        } else
            traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl padding setup: %s",
                       openssl_err_as_string());
    } else
        traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl init: %s",
                   openssl_err_as_string());

    EVP_CIPHER_CTX_reset(ctx->dec_ctx);

    return 0;
}


int aes_ecb_decrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx) {

    AES_ecb_encrypt(in, out, &(ctx->ecb_dec_key), AES_DECRYPT);

    return 0;
}


int aes_init (const unsigned char *key, size_t key_size, aes_context_t **ctx) {

    // allocate context...
    *ctx = (aes_context_t*) calloc(1, sizeof(aes_context_t));
    if(!(*ctx))
        return -1;

    // ...and fill her up:

    // initialize data structures
    if(!((*ctx)->enc_ctx = EVP_CIPHER_CTX_new())) {
        traceEvent(TRACE_ERROR, "aes_init openssl's evp_* encryption context creation failed: %s",
                   openssl_err_as_string());
        return -1;
    }

    if(!((*ctx)->dec_ctx = EVP_CIPHER_CTX_new())) {
        traceEvent(TRACE_ERROR, "aes_init openssl's evp_* decryption context creation failed: %s",
                   openssl_err_as_string());
        return -1;
    }

    // check key size and make key size (given in bytes) dependant settings
    switch(key_size) {
        case AES128_KEY_BYTES:    // 128 bit key size
            (*ctx)->cipher = EVP_aes_128_cbc();
            break;
        case AES192_KEY_BYTES:    // 192 bit key size
            (*ctx)->cipher = EVP_aes_192_cbc();
            break;
        case AES256_KEY_BYTES:    // 256 bit key size
            (*ctx)->cipher = EVP_aes_256_cbc();
            break;
        default:
            traceEvent(TRACE_ERROR, "aes_init invalid key size %u\n", key_size);
            return -1;
    }

    // key materiel handling
    memcpy((*ctx)->key, key, key_size);
    AES_set_decrypt_key(key, key_size * 8, &((*ctx)->ecb_dec_key));

    return 0;
}

int aes_deinit (aes_context_t *ctx) {

    if(ctx) free(ctx);

    return 0;
}

#elif defined (__AES__) && defined (__SSE2__) // Intel's AES-NI ---------------------------------------------------
#else
#endif
