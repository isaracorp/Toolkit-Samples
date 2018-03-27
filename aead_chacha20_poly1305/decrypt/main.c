/** @file main.c
 *
 * @brief Perform ChaCha20-Poly1305-AEAD decryption using the toolkit.
 *
 * @copyright Copyright 2016-2018 ISARA Corporation
 *
 * @license Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <a href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</a>
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
// Declare memset_s() if the platform supports it.
#if !defined(__ANDROID__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
// For SecureZeroMemory().
#include <Windows.h>
#endif

#if defined(__FreeBSD__)
// For explicit_bzero().
#include <strings.h>
#endif

#include "iqr_chacha20.h"
#include "iqr_context.h"
#include "iqr_mac.h"
#include "iqr_retval.h"

/* RFC 7539 specifies that data is padded with zero-bytes so the length is a
 * 16 byte multiple. */
#define PAD_TO_LENGTH 16
/* RFC 7539 specifies that lengths are written out at 8 bytes. */
#define LENGTH_BYTES 8

/* Poly1305 keys must be 32 bytes. */
#define POLY1305_KEY_SIZE 32

/* Poly1305 tags are 16 bytes. */
#define POLY1305_TAG_SIZE 16

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);
static void secure_memzero(void *b, size_t len);
static iqr_retval append_data_and_pad(iqr_MAC *poly1305_obj, const uint8_t *data, size_t size);
static iqr_retval append_length(iqr_MAC *poly1305_obj, size_t length);
static iqr_retval verify_tag(const uint8_t *poly1305_tag, size_t poly1305_tag_size, const uint8_t *tag_data, size_t tag_size);
static iqr_retval decrypt_ciphertext(const uint8_t *key_data, size_t key_size, const uint8_t *nonce_data, size_t nonce_size,
    const uint8_t *ciphertext_data, size_t ciphertext_size, const char *plaintext_file);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases Poly1305 by performing ChaCha20-Poly1305 AEAD
// decryption.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_AEAD_chacha20_poly1305_decrypt(const iqr_Context *ctx, const uint8_t *key_data, size_t key_size,
    const uint8_t *nonce_data, size_t nonce_size, const uint8_t *ciphertext_data, size_t ciphertext_size,
    const uint8_t *aad_data, size_t aad_size, const uint8_t *tag_data, size_t tag_size, const char *plaintext_file)
{
    iqr_MAC *poly1305_obj = NULL;

    /* Generate the Poly1305 key using ChaCha20 with key and nonce.
     * Counter is set to 0 per RFC 7539.
     */
    uint8_t poly1305_key[POLY1305_KEY_SIZE] = { 0 };
    iqr_retval ret = iqr_ChaCha20Encrypt(key_data, key_size, nonce_data, nonce_size, 0, poly1305_key, sizeof(poly1305_key),
        poly1305_key, sizeof(poly1305_key));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ChaCha20Encrypt(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Poly1305 key created.\n");

    /* Do the AEAD construction and MAC it using Poly1305.
     * The AEAD construction is generated by concatenating the following:
     * - Additional authenticated data (AAD), padded out with zeros to a
     *   multiple of 16 bytes.
     * - Ciphertext, padded out with zeros to a multiple of 16 bytes.
     * - AAD length in octets, as a 64-bit little endian integer.
     * - Ciphertext length in octets, as a 64-bit little endian integer.
     */
    ret = iqr_MACCreatePoly1305(ctx, &poly1305_obj);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACCreatePoly1305(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_MACBegin(poly1305_obj, poly1305_key, sizeof(poly1305_key));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACBegin(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = append_data_and_pad(poly1305_obj, aad_data, aad_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = append_data_and_pad(poly1305_obj, ciphertext_data, ciphertext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = append_length(poly1305_obj, aad_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = append_length(poly1305_obj, ciphertext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    uint8_t poly1305_tag[POLY1305_TAG_SIZE];
    size_t poly1305_tag_size = sizeof(poly1305_tag);
    ret = iqr_MACEnd(poly1305_obj, poly1305_tag, poly1305_tag_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACEnd(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Poly1305 tag created.\n");

    ret = verify_tag(poly1305_tag, poly1305_tag_size, tag_data, tag_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Authentication success: provided tag matches calculated tag!\n");

    /* Decrypt the ciphertext.
     * We only do this after the data was successfully authenticated.
     */
    ret = decrypt_ciphertext(key_data, key_size, nonce_data, nonce_size, ciphertext_data, ciphertext_size, plaintext_file);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Plaintext has been saved to disk.\n");

end:
    /* Keys are private, sensitive data, be sure to clear memory containing them
     * when you're done.
     */
    secure_memzero(poly1305_key, sizeof(poly1305_key));

    iqr_MACDestroy(&poly1305_obj);
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Part of the Poly1305 AEAD construction involves MACing data and padding it
// out with zeros if the length isn't a multiple of 16.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval append_data_and_pad(iqr_MAC *poly1305_obj, const uint8_t *data, size_t size)
{
    iqr_retval ret = iqr_MACUpdate(poly1305_obj, data, size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACUpdate(): %s\n", iqr_StrError(ret));
        return ret;
    }

    const uint8_t zeros[PAD_TO_LENGTH] = { 0 };
    const size_t partial_length = size % PAD_TO_LENGTH;
    if (partial_length != 0) {
        ret = iqr_MACUpdate(poly1305_obj, zeros, PAD_TO_LENGTH - partial_length);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACUpdate(): %s\n", iqr_StrError(ret));
            return ret;
        }
    }

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Part of the Poly1305 AEAD construction involves converting length values to
// 8 little-endian bytes and adding it to the MAC.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval append_length(iqr_MAC *poly1305_obj, size_t length)
{
    uint8_t length_bytes[LENGTH_BYTES];
    for (int i = 0; i < LENGTH_BYTES; i++) {
        length_bytes[i] = (uint8_t)length;
        length >>= CHAR_BIT;
    }

    iqr_retval ret = iqr_MACUpdate(poly1305_obj, length_bytes, LENGTH_BYTES);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACUpdate(): %s\n", iqr_StrError(ret));
        return ret;
    }

    return IQR_OK;
}

static iqr_retval verify_tag(const uint8_t *poly1305_tag, size_t poly1305_tag_size, const uint8_t *tag_data, size_t tag_size)
{
    if (tag_size != poly1305_tag_size) {
        fprintf(stdout, "Tag size is incorrect!\n");
        return IQR_EINVBUFSIZE;
    }

    if (memcmp(poly1305_tag, tag_data, tag_size) != 0) {
        fprintf(stdout, "Authentication failure: provided tag doesn't match calculated tag!\n");
        return IQR_EINVDATA;
    }

    return IQR_OK;
}

static iqr_retval decrypt_ciphertext(const uint8_t *key_data, size_t key_size, const uint8_t *nonce_data, size_t nonce_size,
    const uint8_t *ciphertext_data, size_t ciphertext_size, const char *plaintext_file)
{
    const size_t plaintext_size = ciphertext_size;
    uint8_t *plaintext_data = calloc(1, plaintext_size);
    if (plaintext_data == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return IQR_ENOMEM;
    }

    /* Decrypt the ciphertext using ChaCha20 with its key and nonce.
     * Counter is set to 1 per RFC 7539, since counter 0 is used to generate
     * the Poly1305 key.
     */
    iqr_retval ret = iqr_ChaCha20Decrypt(key_data, key_size, nonce_data, nonce_size, 1, ciphertext_data, ciphertext_size,
        plaintext_data, plaintext_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ChaCha20Decrypt(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(plaintext_file, plaintext_data, plaintext_size);
    if (ret != IQR_OK) {
        goto end;
    }

end:
    free(plaintext_data);
    plaintext_data = NULL;

    return ret;
}

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create an IQR Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// These functions are designed to help the end user understand how to use
// this sample and hold little value to the developer trying to learn how to
// use the toolkit.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Generic POSIX file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size)
{
    FILE *fp = fopen(fname, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    iqr_retval ret = IQR_OK;
    fwrite(data, data_size, 1, fp);
    if (ferror(fp) != 0) {
        fprintf(stderr, "Failed on fwrite(): %s\n", strerror(errno));
        ret = IQR_EBADVALUE;
        goto end;
    }

    fprintf(stdout, "Successfully saved %s (%zu bytes)\n", fname, data_size);

end:
    fclose(fp);
    fp = NULL;
    return ret;
}

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size)
{
    FILE *fp = fopen(fname, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    /* Obtain file size. */
    fseek(fp , 0 , SEEK_END);
    size_t tmp_size = (size_t)ftell(fp);
    rewind(fp);

    iqr_retval ret = IQR_OK;
    uint8_t *tmp = NULL;
    if (tmp_size != 0) {
        /* calloc with a param of 0 could return a pointer or NULL depending on
         * implementation, so skip all this when the size is 0 so we
         * consistently return NULL with a size of 0. In some samples it's
         * useful to take empty files as input so users can pass NULL or 0 for
         * optional parameters.
         */
        tmp = calloc(1, tmp_size);
        if (tmp == NULL) {
            fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
            ret = IQR_EBADVALUE;
            goto end;
        }

        size_t read_size = fread(tmp, 1, tmp_size, fp);
        if (read_size != tmp_size) {
            fprintf(stderr, "Failed on fread(): %s\n", strerror(errno));
            free(tmp);
            tmp = NULL;
            ret = IQR_EBADVALUE;
            goto end;
        }
    }

    *data_size = tmp_size;
    *data = tmp;

    fprintf(stdout, "Successfully loaded %s (%zu bytes)\n", fname, *data_size);

end:
    fclose(fp);
    fp = NULL;
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Tell the user about the command-line arguments.
//  --------------------------------------------------------------------------------------------------------------------------------

static void usage(void)
{
    fprintf(stdout, "aead_chacha20_poly1305_decrypt [--key <filename>] [--nonce <filename>]\n"
        "  [--ciphertext <filename>] [--aad <filename>]\n"
        "  [--tag <filename>] [--plaintext <filename>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --key key.dat\n");
    fprintf(stdout, "        --nonce nonce.dat\n");
    fprintf(stdout, "        --ciphertext ciphertext.dat\n");
    fprintf(stdout, "        --aad aad.dat\n");
    fprintf(stdout, "        --tag tag.dat\n");
    fprintf(stdout, "        --plaintext message.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *key, const char *nonce,
    const char *ciphertext, const char *aad, const char *tag, const char *plaintext)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    key file: %s\n", key);
    fprintf(stdout, "    nonce file: %s\n", nonce);
    fprintf(stdout, "    ciphertext file: %s\n", ciphertext);
    fprintf(stdout, "    additional authenticated data file: %s\n", aad);
    fprintf(stdout, "    tag file: %s\n", tag);
    fprintf(stdout, "    plaintext file: %s\n", plaintext);
    fprintf(stdout, "\n");
}

/* Tests if two parameters match.
 * Returns 0 if the two parameter match.
 * Non-zero otherwise.
 *
 * Parameters are expected to be less than 32 characters in length
 */
static int paramcmp(const char *p1 , const char *p2) {
    const size_t max_param_size = 32;  // Arbitrary, but reasonable.
    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }
    return strncmp(p1, p2, max_param_size);
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **key, const char **nonce, const char **ciphertext,
    const char **aad, const char **tag, const char **plaintext)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
            return IQR_EBADVALUE;
        }
        if (paramcmp(argv[i], "--key") == 0) {
            /* [--key <filename>] */
            i++;
            *key = argv[i];
        } else if (paramcmp(argv[i], "--nonce") == 0) {
            /* [--nonce <filename>] */
            i++;
            *nonce = argv[i];
        } else if (paramcmp(argv[i], "--ciphertext") == 0) {
            /* [--ciphertext <filename>] */
            i++;
            *ciphertext = argv[i];
        } else if (paramcmp(argv[i], "--aad") == 0) {
            /* [--aad <filename>] */
            i++;
            *aad = argv[i];
        } else if (paramcmp(argv[i], "--tag") == 0) {
            /* [--tag <filename>] */
            i++;
            *tag = argv[i];
        } else if (paramcmp(argv[i], "--plaintext") == 0) {
            /* [--plaintext <filename>] */
            i++;
            *plaintext = argv[i];
        } else {
            usage();
            return IQR_EBADVALUE;
        }
        i++;
    }
    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Secure memory wipe.
// ---------------------------------------------------------------------------------------------------------------------------------

static void secure_memzero(void *b, size_t len)
{
    /* You may need to substitute your platform's version of a secure memset()
     * (one that won't be optimized out by the compiler). There isn't a secure,
     * portable memset() available before C11 which provides memset_s(). Windows
     * provides SecureZeroMemory() for this purpose, and FreeBSD provides
     * explicit_bzero().
     */
#if defined(__STDC_LIB_EXT1__) || (defined(__APPLE__) && defined(__MACH__))
    memset_s(b, len, 0, len);
#elif defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(b, len);
#elif defined(__FreeBSD__)
    explicit_bzero(b, len);
#else
    /* This fallback will not be optimized out, if the compiler has a conforming
     * implementation of "volatile". It also won't take advantage of any faster
     * intrinsics, so it may end up being slow.
     *
     * Implementation courtesy of this paper:
     * http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1381.pdf
     */
    volatile unsigned char *ptr = b;
    while (len--) {
        *ptr++ = 0x00;
    }
#endif
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    const char *key = "key.dat";
    const char *nonce = "nonce.dat";
    const char *ciphertext = "ciphertext.dat";
    const char *aad = "aad.dat";
    const char *tag = "tag.dat";
    const char *plaintext = "message.dat";

    uint8_t *key_data = NULL;
    size_t key_size = 0;
    uint8_t *nonce_data = NULL;
    uint8_t *ciphertext_data = NULL;
    uint8_t *aad_data = NULL;
    uint8_t *tag_data = NULL;

    iqr_Context *ctx = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &key, &nonce, &ciphertext, &aad, &tag, &plaintext);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], key, nonce, ciphertext, aad, tag, plaintext);

    /* IQR initialization that is not specific to Poly1305. */
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    ret = load_data(key, &key_data, &key_size);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    size_t nonce_size = 0;
    ret = load_data(nonce, &nonce_data, &nonce_size);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    size_t ciphertext_size = 0;
    ret = load_data(ciphertext, &ciphertext_data, &ciphertext_size);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    size_t aad_size = 0;
    ret = load_data(aad, &aad_data, &aad_size);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    size_t tag_size = 0;
    ret = load_data(tag, &tag_data, &tag_size);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of Poly1305 by performing
     * ChaCha20-Poly1305 AEAD decryption.
     */
    ret = showcase_AEAD_chacha20_poly1305_decrypt(ctx, key_data, key_size, nonce_data, nonce_size, ciphertext_data,
        ciphertext_size, aad_data, aad_size, tag_data, tag_size, plaintext);

cleanup:
    free(tag_data);
    tag_data = NULL;
    free(aad_data);
    aad_data = NULL;
    free(ciphertext_data);
    ciphertext_data = NULL;
    free(nonce_data);
    nonce_data = NULL;
    /* Keys are private, sensitive data, be sure to clear memory containing them
     * when you're done.
     */
    if (key_data != NULL) {
        secure_memzero(key_data, key_size);
    }
    free(key_data);
    key_data = NULL;
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
