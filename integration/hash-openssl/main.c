/** @file main.c
 *
 * @brief Create a Hash using the toolkit and OpenSSL's SHA-256/SHA-512.
 *
 * @copyright Copyright (C) 2019-2021, ISARA Corporation, All Rights Reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "isara_samples.h"

#include <openssl/sha.h>

// OpenSSL APIs return 1 for success.
#define OPENSSL_OK 1

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
//  --------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"hash-openssl [--hash sha2-256|sha2-512] [--message <filename>]\n"
"\n"
"    Defaults:\n"
"        --hash sha2-512\n"
"        --message message.dat\n"
"\n"
"    SHA2-256 and SHA2-512 use OpenSSL's implementations rather than the\n"
"    toolkit's.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// OpenSSL's SHA2-256 implementation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval sha2_256_initialize(void **state)
{
    // Sanity-check inputs.
    if (state == NULL) {
        return IQR_ENULLPTR;
    }

    if (*state != NULL) {
        return IQR_EINVPTR;
    }

    // Allocate an OpenSSL SHA256_CTX to store the state.
    SHA256_CTX *ctx = NULL;
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return IQR_ENOMEM;
    }

    *state = ctx;

    return IQR_OK;
}

static iqr_retval sha2_256_begin(void *state)
{
    // Sanity-check inputs.
    if (state == NULL) {
        return IQR_EINVOBJECT;
    }

    SHA256_CTX *ctx = (SHA256_CTX *)state;

    // Let OpenSSL set up its context.
    int rc = SHA256_Init(ctx);
    if (rc != OPENSSL_OK) {
        return IQR_ENOTINIT;
    }

    return IQR_OK;
}

static iqr_retval sha2_256_update(void *state, const uint8_t *data, size_t data_size)
{
    // Sanity-check input.
    if (data == NULL && data_size != 0) {
        return IQR_ENULLPTR;
    }

    if (data_size == 0) {
        return IQR_OK;
    }

    // In this case, the state can't be NULL.
    if (state == NULL) {
        return IQR_EINVOBJECT;
    }

    SHA256_CTX *ctx = (SHA256_CTX *)state;

    // Pass the data pointer into the OpenSSL update function.
    int rc = SHA256_Update(ctx, data, data_size);
    if (rc != OPENSSL_OK) {
        // Update failed.
        return IQR_EINVOBJECT;
    }

    return IQR_OK;
}

static iqr_retval sha2_256_end(void *state, uint8_t *digest, size_t digest_size)
{
    // Sanity-check input.
    if (state == NULL || digest == NULL) {
        return IQR_ENULLPTR;
    }

    SHA256_CTX *ctx = (SHA256_CTX *)state;

    // Make sure there's enough room to store your digest.
    if (digest_size != IQR_SHA2_256_DIGEST_SIZE) {
        return IQR_EINVBUFSIZE;
    }

    // Pass the data pointer into the OpenSSL Final function.
    int rc = SHA256_Final(digest, ctx);
    if (rc != OPENSSL_OK) {
        return IQR_EINVOBJECT;
    }

    return IQR_OK;
}

static iqr_retval sha2_256_cleanup(void **state)
{
    SHA256_CTX *ctx = (SHA256_CTX *)*state;

    secure_memzero(ctx, sizeof(*ctx));
    free(ctx);
    *state = NULL;

    return IQR_OK;
}

// Create the callback structure.
static const iqr_HashCallbacks openssl_sha2_256 = {
    .initialize = sha2_256_initialize,
    .begin = sha2_256_begin,
    .update = sha2_256_update,
    .end = sha2_256_end,
    .cleanup = sha2_256_cleanup
};

// ---------------------------------------------------------------------------------------------------------------------------------
// OpenSSL's SHA2-512 implementation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval sha2_512_initialize(void **state)
{
    // Sanity-check inputs.
    if (state == NULL) {
        return IQR_ENULLPTR;
    }

    if (*state != NULL) {
        return IQR_EINVPTR;
    }

    // Allocate an OpenSSL SHA512_CTX to store the state.
    SHA512_CTX *ctx = NULL;
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return IQR_ENOMEM;
    }

    *state = ctx;

    return IQR_OK;
}

static iqr_retval sha2_512_begin(void *state)
{
    // Sanity-check inputs.
    if (state == NULL) {
        return IQR_ENULLPTR;
    }

    SHA512_CTX *ctx = (SHA512_CTX *)state;

    // Let OpenSSL set up its context.
    int rc = SHA512_Init(ctx);
    if (rc != OPENSSL_OK) {
        return IQR_ENOTINIT;
    }

    return IQR_OK;
}

static iqr_retval sha2_512_update(void *state, const uint8_t *buf, size_t buf_size)
{
    // Sanity-check input.
    if (buf == NULL && buf_size != 0) {
        return IQR_ENULLPTR;
    }

    if (buf_size == 0) {
        return IQR_OK;
    }

    // In this case, the state can't be NULL.
    if (state == NULL) {
        return IQR_ENULLPTR;
    }

    SHA512_CTX *ctx = (SHA512_CTX *)state;

    // Pass the buf pointer into the OpenSSL update function.
    int rc = SHA512_Update(ctx, buf, buf_size);
    if (rc != OPENSSL_OK) {
        // Update failed.
        return IQR_EINVOBJECT;
    }

    return IQR_OK;
}

static iqr_retval sha2_512_end(void *state, uint8_t *digest, size_t digest_size)
{
    // Sanity-check input.
    if (state == NULL || digest == NULL) {
        return IQR_ENULLPTR;
    }

    SHA512_CTX *ctx = (SHA512_CTX *)state;

    // Make sure there's enough room to store your digest.
    if (digest_size != IQR_SHA2_512_DIGEST_SIZE) {
        return IQR_EINVBUFSIZE;
    }

    // Pass the digest pointer into the OpenSSL final function.
    int rc = SHA512_Final(digest, ctx);
    if (rc != OPENSSL_OK) {
        return IQR_EINVOBJECT;
    }

    return IQR_OK;
}

static iqr_retval sha2_512_cleanup(void **state)
{
    SHA512_CTX *ctx = (SHA512_CTX *)*state;

    secure_memzero(ctx, sizeof(*ctx));
    free(ctx);
    *state = NULL;

    return IQR_OK;
}

// Create the callback structure.
static const iqr_HashCallbacks openssl_sha2_512 = {
    .initialize = sha2_512_initialize,
    .begin = sha2_512_begin,
    .update = sha2_512_update,
    .end = sha2_512_end,
    .cleanup = sha2_512_cleanup
};

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases our hashing implementations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_hash(iqr_Context *ctx, iqr_HashAlgorithmType hash_alg, const char *message_file)
{
    uint8_t *digest = NULL;
    uint8_t *message = NULL;
    size_t message_size = 0;

    iqr_Hash *hash = NULL;

    iqr_retval ret = load_data(message_file, &message, &message_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_HashCreate(ctx, hash_alg, &hash);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashCreate(): %s\n", iqr_StrError(ret));
        goto end;
    }

    size_t digest_size = 0;
    ret = iqr_HashGetDigestSize(hash, &digest_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashGetDigestSize(): %s\n", iqr_StrError(ret));
        goto end;
    }
    digest = calloc(1, digest_size);
    if (digest == NULL) {
        fprintf(stderr, "Failed to allocate space for the digest\n");
        ret = IQR_ENOMEM;
        goto end;
    }

    /* Finally, we hash the message.
     * The following iqr_HashBegin/iqr_HashUpdate/iqr_HashEnd calls could be
     * replaced with a single call to iqr_HashMessage like so:
     * ret = iqr_HashMessage(hash, message, message_size, digest, digest_size);
     */
    ret = iqr_HashBegin(hash);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashBegin(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_HashUpdate(hash, message, message_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashUpdate(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_HashEnd(hash, digest, digest_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashEnd(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* And now we publish the hash. */
    size_t i = 0;
    const size_t BYTES_PER_LINE = 32;
    fprintf(stdout, "Message hashes to:");
    for (i = 0; i < digest_size; i++) {
        if ((i % BYTES_PER_LINE) == 0) {
            fprintf(stdout, "\n");
        }
        fprintf(stdout, "%02x", digest[i]);
    }
    fprintf(stdout, "\n");

end:
    free(digest);
    free(message);
    iqr_HashDestroy(&hash);
    return ret;
}

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_HashAlgorithmType hash_alg, const iqr_HashCallbacks *cb)
{
    /* Create an IQR Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used with this Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, hash_alg, cb);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
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
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, iqr_HashAlgorithmType hash_alg, const char *message_file)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);

    if (IQR_HASHALGO_SHA2_256 == hash_alg) {
        fprintf(stdout, "    hash: IQR_HASHALGO_SHA2_256 (OpenSSL implementation)\n");
    } else if (IQR_HASHALGO_SHA2_512 == hash_alg) {
        fprintf(stdout, "    hash: IQR_HASHALGO_SHA2_512 (OpenSSL implementation)\n");
    } else {
        fprintf(stdout, "    hash: INVALID\n");
    }

    fprintf(stdout, "    message data file: %s\n", message_file);
    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, iqr_HashAlgorithmType *hash_alg, const iqr_HashCallbacks **cb,
    const char **message_file)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--hash") == 0) {
            /* [--hash sha2-256|sha2-512] */
            i++;
            if (paramcmp(argv[i], "sha2-256") == 0) {
                *hash_alg = IQR_HASHALGO_SHA2_256;
                *cb = &openssl_sha2_256;
            } else if (paramcmp(argv[i], "sha2-512") == 0) {
                *hash_alg = IQR_HASHALGO_SHA2_512;
                *cb = &openssl_sha2_512;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--message") == 0) {
            /* [--message <filename>] */
            i++;
            *message_file = argv[i];
        }
        i++;
    }

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* Default values. Please adjust the usage message if you make changes here.
     */
    const char *message_file = "message.dat";
    iqr_HashAlgorithmType hash_alg = IQR_HASHALGO_SHA2_512;
    const iqr_HashCallbacks *cb = &IQR_HASH_DEFAULT_SHA2_512;

    iqr_Context *ctx = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &hash_alg, &cb, &message_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], hash_alg, message_file);

    /* IQR initialization that is not specific to hashing. */
    ret = init_toolkit(&ctx, hash_alg, cb);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the toolkit's hashing implementations. */
    ret = showcase_hash(ctx, hash_alg, message_file);

cleanup:
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
