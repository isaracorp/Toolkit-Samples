/** @file main.c Create a Hash using the IQR Toolkit.
 *
 * @copyright Copyright 2016 ISARA Corporation
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

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases our hashing implementations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_hash(iqr_Context *ctx, iqr_HashAlgorithmType hash_alg, const char *salt_file, const char *message_file)
{
    uint8_t *digest = NULL;
    uint8_t *salt = NULL;
    size_t salt_size = 0;
    uint8_t *message = NULL;
    size_t message_size = 0;

    iqr_Hash *hash = NULL;

    iqr_retval ret = IQR_OK;

    if (salt_file != NULL) {
        ret = load_data(salt_file, &salt, &salt_size);
        if (ret != IQR_OK) {
            goto end;
        }
    }

    ret = load_data(message_file, &message, &message_size);
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

    /* If we're using randomized hashing, apply the salt. */
    if (salt_file != NULL) {
        ret = iqr_HashSetSalt(hash, salt, salt_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_HashSetSalt(): %s\n", iqr_StrError(ret));
            goto end;
        }
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
    free(salt);
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

    /* This sets the hashing functions that will be used globally. */
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
// Generic Posix file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size)
{
    FILE *fp = fopen(fname, "r");
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
        /* calloc with a param of 0 could return a pointer or NULL depending on implementation,
         * so skip all this when the size is 0 so we consistently return NULL with a size of 0.
         * In some samples it's useful to take empty files as input so users can pass NULL or 0
         * for optional parameters.
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
    fprintf(stdout, "hash [--hash sha2-256|sha2-512|sha3-256|sha3-512] [--salt <filename>]\n"
        "  [--message <filname>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --hash sha2-512\n");
    fprintf(stdout, "        --message message.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, iqr_HashAlgorithmType hash_alg, const char *salt_file, const char *message_file)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);

    if (IQR_HASHALGO_SHA2_256 == hash_alg) {
        fprintf(stdout, "    hash: IQR_HASHALGO_SHA2_256\n");
    } else if (IQR_HASHALGO_SHA2_512 == hash_alg) {
        fprintf(stdout, "    hash: IQR_HASHALGO_SHA2_512\n");
    } else if (IQR_HASHALGO_SHA3_256 == hash_alg) {
        fprintf(stdout, "    hash: IQR_HASHALGO_SHA3_256\n");
    } else if (IQR_HASHALGO_SHA3_512 == hash_alg) {
        fprintf(stdout, "    hash: IQR_HASHALGO_SHA3_512\n");
    } else {
        fprintf(stdout, "    hash: INVALID\n");
    }

    if (salt_file != NULL) {
        fprintf(stdout, "    salt data file: %s\n", salt_file);
    }

    fprintf(stdout, "    message data file: %s\n", message_file);
    fprintf(stdout, "\n");
}

/* Tests if two parameters match.
 * Returns 0 if the two parameter match.
 * Non-zero otherwise.
 *
 * Parameters are expected to be less than 32 characters in length
 */
static int paramcmp(const char *p1 , const char *p2) {
    const size_t max_param_size = 32; //arbitrary, but reasonable.
    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }
    return strncmp(p1, p2, max_param_size);
}

static iqr_retval parse_commandline(int argc, const char **argv, iqr_HashAlgorithmType *hash_alg, const iqr_HashCallbacks **cb,
    const char **salt_file, const char **message_file)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--hash") == 0) {
            /* [--hash sha2-256|sha2-512|sha3-256|sha3-512] */
            i++;
            if  (paramcmp(argv[i], "sha2-256") == 0) {
                *hash_alg = IQR_HASHALGO_SHA2_256;
                *cb = &IQR_HASH_DEFAULT_SHA2_256;
            } else if (paramcmp(argv[i], "sha2-512") == 0) {
                *hash_alg = IQR_HASHALGO_SHA2_512;
                *cb = &IQR_HASH_DEFAULT_SHA2_512;
            } else if (paramcmp(argv[i], "sha3-256") == 0) {
                *hash_alg = IQR_HASHALGO_SHA3_256;
                *cb = &IQR_HASH_DEFAULT_SHA3_256;
            } else if (paramcmp(argv[i], "sha3-512") == 0) {
                *hash_alg = IQR_HASHALGO_SHA3_512;
                *cb = &IQR_HASH_DEFAULT_SHA3_512;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--salt") == 0) {
           /* [--salt <filename>] */
           i++;
           *salt_file = argv[i];
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
    /* Default values.  Please adjust the usage() message if you make changes
     *  here.
     */
    const char *salt_file = NULL;
    const char *message_file = "message.dat";
    iqr_HashAlgorithmType hash_alg = IQR_HASHALGO_SHA2_512;
    const iqr_HashCallbacks *cb = &IQR_HASH_DEFAULT_SHA2_512;

    iqr_Context *ctx = NULL;

    /* If the command line arguments were not sane, this function will exit
     * the process.
     */
    iqr_retval ret = parse_commandline(argc, argv, &hash_alg, &cb, &salt_file, &message_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], hash_alg, salt_file, message_file);

    /* IQR initialization that is not specific to hashing. */
    ret = init_toolkit(&ctx, hash_alg, cb);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the toolkit's hashing implementations. */
    ret = showcase_hash(ctx, hash_alg, salt_file, message_file);

cleanup:
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
