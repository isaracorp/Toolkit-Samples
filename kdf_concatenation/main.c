/** @file main.c Derive a key using the toolkit's NIST SP 800-56A Alternative 1
 * Concatenation KDF scheme.
 *
 * @copyright Copyright 2016-2017 ISARA Corporation
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
#include "iqr_kdf.h"
#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);
static void *secure_memset(void *b, int c, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases deriving a key using the toolkit's NIST SP 800-56A
// Alternative 1 Concatenation KDF scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_kdf_concatenation(const iqr_Context *ctx, iqr_HashAlgorithmType hash, const uint8_t *secret,
    size_t secret_size, const uint8_t *info, size_t info_size, size_t key_size, const char *key_file)
{
    uint8_t *key = calloc(1, key_size);
    if (key == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return IQR_ENOMEM;
    }

    iqr_retval ret = iqr_ConcatenationKDFDeriveKey(ctx, hash, secret, secret_size, info, info_size, key, key_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ConcatenationKDFDeriveKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Key has been derived.\n");

    ret = save_data(key_file, key, key_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Derived key has been saved to disk.\n");


end:
    if (key != NULL) {
        /* Keys are private, sensitive data, be sure to clear memory containing them when you're done */
        secure_memset(key, 0, key_size);
    }
    free(key);
    key = NULL;

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// KDF.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_HashAlgorithmType hash, const iqr_HashCallbacks *cb)
{
    /* Create a Global Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, hash, cb);
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
    fprintf(stdout, "kdf_concatenation [--hash sha2-256|sha2-512|sha3-256|sha3-512]\n"
        "  [--secret { string <secret> | file <filename> }]\n"
        "  [--info { string <info> | file <filename> | none }]\n"
        "  [--keysize <size>] [--keyfile <output_filename>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --hash sha2-256\n");
    fprintf(stdout, "        --secret string 000102030405060708090a0b0c0d0e0f\n");
    fprintf(stdout, "        --info string ISARA-kdf_concatenation\n");
    fprintf(stdout, "        --keysize 32\n");
    fprintf(stdout, "        --keyfile derived.key\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, iqr_HashAlgorithmType hash, const uint8_t *secret, const char *secret_file,
    const uint8_t *info, const char *info_file, size_t key_size, const char *key_file)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);

    if (IQR_HASHALGO_SHA2_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_256\n");
    } else if (IQR_HASHALGO_SHA2_512 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_512\n");
    } else if (IQR_HASHALGO_SHA3_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA3_256\n");
    } else if (IQR_HASHALGO_SHA3_512 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA3_512\n");
    }
    if (secret != NULL) {
        fprintf(stdout, "    shared secret: %s\n", secret);
    } else if (secret_file != NULL) {
        fprintf(stdout, "    shared secret file: %s\n", secret_file);
    }
    if (info != NULL) {
        fprintf(stdout, "    info: %s\n", info);
    } else if (info_file != NULL) {
        fprintf(stdout, "    info file: %s\n", info_file);
    } else {
        fprintf(stdout, "    no info\n");
    }
    fprintf(stdout, "    key size: %zu\n", key_size);
    fprintf(stdout, "    output key file: %s\n", key_file);
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

/* Parse a parameter string which is supposed to be a positive integer
 * and return the value or -1 if the string is not properly formatted.
 */
static int32_t get_positive_int_param(const char *p) {
    char *end = NULL;
    errno = 0;
    const long l = strtol(p, &end, 10);
    // Check for conversion errors.
    if (errno != 0) {
        return -1;
    }
    // Check that the string contained only a number and nothing else.
    if (end == NULL || end == p || *end != '\0' ) {
        return -1;
    }
    if (l < 0 || l > INT_MAX) {
        return -1;
    }
    return (int32_t)l;
}

static iqr_retval parse_commandline(int argc, const char **argv, iqr_HashAlgorithmType *hash, const iqr_HashCallbacks **cb,
    const uint8_t **secret, const char **secret_file, const uint8_t **info, const char **info_file,
    size_t *key_size, const char **key_file)
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
            if (paramcmp(argv[i], "sha2-256") == 0) {
                *hash = IQR_HASHALGO_SHA2_256;
                *cb = &IQR_HASH_DEFAULT_SHA2_256;
            } else if (paramcmp(argv[i], "sha2-512") == 0) {
                *hash = IQR_HASHALGO_SHA2_512;
                *cb = &IQR_HASH_DEFAULT_SHA2_512;
            } else if (paramcmp(argv[i], "sha3-256") == 0) {
                *hash = IQR_HASHALGO_SHA3_256;
                *cb = &IQR_HASH_DEFAULT_SHA3_256;
            } else if (paramcmp(argv[i], "sha3-512") == 0) {
                *hash = IQR_HASHALGO_SHA3_512;
                *cb = &IQR_HASH_DEFAULT_SHA3_512;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--secret") == 0) {
            /* [--secret { string <secret> | file <filename> }] */
            i++;
            if (i + 2 > argc) {
                usage();
                return IQR_EBADVALUE;
            }

            const char *param2 = argv[i];
            i++;
            if (paramcmp(param2, "string") == 0) {
                *secret = (const uint8_t *)argv[i];
                *secret_file = NULL;
            } else if (paramcmp(param2, "file") == 0) {
                *secret = NULL;
                *secret_file = argv[i];
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--info") == 0) {
            /* [--info { string <info> | file <filename> | none }] */
            i++;
            if (paramcmp(argv[i], "none") == 0) {
                *info = NULL;
                *info_file = NULL;
            } else {
                if (i + 2 > argc) {
                    usage();
                    return IQR_EBADVALUE;
                }

                const char *param2 = argv[i];
                i++;
                if (paramcmp(param2, "string") == 0) {
                    *info = (const uint8_t *)argv[i];
                    *info_file = NULL;
                } else if (paramcmp(param2, "file") == 0) {
                    *info = NULL;
                    *info_file = argv[i];
                } else {
                    usage();
                    return IQR_EBADVALUE;
                }
            }
        } else if (paramcmp(argv[i], "--keysize") == 0) {
            /* [--keysize <output key size>] */
            i++;
            int32_t sz  = get_positive_int_param(argv[i]);
            if (sz <= 0) {
                usage();
                return IQR_EBADVALUE;
            }
            *key_size = (size_t)sz;
        } else if (paramcmp(argv[i], "--keyfile") == 0) {
            /* [--keyfile <output key file>] */
            i++;
            *key_file = argv[i];
        }
        i++;
    }
    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Secure (not really) memset().
// ---------------------------------------------------------------------------------------------------------------------------------

static void *secure_memset(void *b, int c, size_t len)
{
    /** This memset() is NOT secure. It could and probably will be optimized out by the compiler. There isn't a secure,
     * portable memset() available before C11 which provides memset_s(). Windows also provides SecureZeroMemory().
     *
     * This is just for sample purposes, do your own due diligence when choosing a secure memset() so you can securely
     * clear sensitive data.
     */
    return memset(b, c, len);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    iqr_HashAlgorithmType hash = IQR_HASHALGO_SHA2_256;
    const iqr_HashCallbacks *cb = &IQR_HASH_DEFAULT_SHA2_256;
    const uint8_t *secret = (const uint8_t *)"000102030405060708090a0b0c0d0e0f";
    const char *secret_file = NULL;
    const uint8_t *info = (const uint8_t *)"ISARA-kdf_concatenation";
    const char *info_file = NULL;
    size_t key_size = 32;
    const char *key_file = "derived.key";

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &hash, &cb, &secret, &secret_file, &info, &info_file, &key_size, &key_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], hash, secret, secret_file, info, info_file, key_size, key_file);

    /* IQR initialization that is not specific to KDF. */
    iqr_Context *ctx = NULL;
    uint8_t *loaded_secret = NULL;
    uint8_t *loaded_info = NULL;
    ret = init_toolkit(&ctx, hash, cb);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /** Decide whether we're using a shared secret string from the command line
     * or a file */
    size_t secret_size = 0;
    if (secret != NULL) {
        secret_size = strlen((const char *)secret);
    } else if (secret_file != NULL) {
        ret = load_data(secret_file, &loaded_secret, &secret_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        secret = loaded_secret;
    }

    /** Decide whether we're using other info data from the command line or a
     * file. The other info is defined per the algorithm specification.
     */
    size_t info_size = 0;
    if (info != NULL) {
        info_size = strlen((const char *)info);
    } else if (info_file != NULL) {
        ret = load_data(info_file, &loaded_info, &info_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        info = loaded_info;
    }

    /** This function showcases the usage of NIST SP 800-56A Alternative 1
     * Concatenation key derivation.
     */
    ret = showcase_kdf_concatenation(ctx, hash, secret, secret_size, info, info_size, key_size, key_file);

    /* KDF secrets are private, sensitive data, be sure to clear memory containing them when you're done */
    if (loaded_secret != NULL) {
        secure_memset(loaded_secret, 0, secret_size);
    }

cleanup:
    free(loaded_info);
    loaded_info = NULL;
    free(loaded_secret);
    loaded_secret = NULL;
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
