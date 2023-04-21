/** @file main.c
 *
 * @brief Derive a key using the toolkit's RFC-5869 HKDF scheme.
 *
 * @copyright Copyright (C) 2016-2023, ISARA Corporation, All Rights Reserved.
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
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
//  --------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"kdf_rfc5869 [--hash sha2-256|sha2-384|sha2-512|sha3-256|sha3-512]\n"
"  [--salt { string <salt> | file <filename> | none }]\n"
"  [--ikm { string <ikm> | file <filename> }]\n"
"  [--info { string <info> | file <filename> | none }]\n"
"  [--keysize <size>] [--keyfile <output_filename>]\n"
"\n"
"    Defaults:\n"
"        --hash sha2-256\n"
"        --salt string DEADBEEF\n"
"        --ikm string 000102030405060708090a0b0c0d0e0f\n"
"        --info string ISARA-kdf_rfc5869\n"
"        --keysize 32\n"
"        --keyfile derived.key\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases deriving a key using the toolkit's RFC5869HKDF
// scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_kdf_rfc5869(const iqr_Context *ctx, iqr_HashAlgorithmType hash, const uint8_t *salt, size_t salt_size,
    const uint8_t *ikm, size_t ikm_size, const uint8_t *info, size_t info_size, size_t key_size, const char *key_file)
{
    uint8_t *key = calloc(1, key_size);
    if (key == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return IQR_ENOMEM;
    }

    iqr_retval ret = iqr_RFC5869HKDFDeriveKey(ctx, hash, salt, salt_size, ikm, ikm_size, info, info_size, key, key_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RFC5869HKDFDeriveKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Key has been derived.\n");

    ret = save_data(key_file, key, key_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Derived key has been saved to disk.\n");

end:
    /* Keys are private, sensitive data, be sure to clear memory containing
     * them when you're done.
     */
    secure_memzero(key, key_size);
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
    /* Create a Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used with this Context. */
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
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, iqr_HashAlgorithmType hash, const uint8_t *salt, const char *salt_file, const uint8_t *ikm,
    const char *ikm_file, const uint8_t *info, const char *info_file, size_t key_size, const char *key_file)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);

    if (IQR_HASHALGO_SHA2_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_256\n");
    } else if (IQR_HASHALGO_SHA2_384 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_384\n");
    } else if (IQR_HASHALGO_SHA2_512 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_512\n");
    } else if (IQR_HASHALGO_SHA3_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA3_256\n");
    } else if (IQR_HASHALGO_SHA3_512 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA3_512\n");
    }
    if (salt != NULL) {
        fprintf(stdout, "    salt: %s\n", salt);
    } else if (salt_file != NULL) {
        fprintf(stdout, "    salt file: %s\n", salt_file);
    } else {
        fprintf(stdout, "    no salt\n");
    }
    if (ikm != NULL) {
        fprintf(stdout, "    IKM: %s\n", ikm);
    } else if (ikm_file != NULL) {
        fprintf(stdout, "    IKM file: %s\n", ikm_file);
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

/* Parse a parameter string which is supposed to be a positive integer
 * and return the value or -1 if the string is not properly formatted.
 */
static int32_t get_positive_int_param(const char *p)
{
    char *end = NULL;
    errno = 0;
    const long l = strtol(p, &end, 10);
    // Check for conversion errors.
    if (errno != 0) {
        return -1;
    }
    // Check that the string contained only a number and nothing else.
    if (end == NULL || end == p || *end != '\0') {
        return -1;
    }
    if (l < 0 || l > INT_MAX) {
        return -1;
    }
    return (int32_t)l;
}

static iqr_retval parse_commandline(int argc, const char **argv, iqr_HashAlgorithmType *hash, const iqr_HashCallbacks **cb,
    const uint8_t **salt, const char **salt_file, const uint8_t **ikm, const char **ikm_file, const uint8_t **info,
    const char **info_file, size_t *key_size, const char **key_file)
{

    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--hash") == 0) {
            /* [--hash sha2-256|sha2-384|sha2-512|sha3-256|sha3-512] */
            i++;
            if (paramcmp(argv[i], "sha2-256") == 0) {
                *hash = IQR_HASHALGO_SHA2_256;
                *cb = &IQR_HASH_DEFAULT_SHA2_256;
            } else if (paramcmp(argv[i], "sha2-384") == 0) {
                *hash = IQR_HASHALGO_SHA2_384;
                *cb = &IQR_HASH_DEFAULT_SHA2_384;
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
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--salt") == 0) {
            /* [--salt { string <salt> | file <filename> | none }] */
            i++;
            if (paramcmp(argv[i], "none") == 0) {
                *salt = NULL;
                *salt_file = NULL;
            } else {
                if (i + 2 > argc) {
                    fprintf(stdout, "%s", usage_msg);
                    return IQR_EBADVALUE;
                }

                const char *param2 = argv[i];
                i++;
                if (paramcmp(param2, "string") == 0) {
                    *salt = (const uint8_t *)argv[i];
                    *salt_file = NULL;
                } else if (paramcmp(param2, "file") == 0) {
                    *salt = NULL;
                    *salt_file = argv[i];
                } else {
                    fprintf(stdout, "%s", usage_msg);
                    return IQR_EBADVALUE;
                }
            }
        } else if (paramcmp(argv[i], "--ikm") == 0) {
            /* [--ikm { string <ikm> | file <filename> }] */
            i++;
            if (i + 2 > argc) {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }

            const char *param2 = argv[i];
            i++;
            if (paramcmp(param2, "string") == 0) {
                *ikm = (const uint8_t *)argv[i];
                *ikm_file = NULL;
            } else if (paramcmp(param2, "file") == 0) {
                *ikm = NULL;
                *ikm_file = argv[i];
            } else {
                fprintf(stdout, "%s", usage_msg);
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
                    fprintf(stdout, "%s", usage_msg);
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
                    fprintf(stdout, "%s", usage_msg);
                    return IQR_EBADVALUE;
                }
            }
        } else if (paramcmp(argv[i], "--keysize") == 0) {
            /* [--keysize <output key size>] */
            i++;
            int32_t sz = get_positive_int_param(argv[i]);
            if (sz <= 0) {
                fprintf(stdout, "%s", usage_msg);
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
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* Default values. Please adjust the usage message if you make changes
     * here.
     */
    iqr_HashAlgorithmType hash = IQR_HASHALGO_SHA2_256;
    const iqr_HashCallbacks *cb = &IQR_HASH_DEFAULT_SHA2_256;
    const uint8_t *salt = (const uint8_t *)"DEADBEEF";
    const uint8_t *ikm = (const uint8_t *)"000102030405060708090a0b0c0d0e0f";
    const uint8_t *info = (const uint8_t *)"ISARA-kdf_rfc5869";
    size_t key_size = 32;
    const char *key_file = "derived.key";

    const char *salt_file = NULL;
    const char *ikm_file = NULL;
    const char *info_file = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &hash, &cb, &salt, &salt_file, &ikm, &ikm_file, &info, &info_file,
        &key_size, &key_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], hash, salt, salt_file, ikm, ikm_file, info, info_file, key_size, key_file);

    /* IQR initialization that is not specific to KDF. */
    iqr_Context *ctx = NULL;
    uint8_t *loaded_salt = NULL;
    uint8_t *loaded_ikm = NULL;
    size_t ikm_size = 0;
    uint8_t *loaded_info = NULL;
    ret = init_toolkit(&ctx, hash, cb);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Decide whether we're using a salt string from the command line or a
     * file.
     */
    size_t salt_size = 0;
    if (salt != NULL) {
        salt_size = strlen((const char *)salt);
    } else if (salt_file != NULL) {
        ret = load_data(salt_file, &loaded_salt, &salt_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        salt = loaded_salt;
    }

    /* Decide whether we're using IKM data from the command line or a file.
     * Initial keying material is usually a binary blob and so normally would
     * contain non-printable characters and couldn't be read from the command
     * line.
     */
    if (ikm != NULL) {
        ikm_size = strlen((const char *)ikm);
    } else if (ikm_file != NULL) {
        ret = load_data(ikm_file, &loaded_ikm, &ikm_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        ikm = loaded_ikm;
    }

    /* Decide whether we're using an info string from the command line or a
     * file.
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

    /* This function showcases the usage of RFC5869 key derivation. */
    ret = showcase_kdf_rfc5869(ctx, hash, salt, salt_size, ikm, ikm_size, info, info_size, key_size, key_file);

cleanup:
    if (loaded_ikm != NULL) {
        /* Initial keying material is private, sensitive data, be sure to clear
         * memory containing it when you're done.
         */
        secure_memzero(loaded_ikm, ikm_size);
    }
    free(loaded_info);
    loaded_info = NULL;
    free(loaded_ikm);
    loaded_ikm = NULL;
    free(loaded_salt);
    loaded_salt = NULL;

    iqr_DestroyContext(&ctx);

    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
