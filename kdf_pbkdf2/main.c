/** @file main.c Derive a key using the Toolkit's PBKDF2 KDF scheme.
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
#include "iqr_kdf.h"
#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);
static void *secure_memset(void *b, int c, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases deriving a key using the Toolkit's PBKDF2 KDF scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_kdf_pbkdf2(const iqr_Context *ctx, iqr_HashAlgorithmType hash, const uint8_t *password,
    size_t password_size, const uint8_t *salt, size_t salt_size, uint32_t iterations, size_t key_size, const char *key_file)
{
    uint8_t *key = calloc(1, key_size);
    if (key == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return IQR_ENOMEM;
    }

    iqr_retval ret = iqr_PBKDF2DeriveKey(ctx, hash, password, password_size, salt, salt_size, iterations, key, key_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_PBKDF2DeriveKey(): %s\n", iqr_StrError(ret));
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
// Generic Posix file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size)
{
    FILE *fp = fopen(fname, "w");
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
    fprintf(stdout, "kdf_pbkdf2 [--hash sha2-256|sha2-512|sha3-256|sha3-512]\n"
        "  [--pass { string <password> | file <filename> | none }]\n"
        "  [--salt { string <salt> | file <filename> | none }]\n"
        "  [--iter <iterations>] [--keysize <size>] [--keyfile <output_filename>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --hash sha2-256\n");
    fprintf(stdout, "        --pass string CorrectHorseBatteryStaple\n");
    fprintf(stdout, "        --salt string DEADBEEF\n");
    fprintf(stdout, "        --iter 1000\n");
    fprintf(stdout, "        --keysize 32\n");
    fprintf(stdout, "        --keyfile derived.key\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, iqr_HashAlgorithmType hash, const uint8_t *password, const char *password_file,
    const uint8_t *salt, const char *salt_file, uint32_t iterations, size_t key_size, const char *key_file)
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
    if (password != NULL) {
        fprintf(stdout, "    password: %s\n", password);
    } else if (password_file != NULL) {
        fprintf(stdout, "    password file: %s\n", password_file);
    } else {
        fprintf(stdout, "    no password\n");
    }
    if (salt != NULL) {
        fprintf(stdout, "    salt: %s\n", salt);
    } else if (salt_file != NULL) {
        fprintf(stdout, "    salt file: %s\n", salt_file);
    } else {
        fprintf(stdout, "    no salt\n");
    }
    fprintf(stdout, "    iterations: %d\n", iterations);
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
    const uint8_t **password, const char **password_file, const uint8_t **salt, const char **salt_file, uint32_t *iterations,
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
        } else if (paramcmp(argv[i], "--pass") == 0) {
            /* [--pass { string <password> | file <filename> | none }] */
            i++;
            if (paramcmp(argv[i], "none") == 0) {
                *password = NULL;
                *password_file = NULL;
            } else {
                if (i + 2 > argc) {
                    usage();
                    return IQR_EBADVALUE;
                }

                const char *param2 = argv[i];
                i++;
                if (paramcmp(param2, "string") == 0) {
                    *password = (const uint8_t *)argv[i];
                    *password_file = NULL;
                } else if (paramcmp(param2, "file") == 0) {
                    *password = NULL;
                    *password_file = argv[i];
                } else {
                    usage();
                    return IQR_EBADVALUE;
                }
            }
        } else if (paramcmp(argv[i], "--salt") == 0) {
            /* [--salt { string <salt> | file <filename> | none }] */
            i++;
            if (paramcmp(argv[i], "none") == 0) {
                *salt = NULL;
                *salt_file = NULL;
            } else {
                if (i + 2 > argc) {
                    usage();
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
                    usage();
                    return IQR_EBADVALUE;
                }
            }
        } else if (paramcmp(argv[i], "--iter") == 0) {
            /* [--iter <iterations>] */
            i++;
            int32_t iter = get_positive_int_param(argv[i]);
            if (iter <= 0) {
                usage();
                return IQR_EBADVALUE;
            }
            *iterations = (uint32_t)iter;
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
    const uint8_t *password = (const uint8_t *)"CorrectHorseBatteryStaple";
    const char *password_file = NULL;
    const uint8_t *salt = (const uint8_t *)"DEADBEEF";
    const char *salt_file = NULL;
    uint32_t iterations = 1000;
    size_t key_size = 32;
    const char *key_file = "derived.key";

    /* If the command line arguments were not sane, this function will exit
     * the process.
     */
    iqr_retval ret = parse_commandline(argc, argv, &hash, &cb, &password, &password_file, &salt, &salt_file, &iterations,
        &key_size, &key_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], hash, password, password_file, salt, salt_file, iterations, key_size, key_file);

    /* IQR initialization that is not specific to KDF. */
    iqr_Context *ctx = NULL;
    uint8_t *loaded_password = NULL;
    uint8_t *loaded_salt = NULL;
    ret = init_toolkit(&ctx, hash, cb);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Decide whether we're using a password string from the command line or a file */
    size_t password_size = 0;
    if (password != NULL) {
        password_size = strlen((const char *)password);
    } else if (password_file != NULL) {
        ret = load_data(password_file, &loaded_password, &password_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        password = loaded_password;
    }

    /* Decide whether we're using a salt string from the command line or a file */
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

    /* This function showcases the usage of PBKDF2 key derivation.
     */
    ret = showcase_kdf_pbkdf2(ctx, hash, password, password_size, salt, salt_size, iterations, key_size, key_file);

cleanup:
    free(loaded_salt);
    loaded_salt = NULL;
    free(loaded_password);
    loaded_password = NULL;
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
