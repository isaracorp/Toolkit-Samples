/** @file main.c Demonstrate the use of IQR's McEliece QC-MDPC cryptosystem
 * implementation.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_mceliece.h"
#include "iqr_retval.h"
#include "iqr_rng.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases McEliece QC-MDPC encryption.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_mceliece_encryption(const iqr_RNG *rng, const iqr_McElieceParams *params, const char *pubkey_file,
    const char *plaintext_file, const char * ciphertext_file)
{
    size_t ciphertext_size = 0;
    size_t plaintext_size = 0;
    size_t pubkey_dat_size = 0;

    uint8_t *ciphertext = NULL;
    uint8_t *plaintext = NULL;
    uint8_t *pubkey_dat = NULL;

    iqr_McEliecePublicKey *pubkey = NULL;

    iqr_retval ret = load_data(pubkey_file, &pubkey_dat, &pubkey_dat_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = load_data(plaintext_file, &plaintext, &plaintext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_McElieceImportPublicKey(params, pubkey_dat, pubkey_dat_size, &pubkey);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_McElieceImportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Get the ciphertext size, so that we can allocate a buffer big enough to
     * hold the ciphertext.
     */
    ret = iqr_McElieceGetCiphertextSize(params, plaintext_size, &ciphertext_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_McElieceGetCiphertextSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ciphertext = calloc(1, ciphertext_size);
    if (ciphertext == NULL) {
        fprintf(stderr, "Failed on memory allocation.\n");
        ret = IQR_ENOMEM;
        goto end;
    }

    /* Perform McEliece QC-MDPC encryption. */
    ret = iqr_McElieceEncrypt(pubkey, rng, plaintext, plaintext_size, ciphertext, ciphertext_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_McElieceEncrypt(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(ciphertext_file, ciphertext, ciphertext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "McEliece QC-MDPC encryption completed.\n");

end:
    free(ciphertext);
    free(plaintext);
    free(pubkey_dat);
    iqr_McElieceDestroyPublicKey(&pubkey);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of McEliece QC-MDPC parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_mceliece_params_creation(const iqr_Context *ctx, iqr_McElieceKeySize public_key_size,
    iqr_McElieceParams **params)
{
    /* Create McEliece parameters. */
    iqr_retval ret = iqr_McElieceCreateParams(ctx, IQR_HASHALGO_SHA2_256, public_key_size, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_McElieceCreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "McEliece QC-MDPC parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// McEliece.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Initialize the toolkit by creating a context, registering hash
// algorithm, and creating a RNG object.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_RNG **rng)
{
    /* Create a context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "The context has been created.\n");

    /* Globally register the hashing functions. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "Hash functions have been registered in the context.\n");

    /* Create a HMAC DRBG object. */
    ret = iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA2_256, rng);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGCreateHMACDRBG(): %s\n", iqr_StrError(ret));
        return ret;
    }

    time_t seed = time(NULL);

    ret = iqr_RNGInitialize(*rng, (void *) &seed, sizeof(seed));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGInitialize(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "RNG object has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// These functions are designed to help the end user use the sample or are
// generic utility functions. This section has little value to the developer
// trying to learn how to use the toolkit.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Generic POSIX file stream I/O operations.
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
        /* calloc() with a param of 0 could return a pointer or NULL depending
         * on implementation, so skip all this when the size is 0 so we
         * consistently return NULL with a size of 0.
         *
         * In some samples it's useful to take empty files as input so users
         * can pass NULL or 0 for optional parameters.
         */
        tmp = calloc(1, tmp_size);
        if (tmp == NULL) {
            fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
            ret = IQR_EBADVALUE;
            goto end;
        }

        size_t read_size = fread(tmp, 1, tmp_size, fp);;
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
// ---------------------------------------------------------------------------------------------------------------------------------

static void usage(void)
{
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "mceliece_encrypt {[--security <level>] | [--keysize <value>]}\n");
    fprintf(stdout, "[--pub <filename>] [--plaintext <filename>] [--ciphertext <filename>]\n");
    fprintf(stdout, "    Valid security level are:\n");
    fprintf(stdout, "        * 128\n");
    fprintf(stdout, "        * 256\n");
    fprintf(stdout, "    Valid keysize values are:\n");
    fprintf(stdout, "        * 9857\n");
    fprintf(stdout, "        * 14866\n");
    fprintf(stdout, "        * 20409\n");
    fprintf(stdout, "        * 32771\n");
    fprintf(stdout, "        * 45062\n");
    fprintf(stdout, "        * 61449\n");
    fprintf(stdout, "    Default for the sample (when no option is specified):\n");
    fprintf(stdout, "        --keysize 9857\n");
    fprintf(stdout, "        --pub pub.key\n");
    fprintf(stdout, "        --plaintext message.dat\n");
    fprintf(stdout, "        --ciphertext ciphertext.dat\n");
}

/* Tests if two parameters match.
 * Returns 0 if the two parameter match, non-zero otherwise.
 * Parameters are expected to be less than 32 characters in length.
 */
static int paramcmp(const char *p1 , const char *p2)
{
    const size_t max_param_size = 32;
    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }
    return strncmp(p1, p2, max_param_size);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, iqr_McElieceKeySize public_key_size, const char *pub, const char *plain, const char *cipher)
{
    size_t keysize = 0;
    uint32_t security_level = 0;

    if (public_key_size == IQR_MCELIECE_PUBKEY9857) {
        keysize = 9857;
        security_level = 128;
    } else if (public_key_size == IQR_MCELIECE_PUBKEY14866) {
        keysize = 14866;
        security_level = 128;
    } else if (public_key_size == IQR_MCELIECE_PUBKEY20409) {
        keysize = 20409;
        security_level = 128;
    } else if (public_key_size == IQR_MCELIECE_PUBKEY32771) {
        keysize = 32771;
        security_level = 256;
    } else if (public_key_size == IQR_MCELIECE_PUBKEY45062) {
        keysize = 45062;
        security_level = 256;
    } else if (public_key_size == IQR_MCELIECE_PUBKEY61449) {
        keysize = 61449;
        security_level = 256;
    }

    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    plaintext file: %s\n", plain);
    fprintf(stdout, "    ciphertext file: %s\n", cipher);
    fprintf(stdout, "    security level: %d\n", security_level);
    fprintf(stdout, "    key size: %zu\n", keysize);
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, iqr_McElieceKeySize *public_key_size, const char **public_key_file,
    const char **plaintext_file, const char **ciphertext_file)
{

    bool security_level_set = false;
    bool keysize_value_set = false;

    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--security") == 0) {
            /* [--security <level>] */
            if (keysize_value_set) {
                usage();
                return IQR_EBADVALUE;
            }
            i++;
            if (paramcmp(argv[i], "128") == 0) {
                *public_key_size = IQR_MCELIECE_PUBKEY9857;
            } else if (paramcmp(argv[i], "256") == 0) {
                *public_key_size = IQR_MCELIECE_PUBKEY32771;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
            security_level_set = true;
        } else if (paramcmp(argv[i], "--keysize") == 0) {
            /* [--keysize <value>] */
            if (security_level_set) {
                usage();
                return IQR_EBADVALUE;
            }
            i ++;
            if (paramcmp(argv[i], "9857") == 0) {
                *public_key_size = IQR_MCELIECE_PUBKEY9857;
            } else if (paramcmp(argv[i], "14866") == 0) {
                *public_key_size = IQR_MCELIECE_PUBKEY14866;
            } else if (paramcmp(argv[i], "20409") == 0) {
                *public_key_size = IQR_MCELIECE_PUBKEY20409;
            } else if (paramcmp(argv[i], "32771") == 0) {
                *public_key_size = IQR_MCELIECE_PUBKEY32771;
            } else if (paramcmp(argv[i], "45062") == 0) {
                *public_key_size = IQR_MCELIECE_PUBKEY45062;
            } else if (paramcmp(argv[i], "61449") == 0) {
                *public_key_size = IQR_MCELIECE_PUBKEY61449;
            }else {
                usage();
                return IQR_EBADVALUE;
            }
            keysize_value_set = true;
        } else if (paramcmp(argv[i], "--pub") == 0) {
            /* [--pub <filename>] */
            i++;
            *public_key_file = argv[i];
        } else if (paramcmp(argv[i], "--plaintext") == 0) {
            /* [--plaintext <filename>] */
            i++;
            *plaintext_file = argv[i];
        } else if (paramcmp(argv[i], "--ciphertext") == 0) {
            /* [--ciphertext <filename>] */
            i++;
            *ciphertext_file = argv[i];
        } else {
            usage();
            return IQR_EBADVALUE;
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
    iqr_Context * ctx = NULL;
    iqr_RNG *rng = NULL;
    iqr_McElieceParams *parameters = NULL;

    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    iqr_McElieceKeySize public_key_size = IQR_MCELIECE_PUBKEY9857;
    const char *public_key_file = "pub.key";
    const char *plaintext_file = "message.dat";
    const char *ciphertext_file = "ciphertext.dat";

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &public_key_size, &public_key_file, &plaintext_file, &ciphertext_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Show the parameters for the program. */
    preamble(argv[0], public_key_size, public_key_file, plaintext_file, ciphertext_file);

    /* IQR toolkit initialization. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the creation of McEliece QC-MDPC parameter structure. */
    ret = showcase_mceliece_params_creation(ctx, public_key_size, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase McEliece QC-MDPC encryption. */
    ret = showcase_mceliece_encryption(rng, parameters, public_key_file,plaintext_file, ciphertext_file);

cleanup:
    iqr_McElieceDestroyParams(&parameters);
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
