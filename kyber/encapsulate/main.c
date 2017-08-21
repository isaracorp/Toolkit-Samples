/** @file main.c Demonstrate the toolkit's Kyber Key Encapsulation Mechanism.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_kyber.h"
#include "iqr_retval.h"
#include "iqr_rng.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases Kyber encapsulation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_kyber_encapsulation(const iqr_RNG *rng, const iqr_KyberParams *params, const char *pubkey_file,
    const char *ciphertext_file, const char *sharedkey_file)
{
    uint8_t *ciphertext = NULL;
    size_t ciphertext_size = 0;
    uint8_t sharedkey[IQR_KYBER_SHARED_KEY_SIZE] = {0};

    size_t pubkey_dat_size = 0;
    uint8_t *pubkey_dat = NULL;
    iqr_KyberPublicKey *pubkey = NULL;

    iqr_retval ret = load_data(pubkey_file, &pubkey_dat, &pubkey_dat_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_KyberImportPublicKey(params, pubkey_dat, pubkey_dat_size, &pubkey);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_KyberImportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_KyberGetCiphertextSize(params, &ciphertext_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_KyberGetCiphertextSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ciphertext = calloc(1, ciphertext_size);
    if (ciphertext == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    /* Perform Kyber encapsulation. */
    ret = iqr_KyberEncapsulate(pubkey, rng, ciphertext, ciphertext_size, sharedkey, sizeof(sharedkey));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_KyberEncapsulate(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(ciphertext_file, ciphertext, ciphertext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = save_data(sharedkey_file, sharedkey, sizeof(sharedkey));
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Kyber encapsulation completed.\n");

end:
    free(pubkey_dat);
    iqr_KyberDestroyPublicKey(&pubkey);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of Kyber parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_kyber_params_creation(const iqr_Context *ctx, const iqr_KyberVariant *variant, iqr_KyberParams **params)
{
    /* Create kyber parameters. */
    iqr_retval ret = iqr_KyberCreateParams(ctx, variant, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_KyberCreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "Kyber parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// kyber.
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

    /* This sets the hashing functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This will allow us to give satisfactory randomness to the algorithm. */
    ret =  iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA2_256, rng);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGCreateHMACDRBG(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* The seed should be initialized from a guaranteed entropy source. This is
     * only an example; DO NOT INITIALIZE THE SEED LIKE THIS.
     */
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
    fprintf(stdout, "kyber_encapsulate [--security 128|224] [--pub <filename>] [--ciphertext <filename>]\n"
            "  [--shared <filename>]\n");
    fprintf(stdout, "    Default for the sample (when no option is specified):\n");
    fprintf(stdout, "        --security 128\n");
    fprintf(stdout, "        --pub pub.key\n");
    fprintf(stdout, "        --ciphertext ciphertext.dat\n");
    fprintf(stdout, "        --shared shared.key\n");
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

static void preamble(const char *cmd, const char *pub, const char *cipher, const char *sharedkey)
{
    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    ciphertext file: %s\n", cipher);
    fprintf(stdout, "    shared key file: %s\n", sharedkey);
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_KyberVariant **variant, const char **public_key_file,
    const char **ciphertext_file, const char **sharedkey_file)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--pub") == 0) {
            /* [--pub <filename>] */
            i++;
            *public_key_file = argv[i];
        } else if (paramcmp(argv[i], "--ciphertext") == 0) {
            /* [--ciphertext <filename>] */
            i++;
            *ciphertext_file = argv[i];
        } else if (paramcmp(argv[i], "--shared") == 0) {
            /* [--shared <filename>] */
            i++;
            *sharedkey_file = argv[i];
        } else if (paramcmp(argv[i], "--security") == 0) {
            /* [--security 128|224] */
            i++;
            if (paramcmp(argv[i], "128") == 0) {
                *variant = &IQR_KYBER_128;
            } else if  (paramcmp(argv[i], "224") == 0) {
                *variant = &IQR_KYBER_224;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
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
    iqr_KyberParams *parameters = NULL;
    const iqr_KyberVariant *variant = &IQR_KYBER_128;

    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    const char *public_key_file = "pub.key";
    const char *ciphertext_file = "ciphertext.dat";
    const char *sharedkey_file = "shared.key";

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &public_key_file, &ciphertext_file, &sharedkey_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Show the parameters for the program. */
    preamble(argv[0], public_key_file, ciphertext_file, sharedkey_file);

    /* IQR toolkit initialization. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the creation of Kyber parameter structure. */
    ret = showcase_kyber_params_creation(ctx, variant, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase Kyber encapsulation. */
    ret = showcase_kyber_encapsulation(rng, parameters, public_key_file, ciphertext_file, sharedkey_file);

cleanup:
    iqr_KyberDestroyParams(&parameters);
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
