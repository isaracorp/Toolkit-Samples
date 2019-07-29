/** @file main.c
 *
 * @brief Demonstrate the toolkit's FrodoKEM key encapsulation mechanism.
 *
 * @copyright Copyright (C) 2018-2019, ISARA Corporation
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
#include "iqr_frodokem.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"frodokem_encapsulate [--variant AES|SHAKE] [--pub <filename>]\n"
"  [--ciphertext <filename>] [--shared <filename>]\n"
"    Default for the sample (when no option is specified):\n"
"        --variant AES\n"
"        --pub pub.key\n"
"        --ciphertext ciphertext.dat\n"
"        --shared shared.key\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases FrodoKEM encapsulation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_frodokem_encapsulation(const iqr_RNG *rng, const iqr_FrodoKEMParams *params, const char *pubkey_file,
    const char *ciphertext_file, const char *sharedkey_file)
{
    uint8_t ciphertext[IQR_FRODOKEM_CIPHERTEXT_SIZE] = { 0 };
    uint8_t sharedkey[IQR_FRODOKEM_SHARED_KEY_SIZE] = { 0 };

    uint8_t *pubkey_dat = NULL;
    size_t pubkey_dat_size = sizeof(pubkey_dat);
    iqr_FrodoKEMPublicKey *pubkey = NULL;

    iqr_retval ret = load_data(pubkey_file, &pubkey_dat, &pubkey_dat_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_FrodoKEMImportPublicKey(params, pubkey_dat, pubkey_dat_size, &pubkey);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoKEMImportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Perform FrodoKEM encapsulation. */
    ret = iqr_FrodoKEMEncapsulate(pubkey, rng, ciphertext, sizeof(ciphertext), sharedkey, sizeof(sharedkey));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoKEMEncapsulate(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(ciphertext_file, ciphertext, sizeof(ciphertext));
    if (ret != IQR_OK) {
        goto end;
    }

    ret = save_data(sharedkey_file, sharedkey, sizeof(sharedkey));
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "FrodoKEM encapsulation completed.\n");

end:
    iqr_FrodoKEMDestroyPublicKey(&pubkey);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of FrodoKEM parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_frodokem_params_creation(const iqr_Context *ctx, const iqr_FrodoKEMVariant *variant,
    iqr_FrodoKEMParams **params)
{
    /* Create frodokem parameters. */
    iqr_retval ret = iqr_FrodoKEMCreateParams(ctx, variant, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoKEMCreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "FrodoKEM parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// FrodoKEM.
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

    /* This sets the SHA2-256 functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This lets us give satisfactory randomness to the algorithm. */
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
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const iqr_FrodoKEMVariant *variant, const char *pub, const char *cipher,
    const char *sharedkey)
{
    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    ciphertext file: %s\n", cipher);
    fprintf(stdout, "    shared key file: %s\n", sharedkey);
    if (variant == &IQR_FRODOKEM_976_AES) {
        fprintf(stdout, "    variant: AES\n");
    } else {
        fprintf(stdout, "    variant: SHAKE\n");
    }
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_FrodoKEMVariant **variant, const char **public_key_file,
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
        } else if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant AES|SHAKE] */
            i++;
            if (paramcmp(argv[i], "AES") == 0) {
                *variant = &IQR_FRODOKEM_976_AES;
            } else if  (paramcmp(argv[i], "SHAKE") == 0) {
                *variant = &IQR_FRODOKEM_976_SHAKE;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else {
            fprintf(stdout, "%s", usage_msg);
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
    /* Default values.  Please adjust the usage message if you make changes
     * here.
     */
    const iqr_FrodoKEMVariant *variant = &IQR_FRODOKEM_976_AES;
    const char *public_key_file = "pub.key";
    const char *ciphertext_file = "ciphertext.dat";
    const char *sharedkey_file = "shared.key";

    iqr_Context * ctx = NULL;
    iqr_RNG *rng = NULL;
    iqr_FrodoKEMParams *parameters = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &public_key_file, &ciphertext_file, &sharedkey_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Show the parameters for the program. */
    preamble(argv[0], variant, public_key_file, ciphertext_file, sharedkey_file);

    /* IQR toolkit initialization. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the creation of FrodoKEM parameter structure. */
    ret = showcase_frodokem_params_creation(ctx, variant, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase FrodoKEM encapsulation. */
    ret = showcase_frodokem_encapsulation(rng, parameters, public_key_file, ciphertext_file, sharedkey_file);

cleanup:
    iqr_FrodoKEMDestroyParams(&parameters);
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
