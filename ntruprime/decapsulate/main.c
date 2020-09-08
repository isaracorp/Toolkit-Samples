/** @file main.c
 *
 * @brief Demonstrate the toolkit's NTRUPrime key encapsulation mechanism.
 *
 * @copyright Copyright (C) 2017-2020, ISARA Corporation
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
#include "iqr_ntruprime.h"
#include "iqr_retval.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"ntruprime_decapsulate [--variant 653|761|857] [--priv <filename>] [--ciphertext <filename>]\n"
"  [--shared <filename>]\n"
"\n"
"    Defaults:\n"
"        --variant 761\n"
"        --priv priv.key\n"
"        --ciphertext ciphertext.dat\n"
"        --shared shared.key\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases NTRUPrime decapsulation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_ntruprime_decapsulation(const iqr_NTRUPrimeParams *params, const char *privkey_file,
    const char * ciphertext_file, const char *sharedkey_file)
{
    size_t ciphertext_size = 0;
    size_t privkey_dat_size = 0;

    uint8_t *ciphertext = NULL;
    uint8_t *privkey_dat = NULL;

    uint8_t sharedkey[IQR_NTRUPRIME_SHARED_KEY_SIZE];

    iqr_NTRUPrimePrivateKey *privkey = NULL;

    iqr_retval ret = load_data(privkey_file, &privkey_dat, &privkey_dat_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = load_data(ciphertext_file, &ciphertext, &ciphertext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_NTRUPrimeImportPrivateKey(params, privkey_dat, privkey_dat_size, &privkey);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NTRUPrimeImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Perform NTRUPrime decapsulation. */
    ret = iqr_NTRUPrimeDecapsulate(privkey, ciphertext, ciphertext_size, sharedkey, sizeof(sharedkey));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NTRUPrimeDecapsulate(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(sharedkey_file, sharedkey, sizeof(sharedkey));
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "NTRUPrime decapsulation completed.\n");

end:
    if (privkey_dat != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memzero(privkey_dat, privkey_dat_size);
    }
    free(ciphertext);
    free(privkey_dat);
    iqr_NTRUPrimeDestroyPrivateKey(&privkey);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of NTRUPrime parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_ntruprime_params_creation(const iqr_Context *ctx, const iqr_NTRUPrimeVariant *variant,
    iqr_NTRUPrimeParams **params)
{
    /* Create NTRUPrime parameters. */
    iqr_retval ret = iqr_NTRUPrimeCreateParams(ctx, variant, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NTRUPrimeCreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "NTRUPrime parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Initialize the toolkit by creating a context and registering hash algorithm.
//
// For NTRUPrime IQR_HASHALGO_SHA2_512 must be registered.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create a context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "The context has been created.\n");

    /* Register the hashing functions with the Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_512, &IQR_HASH_DEFAULT_SHA2_512);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "Hash functions have been registered in the context.\n");

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

static void preamble(const char *cmd, const iqr_NTRUPrimeVariant *variant, const char *priv, const char *cipher,
    const char *sharedkey)
{
    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    ciphertext file: %s\n", cipher);
    fprintf(stdout, "    shared key file: %s\n", sharedkey);
    if (variant == &IQR_SNTRUP_653) {
        fprintf(stdout, "    variant: IQR_SNTRUP_653\n");
    } else if (variant == &IQR_SNTRUP_761) {
        fprintf(stdout, "    variant: IQR_SNTRUP_761\n");
    } else {
        fprintf(stdout, "    variant: IQR_SNTRUP_857\n");
    }
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_NTRUPrimeVariant **variant,
    const char **private_key_file, const char **ciphertext_file, const char **sharedkey_file)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *private_key_file = argv[i];
        } else if (paramcmp(argv[i], "--ciphertext") == 0) {
            /* [--ciphertext <filename>] */
            i++;
            *ciphertext_file = argv[i];
        } else if (paramcmp(argv[i], "--shared") == 0) {
            /* [--shared <filename>] */
            i++;
            *sharedkey_file = argv[i];
        } else if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant 653|761|857] */
            i++;
            if (paramcmp(argv[i], "653") == 0) {
                *variant = &IQR_SNTRUP_653;
            } else if (paramcmp(argv[i], "761") == 0) {
                *variant = &IQR_SNTRUP_761;
            } else if (paramcmp(argv[i], "857") == 0) {
                *variant = &IQR_SNTRUP_857;
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
    /* Default values. Please adjust the usage message if you make changes
     * here.
     */
    const iqr_NTRUPrimeVariant *variant = &IQR_SNTRUP_761;
    const char *private_key_file = "priv.key";
    const char *ciphertext_file = "ciphertext.dat";
    const char *sharedkey_file = "shared.key";

    iqr_Context * ctx = NULL;
    iqr_NTRUPrimeParams *parameters = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &private_key_file, &ciphertext_file, &sharedkey_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Show the parameters for the program. */
    preamble(argv[0], variant, private_key_file, ciphertext_file, sharedkey_file);

    /* IQR toolkit initialization. */
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the creation of NTRUPrime parameter structure. */
    ret = showcase_ntruprime_params_creation(ctx, variant, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase NTRUPrime decapsulation. */
    ret = showcase_ntruprime_decapsulation(parameters, private_key_file, ciphertext_file, sharedkey_file);

cleanup:
    iqr_NTRUPrimeDestroyParams(&parameters);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
