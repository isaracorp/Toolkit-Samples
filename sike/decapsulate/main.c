/** @file main.c
 *
 * @brief Demonstrate the toolkit's SIKE key encapsulation mechanism.
 *
 * @copyright Copyright (C) 2016-2019, ISARA Corporation
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
#include "iqr_sike.h"
#include "iqr_retval.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Documeht the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"sike_decapsulate [--variant p503|p751] [--priv <filename>]\n"
"  [--ciphertext <filename>] [--shared <filename>]\n"
"    Default for the sample (when no option is specified):\n"
"        --variant p751\n"
"        --priv priv.key\n"
"        --ciphertext ciphertext.dat\n"
"        --shared shared.key\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases SIKE decapsulation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_sike_decapsulation(const iqr_SIKEParams *params, const char *privkey_file,
    const char * ciphertext_file, const char *sharedkey_file)
{
    size_t ciphertext_size = 0;
    size_t privkey_dat_size = 0;
    size_t sharedkey_size = 0;

    uint8_t *ciphertext = NULL;
    uint8_t *privkey_dat = NULL;
    uint8_t *sharedkey = NULL;

    iqr_SIKEPrivateKey *privkey = NULL;

    iqr_retval ret = load_data(privkey_file, &privkey_dat, &privkey_dat_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = load_data(ciphertext_file, &ciphertext, &ciphertext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_SIKEGetSharedKeySize(params, &sharedkey_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKEGetSharedKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    sharedkey = malloc(sharedkey_size);
    if (sharedkey == NULL) {
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_SIKEImportPrivateKey(params, privkey_dat, privkey_dat_size, &privkey);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKEImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Perform SIKE decapsulation. */
    ret = iqr_SIKEDecapsulate(privkey, ciphertext, ciphertext_size, sharedkey, sharedkey_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKEDecapsulate(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(sharedkey_file, sharedkey, sharedkey_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "SIKE decapsulation completed.\n");

end:
    if (privkey_dat != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memzero(privkey_dat, privkey_dat_size);
    }
    free(sharedkey);
    free(ciphertext);
    free(privkey_dat);
    iqr_SIKEDestroyPrivateKey(&privkey);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of SIKE parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_sike_params_creation(const iqr_Context *ctx, const iqr_SIKEVariant *variant, iqr_SIKEParams **params)
{
    /* Create sike parameters. */
    iqr_retval ret = iqr_SIKECreateParams(ctx, variant, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKECreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "SIKE parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// sike.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Initialize the toolkit by creating a context and registering hash algorithm.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create a context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the SHA3-256 functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_256, &IQR_HASH_DEFAULT_SHA3_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the SHA3-512 functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_512, &IQR_HASH_DEFAULT_SHA3_512);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "The context has been created.\n");

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

static void preamble(const char *cmd, const iqr_SIKEVariant *variant, const char *priv, const char *cipher, const char *sharedkey)
{
    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    if (variant == &IQR_SIKE_P751) {
        fprintf(stdout, "    variant: p751\n");
    } else {
        fprintf(stdout, "    variant: p503\n");
    }
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    ciphertext file: %s\n", cipher);
    fprintf(stdout, "    shared key file: %s\n", sharedkey);
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_SIKEVariant **variant, const char **private_key_file,
    const char **ciphertext_file, const char **sharedkey_file)
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
            /* [--variant p503|p751] */
            i++;
            if (paramcmp(argv[i], "p503") == 0) {
                *variant = &IQR_SIKE_P503;
            } else if  (paramcmp(argv[i], "p751") == 0) {
                *variant = &IQR_SIKE_P751;
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
    const iqr_SIKEVariant *variant = &IQR_SIKE_P751;
    const char *private_key_file = "priv.key";
    const char *ciphertext_file = "ciphertext.dat";
    const char *sharedkey_file = "shared.key";

    iqr_Context * ctx = NULL;
    iqr_SIKEParams *parameters = NULL;

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

    /* Showcase the creation of SIKE parameter structure. */
    ret = showcase_sike_params_creation(ctx, variant, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase SIKE decapsulation. */
    ret = showcase_sike_decapsulation(parameters, private_key_file, ciphertext_file, sharedkey_file);

cleanup:
    iqr_SIKEDestroyParams(&parameters);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
