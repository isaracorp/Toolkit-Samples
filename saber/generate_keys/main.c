/** @file main.c
 *
 * @brief Demonstrate the toolkit's Saber key encapsulation mechanism.
 *
 * @copyright Copyright (C) 2019-2020, ISARA Corporation
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
#include "iqr_saber.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"saber_generate_keys [--variant light|saber|fire] [--pub <filename>]\n"
"  [--priv <filename>]\n"
"\n"
"    Defaults:\n"
"        --variant saber\n"
"        --pub pub.key\n"
"        --priv priv.key\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the generation of Saber public and
// private keys.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_saber_key_gen(const iqr_SaberParams *params, const iqr_RNG *rng, const char *pub_file,
    const char *priv_file)
{
    iqr_SaberPublicKey *pub = NULL;
    iqr_SaberPrivateKey *priv = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    fprintf(stdout, "Creating Saber key-pair.\n");

    iqr_retval ret = iqr_SaberCreateKeyPair(params, rng, &pub, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SaberCreateKeyPair(): %s\n", iqr_StrError(ret));
        goto end;
    }
    fprintf(stdout, "Saber public and private key-pair has been created\n");

    ret = iqr_SaberGetPublicKeySize(params, &pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SaberGetPublicKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    pub_raw = calloc(1, pub_raw_size);
    if (pub_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_SaberExportPublicKey(pub, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SaberExportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public key has been exported.\n");

    ret = iqr_SaberGetPrivateKeySize(params, &priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SaberGetPrivateKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    priv_raw = calloc(1, priv_raw_size);
    if (priv_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_SaberExportPrivateKey(priv, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SaberExportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key has been exported.\n");

    /* And finally, write the public and private key to disk. */
    ret = save_data(pub_file, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = save_data(priv_file, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Public and private keys have been saved to disk.\n");

end:
    if (priv_raw != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memzero(priv_raw, priv_raw_size);
    }

    iqr_SaberDestroyPublicKey(&pub);
    iqr_SaberDestroyPrivateKey(&priv);

    free(pub_raw);
    free(priv_raw);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of Saber parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_saber_params_creation(const iqr_Context *ctx, const iqr_SaberVariant *variant, iqr_SaberParams **params)
{
    /* Create saber parameters. */
    iqr_retval ret = iqr_SaberCreateParams(ctx, variant, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SaberCreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "Saber parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// Saber.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Initialize the toolkit by creating a context, registering hash
// algorithms, and creating an RNG object.
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

    /* This sets the SHA2-256 functions that will be used with this Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the SHA3-256 functions that will be used with this Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_256, &IQR_HASH_DEFAULT_SHA3_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the SHA3-512 functions that will be used with this Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_512, &IQR_HASH_DEFAULT_SHA3_512);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "Hash functions have been registered in the context.\n");

    /* Create an HMAC DRBG object. */
    ret = iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA2_256, rng);
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

static void preamble(const char *cmd, const iqr_SaberVariant *variant, const char * pub, const char * priv)
{
    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    private key file: %s\n", priv);
    if (variant == &IQR_LIGHT_SABER) {
        fprintf(stdout, "    variant: light\n");
    } else if (variant == &IQR_SABER) {
        fprintf(stdout, "    variant: saber\n");
    } else {
        fprintf(stdout, "    variant: fire\n");
    }
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_SaberVariant **variant, const char **public_key_file,
    const char **private_key_file)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--pub") == 0) {
            /* [--pub <filename>] */
            i++;
            *public_key_file = argv[i];
        } else if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *private_key_file = argv[i];
        } else if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant light|saber|fire] */
            i++;
            if (paramcmp(argv[i], "light") == 0) {
                *variant = &IQR_LIGHT_SABER;
            } else if (paramcmp(argv[i], "saber") == 0) {
                *variant = &IQR_SABER;
            } else if (paramcmp(argv[i], "fire") == 0) {
                *variant = &IQR_FIRE_SABER;
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
    const iqr_SaberVariant *variant = &IQR_SABER;
    const char *public_key_file = "pub.key";
    const char *private_key_file = "priv.key";

    iqr_Context * ctx = NULL;
    iqr_RNG *rng = NULL;
    iqr_SaberParams *parameters = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &public_key_file, &private_key_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Show the parameters for the program. */
    preamble(argv[0], variant, public_key_file, private_key_file);

    /* IQR toolkit initialization. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the creation of Saber parameter structure. */
    ret = showcase_saber_params_creation(ctx, variant, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the generation of Saber public/private keys. */
    ret = showcase_saber_key_gen(parameters, rng, public_key_file, private_key_file);

cleanup:
    iqr_SaberDestroyParams(&parameters);
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
