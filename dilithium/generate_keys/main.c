/** @file main.c
 *
 * @brief Generate keys using the toolkit's Dilithium Signature scheme.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iqr_context.h"
#include "iqr_dilithium.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"dilithium_generate_keys [--variant 80|128|160] [--pub <filename>]\n"
"  [--priv <filename>]\n"
"\n"
"    Defaults:\n"
"        --variant 128\n"
"        --pub pub.key\n"
"        --priv priv.key\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the generation of Dilithium public and private keys
// for signing.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_dilithium_keygen(const iqr_Context *ctx, const iqr_RNG *rng, const iqr_DilithiumVariant *variant,
    const char *pub_file, const char *priv_file)
{
    iqr_DilithiumParams *params = NULL;
    iqr_DilithiumPrivateKey *priv = NULL;
    iqr_DilithiumPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    iqr_retval ret = iqr_DilithiumCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Generate the keys. */
    ret = iqr_DilithiumCreateKeyPair(params, rng, &pub, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumCreateKeyPair(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Keys have been generated.\n");

    ret = iqr_DilithiumGetPublicKeySize(params, &pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumGetPublicKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    pub_raw = calloc(1, pub_raw_size);
    if (pub_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_DilithiumExportPublicKey(pub, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumExportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public Key has been exported.\n");

    ret = iqr_DilithiumGetPrivateKeySize(params, &priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumGetPrivateKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    priv_raw = calloc(1, priv_raw_size);
    if (priv_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_DilithiumExportPrivateKey(priv, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumExportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private Key has been exported.\n");

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

    iqr_DilithiumDestroyPrivateKey(&priv);
    iqr_DilithiumDestroyPublicKey(&pub);
    iqr_DilithiumDestroyParams(&params);

    free(pub_raw);
    free(priv_raw);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// the Dilithium signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_RNG **rng)
{
    /* Create a Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used with this Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_512, &IQR_HASH_DEFAULT_SHA3_512);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This lets us give satisfactory randomness to the algorithm. */
    ret = iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA3_512, rng);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGCreateHMACDRBG(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* The seed should be initialized from a guaranteed entropy source. This is
     * only an example; DO NOT INITIALIZE THE SEED LIKE THIS.
     */
    time_t seed = time(NULL);

    ret = iqr_RNGInitialize(*rng, (uint8_t *)&seed, sizeof(seed));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGInitialize(): %s\n", iqr_StrError(ret));
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

static void preamble(const char *cmd, const iqr_DilithiumVariant *variant, const char *pub, const char *priv)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_DILITHIUM_80) {
        fprintf(stdout, "    variant: IQR_DILITHIUM_80\n");
    } else if (variant == &IQR_DILITHIUM_128) {
        fprintf(stdout, "    variant: IQR_DILITHIUM_128\n");
    } else {
        fprintf(stdout, "    variant: IQR_DILITHIUM_160\n");
    }
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "\n");
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_DilithiumVariant **variant, const char **pub,
    const char **priv)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant 80|128|160] */
            i++;
            if (paramcmp(argv[i], "80") == 0) {
                *variant = &IQR_DILITHIUM_80;
            } else if (paramcmp(argv[i], "128") == 0) {
                *variant = &IQR_DILITHIUM_128;
            } else if (paramcmp(argv[i], "160") == 0) {
                *variant = &IQR_DILITHIUM_160;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--pub") == 0) {
            /* [--pub <filename>] */
            i++;
            *pub = argv[i];
        } else if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *priv = argv[i];
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
    const iqr_DilithiumVariant *variant = &IQR_DILITHIUM_128;
    const char *pub = "pub.key";
    const char *priv = "priv.key";

    iqr_Context *ctx = NULL;
    iqr_RNG *rng = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &pub, &priv);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], variant, pub, priv);

    /* IQR initialization that is not specific to Dilithium. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the generation of Dilithium public/private keys. */
    ret = showcase_dilithium_keygen(ctx, rng, variant, pub, priv);

cleanup:
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
