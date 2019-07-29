/** @file main.c
 *
 * @brief Generate keys using the toolkit's Rainbow signature scheme.
 *
 * @copyright Copyright (C) 2017-2019, ISARA Corporation
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
#include "iqr_hash.h"
#include "iqr_rainbow.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "iqr_watchdog.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"rainbow_generate_keys [--security IIIc|Vc] [--pub <filename>]\n"
"  [--priv <filename>]\n"
"    Defaults are: \n"
"        --security IIIc\n"
"        --pub pub.key\n"
"        --priv priv.key\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the generation of Rainbow public and private keys for
// signing.
//
// This function assumes that all the parameter have already been validated.
// However, the function will exit early if there is a file system related
// failure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_rainbow_keygen(const iqr_Context *ctx, const iqr_RNG *rng, const iqr_RainbowVariant *variant,
    const char *pub_file, const char *priv_file)
{
    iqr_RainbowParams *params = NULL;
    iqr_RainbowPrivateKey *priv = NULL;
    iqr_RainbowPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    iqr_retval ret = iqr_RainbowCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Generate the keys. */
    ret = iqr_RainbowCreateKeyPair(params, rng, &pub, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowCreateKeyPair(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "\n");
    fprintf(stdout, "Keys have been generated.\n");

    ret = iqr_RainbowGetPublicKeySize(params, &pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowGetPublicKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    pub_raw = calloc(1, pub_raw_size);
    if (pub_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_RainbowExportPublicKey(pub, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowExportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public Key has been exported.\n");

    ret = iqr_RainbowGetPrivateKeySize(params, &priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowGetPrivateKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    priv_raw = calloc(1, priv_raw_size);
    if (pub_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_RainbowExportPrivateKey(priv, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowExportPrivateKey(): %s\n", iqr_StrError(ret));
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
    /* (Private) Keys are private, sensitive data, be sure to clear memory
     * containing them when you're done.
     */
    secure_memzero(priv_raw, sizeof(priv_raw));

    iqr_RainbowDestroyPrivateKey(&priv);
    iqr_RainbowDestroyPublicKey(&pub);
    iqr_RainbowDestroyParams(&params);

    free(pub_raw);
    free(priv_raw);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// the Rainbow signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

// Provides a cheap progress indicator for key generation, which is a long-
// running task depending on your parameters.
static iqr_retval progress_watchdog(void *watchdog_data)
{
    (void)watchdog_data;  // Not used.

    fprintf(stdout, ".");
    fflush(stdout);

    return IQR_OK;
}

// Initialize the toolkit and the algorithms required by HSS.
static iqr_retval init_toolkit(iqr_Context **ctx, iqr_RNG **rng)
{
    /* Create a Global Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* Call this watchdog function periodically during long-running tasks. */
    ret = iqr_WatchdogRegisterCallback(*ctx, progress_watchdog, NULL);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_WatchdogRegisterCallback(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_384, &IQR_HASH_DEFAULT_SHA2_384);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_512, &IQR_HASH_DEFAULT_SHA2_512);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This lets us give satisfactory randomness to the algorithm. */
    ret =  iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA2_384, rng);
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

static void preamble(const char *cmd, const iqr_RainbowVariant *variant, const char *pub, const char *priv)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_RAINBOW_GF256_68_36_36) {
        fprintf(stdout, "    security level: IIIc. parameter set: (GF(256), 68, 36, 36)\n");
    } else if (variant == &IQR_RAINBOW_GF256_92_48_48) {
        fprintf(stdout, "    security level: Vc. parameter set: (GF(256), 92, 48, 48)\n");
    }
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, const iqr_RainbowVariant **variant, const char **pub,
    const char **priv)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--security") == 0) {
            /* [--security IIIb|IIIc|IVa|Vc|VIa|VIb] */
            i++;
            if  (paramcmp(argv[i], "IIIc") == 0) {
                *variant = &IQR_RAINBOW_GF256_68_36_36;
            } else if  (paramcmp(argv[i], "Vc") == 0) {
                *variant = &IQR_RAINBOW_GF256_92_48_48;
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
    const iqr_RainbowVariant *variant = &IQR_RAINBOW_GF256_68_36_36;
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

    /* IQR initialization that is not specific to Rainbow. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of Rainbow key generation.
     */
    ret = showcase_rainbow_keygen(ctx, rng, variant, pub, priv);

cleanup:
    /* Clean up. */
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
