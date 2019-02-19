/** @file main.c
 *
 * @brief Sign a message using the toolkit's Rainbow signature scheme.
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
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"rainbow_sign [--security IIIb|IIIc|IVa|Vc|VIa|VIb] [--sig filename]\n"
"  [--priv <filename>] [--message <filename>]\n"
"    Defaults are: \n"
"        --security IIIb\n"
"        --sig sig.dat\n"
"        --priv priv.key\n"
"        --message message.dat\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases signing of a digest using the Rainbow signature
// scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_rainbow_sign(const iqr_Context *ctx, const iqr_RainbowVariant *variant, const iqr_RNG *rng,
    const char *priv_file, const char *message_file, const char *sig_file)
{
    iqr_RainbowParams *params = NULL;
    iqr_RainbowPrivateKey *priv = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    size_t message_size = 0;
    uint8_t *message = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    iqr_retval ret = iqr_RainbowCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the raw private key. */
    ret = load_data(priv_file, &priv_raw, &priv_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_RainbowImportPrivateKey(params, priv_raw, priv_raw_size, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key has been imported.\n");

    /* Load the message. */
    ret = load_data(message_file, &message, &message_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Create the signature. */
    ret = iqr_RainbowGetSignatureSize(params, &sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowGetSignatureSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    sig = calloc(1, sig_size);
    if (sig == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_RainbowSign(priv, rng, message, message_size, sig, sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowSign(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Signature has been created.\n");

    /* And finally, write the signature to disk. */
    ret = save_data(sig_file, sig, sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Signature has been saved to disk.\n");

end:
    if (priv_raw != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memzero(priv_raw, priv_raw_size);
    }

    iqr_RainbowDestroyPrivateKey(&priv);
    iqr_RainbowDestroyParams(&params);

    free(priv_raw);
    free(message);
    free(sig);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// the Rainbow signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_RNG **rng)
{
    /* Create a Global Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used by the scheme. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_384, &IQR_HASH_DEFAULT_SHA2_384);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_512, &IQR_HASH_DEFAULT_SHA2_512);
    if (IQR_OK != ret) {
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

static void preamble(const char *cmd, const iqr_RainbowVariant *variant, const char *sig, const char *priv, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_RAINBOW_GF31_64_32_48) {
        fprintf(stdout, "    security level: IIIb. parameter set: (GF(31), 64, 32, 48)\n");
    } else if (variant == &IQR_RAINBOW_GF256_68_36_36) {
        fprintf(stdout, "    security level: IIIc. parameter set: (GF(256), 68, 36, 36)\n");
    } else if (variant == &IQR_RAINBOW_GF16_56_48_48) {
        fprintf(stdout, "    security level: IVa. parameter set: (GF(16), 56, 48, 48)\n");
    } else if (variant == &IQR_RAINBOW_GF256_92_48_48) {
        fprintf(stdout, "    security level: Vc. parameter set: (GF(256), 92, 48, 48)\n");
    } else if (variant == &IQR_RAINBOW_GF16_76_64_64) {
        fprintf(stdout, "    security level: VIa. parameter set: (GF(16), 76, 64, 64)\n");
    } else if (variant == &IQR_RAINBOW_GF31_84_56_56) {
        fprintf(stdout, "    security level: VIb. parameter set: (GF(31), 84, 56, 56)\n");
    }
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    message data file: %s\n", message);
    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, const iqr_RainbowVariant **variant, const char **sig,
    const char **priv, const char **message)
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
            if  (paramcmp(argv[i], "IIIb") == 0) {
                *variant = &IQR_RAINBOW_GF31_64_32_48;
            } else if  (paramcmp(argv[i], "IIIc") == 0) {
                *variant = &IQR_RAINBOW_GF256_68_36_36;
            } else if  (paramcmp(argv[i], "IVa") == 0) {
                *variant = &IQR_RAINBOW_GF16_56_48_48;
            } else if  (paramcmp(argv[i], "Vc") == 0) {
                *variant = &IQR_RAINBOW_GF256_92_48_48;
            } else if  (paramcmp(argv[i], "VIa") == 0) {
                *variant = &IQR_RAINBOW_GF16_76_64_64;
            } else if  (paramcmp(argv[i], "VIb") == 0) {
                *variant = &IQR_RAINBOW_GF31_84_56_56;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--sig") == 0) {
            /* [--sig <filename>] */
            i++;
            *sig = argv[i];
        } else if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *priv = argv[i];
        } else if (paramcmp(argv[i], "--message") == 0) {
           /* [--message <filename>] */
           i++;
           *message = argv[i];
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
     *  here.
     */
    const iqr_RainbowVariant *variant = &IQR_RAINBOW_GF31_64_32_48;
    const char *sig = "sig.dat";
    const char *priv = "priv.key";
    const char *message = "message.dat";

    iqr_Context *ctx = NULL;
    iqr_RNG *rng = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &sig, &priv, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], variant, sig, priv, message);

    /* IQR initialization that is not specific to Rainbow. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of Rainbow signing.
     */
    ret = showcase_rainbow_sign(ctx, variant, rng, priv, message, sig);

cleanup:
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
