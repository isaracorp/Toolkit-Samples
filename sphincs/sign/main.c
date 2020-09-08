/** @file main.c
 *
 * @brief Sign a message using the toolkit's SPHINCS+ signature scheme.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iqr_context.h"
#include "iqr_sphincs.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"sphincs_sign [--variant sha192f|sha192s|shake192f|shake192s|sha256f|sha256s\n"
"    |shake256f|shake256s]\n"
"  [--sig filename] [--priv <filename>] [--message <filename>]\n"
"\n"
"    Defaults:\n"
"        --variant shake192f\n"
"        --sig sig.dat\n"
"        --priv priv.key\n"
"        --message message.dat\n"
"\n"
"    The --variant must match the --variant specified when generating keys.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases signing of a digest using the SPHINCS+ signature
// scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_sphincs_sign(const iqr_Context *ctx, const iqr_RNG *rng, const iqr_SPHINCSVariant *variant,
    const char *priv_file, const char *message_file, const char *sig_file)
{
    iqr_SPHINCSParams *params = NULL;
    iqr_SPHINCSPrivateKey *priv = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    size_t message_size = 0;
    uint8_t *message = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    iqr_retval ret = iqr_SPHINCSCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the raw private key. */
    ret = load_data(priv_file, &priv_raw, &priv_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_SPHINCSImportPrivateKey(params, priv_raw, priv_raw_size, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key has been imported.\n");

    /* Load the message. */
    ret = load_data(message_file, &message, &message_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Create the signature. */
    ret = iqr_SPHINCSGetSignatureSize(params, &sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSGetSignatureSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    sig = calloc(1, sig_size);
    if (sig == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_SPHINCSSign(priv, rng, message, message_size, sig, sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSSign(): %s\n", iqr_StrError(ret));
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

    iqr_SPHINCSDestroyPrivateKey(&priv);
    iqr_SPHINCSDestroyParams(&params);

    free(priv_raw);
    free(message);
    free(sig);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// the SPHINCS+ signature scheme.
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

    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
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

static void preamble(const char *cmd, const iqr_SPHINCSVariant *variant, const char *sig, const char *priv, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_SPHINCS_SHA2_256_192F) {
        fprintf(stdout, "    Variant: SHA-256-192 (fast)\n");
    } else if (variant == &IQR_SPHINCS_SHA2_256_192S) {
        fprintf(stdout, "    Variant: SHA-256-192 (small)\n");
    } else if (variant == &IQR_SPHINCS_SHAKE_256_192F) {
        fprintf(stdout, "    Variant: SHAKE-256-192 (fast)\n");
    } else if (variant == &IQR_SPHINCS_SHAKE_256_192S) {
        fprintf(stdout, "    Variant: SHAKE-256-192 (small)\n");
    } else if (variant == &IQR_SPHINCS_SHA2_256_256F) {
        fprintf(stdout, "    Variant: SHA-256-256 (fast)\n");
    } else if (variant == &IQR_SPHINCS_SHA2_256_256S) {
        fprintf(stdout, "    Variant: SHA-256-256 (small)\n");
    } else if (variant == &IQR_SPHINCS_SHAKE_256_256F) {
        fprintf(stdout, "    Variant: SHAKE-256-256 (fast)\n");
    } else if (variant == &IQR_SPHINCS_SHAKE_256_256S) {
        fprintf(stdout, "    Variant: SHAKE-256-256 (small)\n");
    }

    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    message data file: %s\n", message);
    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, const iqr_SPHINCSVariant **variant, const char **sig,
    const char **priv, const char **message)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant sha192f|sha192s|shake192f|shake192s|sha256f|sha256s
             *  |shake256f|shake256s]
             */
            i++;
            if (paramcmp(argv[i], "sha192f") == 0) {
                *variant = &IQR_SPHINCS_SHA2_256_192F;
            } else if (paramcmp(argv[i], "sha192s") == 0) {
                *variant = &IQR_SPHINCS_SHA2_256_192S;
            } else if (paramcmp(argv[i], "shake192f") == 0) {
                *variant = &IQR_SPHINCS_SHAKE_256_192F;
            } else if (paramcmp(argv[i], "shake192s") == 0) {
                *variant = &IQR_SPHINCS_SHAKE_256_192S;
            } else if (paramcmp(argv[i], "sha256f") == 0) {
                *variant = &IQR_SPHINCS_SHA2_256_256F;
            } else if (paramcmp(argv[i], "sha256s") == 0) {
                *variant = &IQR_SPHINCS_SHA2_256_256S;
            } else if (paramcmp(argv[i], "shake256f") == 0) {
                *variant = &IQR_SPHINCS_SHAKE_256_256F;
            } else if (paramcmp(argv[i], "shake256s") == 0) {
                *variant = &IQR_SPHINCS_SHAKE_256_256S;
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
    const iqr_SPHINCSVariant *variant = &IQR_SPHINCS_SHAKE_256_192F;
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

    /* IQR initialization that is not specific to SPHINCS+. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the generation of a SPHINCS+ signature. */
    ret = showcase_sphincs_sign(ctx, rng, variant, priv, message, sig);

cleanup:
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
