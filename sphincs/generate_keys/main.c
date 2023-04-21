/** @file main.c
 *
 * @brief Generate keys using the toolkit's SPHINCS+ Signature scheme.
 *
 * @copyright Copyright (C) 2019-2023, ISARA Corporation, All Rights Reserved.
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
"sphincs_generate_keys [--variant sha128f|sha128s|sha192f|sha192s|sha256f\n"
"    |sha256s|shake128f|shake128s|shake192f|shake192s|shake256f|shake256s]\n"
"  [--pub <filename>] [--priv <filename>]\n"
"\n"
"    Defaults:\n"
"        --variant shake192f\n"
"        --pub pub.key\n"
"        --priv priv.key\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the generation of SPHINCS+ public and private keys
// for signing.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_sphincs_keygen(const iqr_Context *ctx, const iqr_RNG *rng, const iqr_SPHINCSVariant *variant,
    const char *pub_file, const char *priv_file)
{
    iqr_SPHINCSParams *params = NULL;
    iqr_SPHINCSPrivateKey *priv = NULL;
    iqr_SPHINCSPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    iqr_retval ret = iqr_SPHINCSCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Generate the keys. */
    ret = iqr_SPHINCSCreateKeyPair(params, rng, &pub, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSCreateKeyPair(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Keys have been generated.\n");

    ret = iqr_SPHINCSGetPublicKeySize(params, &pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSGetPublicKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    pub_raw = calloc(1, pub_raw_size);
    if (pub_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_SPHINCSExportPublicKey(pub, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSExportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public Key has been exported.\n");

    ret = iqr_SPHINCSGetPrivateKeySize(params, &priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSGetPrivateKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    priv_raw = calloc(1, priv_raw_size);
    if (priv_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_SPHINCSExportPrivateKey(priv, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SPHINCSExportPrivateKey(): %s\n", iqr_StrError(ret));
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

    iqr_SPHINCSDestroyPrivateKey(&priv);
    iqr_SPHINCSDestroyPublicKey(&pub);
    iqr_SPHINCSDestroyParams(&params);

    free(pub_raw);
    free(priv_raw);

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

static void preamble(const char *cmd, const iqr_SPHINCSVariant *variant, const char *pub, const char *priv)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_SPHINCS_SHA2_256_128F) {
        fprintf(stdout, "    Variant: SHA-256-128 (fast)\n");
    } else if (variant == &IQR_SPHINCS_SHA2_256_128S) {
        fprintf(stdout, "    Variant: SHA-256-128 (small)\n");
    } else if (variant == &IQR_SPHINCS_SHAKE_256_128F) {
        fprintf(stdout, "    Variant: SHAKE-256-128 (fast)\n");
    } else if (variant == &IQR_SPHINCS_SHAKE_256_128S) {
        fprintf(stdout, "    Variant: SHAKE-256-128 (small)\n");
    } else if (variant == &IQR_SPHINCS_SHA2_256_192F) {
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

    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "\n");
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_SPHINCSVariant **variant, const char **pub,
    const char **priv)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant sha128f|sha128s|sha192f|sha192s|sha256f|
             *            sha256s|shake128f|shake128s|shake192f|
             *            shake192s|shake256f|shake256s]
             */
            i++;
            if (paramcmp(argv[i], "sha128f") == 0) {
                *variant = &IQR_SPHINCS_SHA2_256_128F;
            } else if (paramcmp(argv[i], "sha128s") == 0) {
                *variant = &IQR_SPHINCS_SHA2_256_128S;
            } else if (paramcmp(argv[i], "shake128f") == 0) {
                *variant = &IQR_SPHINCS_SHAKE_256_128F;
            } else if (paramcmp(argv[i], "shake128s") == 0) {
                *variant = &IQR_SPHINCS_SHAKE_256_128S;
            } else if (paramcmp(argv[i], "sha192f") == 0) {
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
    const iqr_SPHINCSVariant *variant = &IQR_SPHINCS_SHAKE_256_192F;
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

    /* IQR initialization that is not specific to SPHINCS. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the generation of SPHINCS public/private keys. */
    ret = showcase_sphincs_keygen(ctx, rng, variant, pub, priv);

cleanup:
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
