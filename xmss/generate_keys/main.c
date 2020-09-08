/** @file main.c
 *
 * @brief Generate keys using the toolkit's XMSS signature scheme.
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
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "iqr_watchdog.h"
#include "iqr_xmss.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"xmss_generate_keys [--pub <filename>] [--priv <filename>] [--state <filename>]\n"
"  [--variant 10|16|20] [--strategy cpu|memory|full]\n"
"\n"
"    Defaults:\n"
"        --pub pub.key\n"
"        --priv priv.key\n"
"        --state priv.state\n"
"        --variant 10\n"
"        --strategy full\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the generation of XMSS public and private keys for
// signing.
//
// This function assumes that all the parameter have already been validated.
// However, the function will exit early if there is a file system related
// failure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_xmss_keygen(const iqr_Context *ctx, const iqr_RNG *rng, const char *pub_file, const char *priv_file,
    const char *state_file, const iqr_XMSSTreeStrategy *strategy, const iqr_XMSSVariant *variant)
{
    iqr_XMSSParams *params = NULL;
    iqr_XMSSPrivateKey *priv = NULL;
    iqr_XMSSPrivateKeyState *state = NULL;
    iqr_XMSSPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    size_t state_raw_size = 0;
    uint8_t *state_raw = NULL;

    iqr_retval ret = iqr_XMSSCreateParams(ctx, strategy, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Generate the keys. */
    ret = iqr_XMSSCreateKeyPair(params, rng, &pub, &priv, &state);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSCreateKeyPair(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "\n");
    fprintf(stdout, "Keys have been generated.\n");

    /* Get the size of the public key and export the buffer. */
    ret = iqr_XMSSGetPublicKeySize(params, &pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSGetPublicKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    pub_raw = calloc(1, pub_raw_size);
    if (pub_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_XMSSExportPublicKey(pub, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSExportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public Key has been exported.\n");

    /* Get the size of the private key and export the buffer. */
    ret = iqr_XMSSGetPrivateKeySize(params, &priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSGetPrivateKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    priv_raw = calloc(1, priv_raw_size);
    if (priv_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_XMSSExportPrivateKey(priv, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSExportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private Key has been exported.\n");

    /* Get the size of the state and export the buffer. */
    ret = iqr_XMSSGetStateSize(params, &state_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSGetStateSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    state_raw = calloc(1, state_raw_size);
    if (state_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_XMSSExportState(state, state_raw, state_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSExportState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private Key State has been exported.\n");

    /* And finally, write the public and private key to disk. */
    ret = save_data(pub_file, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = save_data(priv_file, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = save_data(state_file, state_raw, state_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Public, private keys, and state have been saved to disk.\n");

end:
    if (priv_raw != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memzero(priv_raw, priv_raw_size);
    }
    free(pub_raw);
    free(priv_raw);
    free(state_raw);

    iqr_XMSSDestroyPrivateKey(&priv);
    iqr_XMSSDestroyPublicKey(&pub);
    iqr_XMSSDestroyState(&state);
    iqr_XMSSDestroyParams(&params);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// XMSS.
// ---------------------------------------------------------------------------------------------------------------------------------

// Provides a cheap progress indicator for key generation, which is a long-
// running task for large XMSS tree variants.
static iqr_retval progress_watchdog(void *watchdog_data)
{
    (void)watchdog_data;  // Not used.

    fprintf(stdout, ".");
    fflush(stdout);

    return IQR_OK;
}

// Initialize the toolkit and the algorithms required by XMSS.
static iqr_retval init_toolkit(iqr_Context **ctx, iqr_RNG **rng)
{
    /* Create a Context. */
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

    /* This sets the hashing functions that will be used with this Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This lets us give satisfactory randomness to the algorithm. */
    ret = iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA2_256, rng);
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

static void preamble(const char *cmd, const char *pub, const char *priv, const char *state, const iqr_XMSSVariant *variant,
    const iqr_XMSSTreeStrategy *strategy)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    private key state file: %s\n", state);

    if (&IQR_XMSS_2E10 == variant) {
        fprintf(stdout, "    variant: IQR_XMSS_2E10\n");
    } else if (&IQR_XMSS_2E16 == variant) {
        fprintf(stdout, "    variant: IQR_XMSS_2E16\n");
    } else if (&IQR_XMSS_2E20 == variant) {
        fprintf(stdout, "    variant: IQR_XMSS_2E20\n");
    } else {
        fprintf(stdout, "    variant: INVALID\n");
    }

    if (strategy == &IQR_XMSS_FULL_TREE_STRATEGY) {
        fprintf(stdout, "    strategy: Full Tree\n");
    } else if (strategy == &IQR_XMSS_MEMORY_CONSTRAINED_STRATEGY) {
        fprintf(stdout, "    strategy: Memory Constrained\n");
    } else if (strategy == &IQR_XMSS_CPU_CONSTRAINED_STRATEGY) {
        fprintf(stdout, "    strategy: CPU Constrained\n");
    } else {
        fprintf(stdout, "    strategy: INVALID\n");
    }

    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **pub, const char **priv, const char **state,
    const iqr_XMSSVariant **variant, const iqr_XMSSTreeStrategy **strategy)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--pub") == 0) {
            /* [--pub <filename>] */
            i++;
            *pub = argv[i];
        } else if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *priv = argv[i];
        } else if (paramcmp(argv[i], "--state") == 0) {
            /* [--state <filename>] */
            i++;
            *state = argv[i];
        } else if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant 10|16|20] */
            i++;
            if (paramcmp(argv[i], "10") == 0) {
                *variant = &IQR_XMSS_2E10;
            } else if (paramcmp(argv[i], "16") == 0) {
                *variant = &IQR_XMSS_2E16;
            } else if (paramcmp(argv[i], "20") == 0) {
                *variant = &IQR_XMSS_2E20;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--strategy") == 0) {
            /* [--strategy cpu|memory|full] */
            i++;
            if (paramcmp(argv[i], "cpu") == 0) {
                *strategy = &IQR_XMSS_CPU_CONSTRAINED_STRATEGY;
            } else if (paramcmp(argv[i], "memory") == 0) {
                *strategy = &IQR_XMSS_MEMORY_CONSTRAINED_STRATEGY;
            } else if (paramcmp(argv[i], "full") == 0) {
                *strategy = &IQR_XMSS_FULL_TREE_STRATEGY;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
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
    const char *pub = "pub.key";
    const char *priv = "priv.key";
    const char *state = "priv.state";
    const iqr_XMSSTreeStrategy *strategy = &IQR_XMSS_FULL_TREE_STRATEGY;
    const iqr_XMSSVariant *variant = &IQR_XMSS_2E10;

    iqr_Context *ctx = NULL;
    iqr_RNG *rng = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &pub, &priv, &state, &variant, &strategy);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], pub, priv, state, variant, strategy);

    /* IQR initialization that is not specific to XMSS. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of XMSS key generation. */
    ret = showcase_xmss_keygen(ctx, rng, pub, priv, state, strategy, variant);

cleanup:
    /* Clean up. */
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
