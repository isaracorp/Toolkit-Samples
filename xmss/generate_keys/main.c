/** @file main.c
 *
 * @brief Generate keys using the toolkit's XMSS signature scheme.
 *
 * @copyright Copyright 2017-2018 ISARA Corporation
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
// Declare memset_s() if the platform supports it.
#if !defined(__ANDROID__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
// For SecureZeroMemory().
#include <Windows.h>
#endif

#if defined(__FreeBSD__)
// For explicit_bzero().
#include <strings.h>
#endif

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "iqr_watchdog.h"
#include "iqr_xmss.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static void secure_memzero(void *b, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the generation of XMSS public and private keys for
// signing.
//
// This function assumes that all the parameter have already been validated.
// However, the function will exit early if there is a file system related
// failure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_xmss_keygen(const iqr_Context *ctx, const iqr_RNG *rng, const char *pub_file, const char *priv_file,
    const char *state_file, const iqr_XMSSTreeStrategy *strategy, const iqr_XMSSHeight height)
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

    iqr_retval ret = iqr_XMSSCreateParams(ctx, strategy, height, &params);
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
    ret = iqr_XMSSGetPublicKeySize(pub, &pub_raw_size);
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
    ret = iqr_XMSSGetPrivateKeySize(priv, &priv_raw_size);
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
    ret = iqr_XMSSGetStateSize(state, &state_raw_size);
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
// running task for large XMSS tree heights.
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
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This will allow us to give satisfactory randomness to the algorithm. */
    ret =  iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA2_256, rng);
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
// Generic POSIX file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size)
{
    FILE *fp = fopen(fname, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    iqr_retval ret = IQR_OK;
    fwrite(data, data_size, 1, fp);
    if (ferror(fp) != 0) {
        fprintf(stderr, "Failed on fwrite(): %s\n", strerror(errno));
        ret = IQR_EBADVALUE;
        goto end;
    }

    fprintf(stdout, "Successfully saved %s (%zu bytes)\n", fname, data_size);

end:
    fclose(fp);
    fp = NULL;
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Tell the user about the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static void usage(void)
{
    fprintf(stdout, "xmss_generate_keys [--pub <filename>] [--priv <filename>] [--state <filename>]\n"
                    "  [--height 10|16|20] [--strategy bds|full]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --pub pub.key\n");
    fprintf(stdout, "        --priv priv.key\n");
    fprintf(stdout, "        --state priv.state\n");
    fprintf(stdout, "        --height 10\n");
    fprintf(stdout, "        --strategy full\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *pub, const char *priv, const char *state, const iqr_XMSSHeight height,
    const iqr_XMSSTreeStrategy *strategy)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    private key state file: %s\n", state);

    if (IQR_XMSS_HEIGHT_10 == height) {
        fprintf(stdout, "    height: IQR_XMSS_HEIGHT_10\n");
    } else if (IQR_XMSS_HEIGHT_16 == height) {
        fprintf(stdout, "    height: IQR_XMSS_HEIGHT_16\n");
    } else if (IQR_XMSS_HEIGHT_20 == height) {
        fprintf(stdout, "    height: IQR_XMSS_HEIGHT_20\n");
    } else {
        fprintf(stdout, "    height: INVALID\n");
    }

    if (strategy == &IQR_XMSS_FULL_STRATEGY) {
        fprintf(stdout, "    strategy: Full Tree\n");
    } else if (strategy == &IQR_XMSS_BDS_STRATEGY) {
        fprintf(stdout, "    strategy: BDS\n");
    } else {
        fprintf(stdout, "    strategy: INVALID\n");
    }

    fprintf(stdout, "\n");
}

/* Tests if two parameters match.
 * Returns 0 if the two parameter match.
 * Non-zero otherwise.
 *
 * Parameters are expected to be less than 32 characters in length
 */
static int paramcmp(const char *p1 , const char *p2) {
    const size_t max_param_size = 32;  // Arbitrary, but reasonable.
    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }

    return strncmp(p1, p2, max_param_size);
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **pub, const char **priv, const char **state,
    iqr_XMSSHeight *height, const iqr_XMSSTreeStrategy **strategy)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
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
        } else if (paramcmp(argv[i], "--height") == 0) {
            /* [--height 10|16|20] */
            i++;
            if (paramcmp(argv[i], "10") == 0) {
                *height = IQR_XMSS_HEIGHT_10;
            } else if  (paramcmp(argv[i], "16") == 0) {
                *height = IQR_XMSS_HEIGHT_16;
            } else if  (paramcmp(argv[i], "20") == 0) {
                *height = IQR_XMSS_HEIGHT_20;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--strategy") == 0) {
            /* [--strategy bds|full] */
            i++;
            if (paramcmp(argv[i], "bds") == 0) {
                *strategy = &IQR_XMSS_BDS_STRATEGY;
            } else if (paramcmp(argv[i], "full") == 0) {
                *strategy = &IQR_XMSS_FULL_STRATEGY;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        }
        i++;
    }

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Secure memory wipe.
// ---------------------------------------------------------------------------------------------------------------------------------

static void secure_memzero(void *b, size_t len)
{
    /* You may need to substitute your platform's version of a secure memset()
     * (one that won't be optimized out by the compiler). There isn't a secure,
     * portable memset() available before C11 which provides memset_s(). Windows
     * provides SecureZeroMemory() for this purpose, and FreeBSD provides
     * explicit_bzero().
     */
#if defined(__STDC_LIB_EXT1__) || (defined(__APPLE__) && defined(__MACH__))
    memset_s(b, len, 0, len);
#elif defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(b, len);
#elif defined(__FreeBSD__)
    explicit_bzero(b, len);
#else
    /* This fallback will not be optimized out, if the compiler has a conforming
     * implementation of "volatile". It also won't take advantage of any faster
     * intrinsics, so it may end up being slow.
     *
     * Implementation courtesy of this paper:
     * http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1381.pdf
     */
    volatile unsigned char *ptr = b;
    while (len--) {
        *ptr++ = 0x00;
    }
#endif
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    const char *pub = "pub.key";
    const char *priv = "priv.key";
    const char *state = "priv.state";
    const iqr_XMSSTreeStrategy *strategy = &IQR_XMSS_FULL_STRATEGY;
    iqr_XMSSHeight height =  IQR_XMSS_HEIGHT_10;

    iqr_Context *ctx = NULL;
    iqr_RNG *rng = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &pub, &priv, &state, &height, &strategy);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], pub, priv, state, height, strategy);

    /* IQR initialization that is not specific to XMSS. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of XMSS key generation.
     */
    ret = showcase_xmss_keygen(ctx, rng, pub, priv, state, strategy, height);

cleanup:
    /* Clean up. */
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
