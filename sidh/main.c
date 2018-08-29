/** @file main.c
 *
 * @brief Demonstrate the toolkit's SIDH implementation.
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
#include <stdbool.h>
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
#include "iqr_sidh.h"

#include "internal.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static void secure_memzero(void *b, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the use of SIDH to generate a shared secret.
//
// This function assumes that all the parameters have already been validated.
// However, the function will exit early if there is a file system related
// failure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_sidh(const iqr_Context *ctx, const iqr_RNG *rng, const iqr_SIDHVariant *variant, bool dump)
{
    iqr_retval ret = init_comms();
    if (ret != IQR_OK) {
        return ret;
    }

    size_t secret_size = 0;
    ret = init_alice(ctx, variant, &secret_size);
    if (ret != IQR_OK) {
        cleanup_comms();
        return ret;
    }
    ret = init_bob(ctx, variant);
    if (ret != IQR_OK) {
        cleanup_alice();
        cleanup_comms();
        return ret;
    }

    uint8_t *alice_secret = calloc(1, secret_size);
    uint8_t *bob_secret = calloc(1, secret_size);
    if (alice_secret == NULL || bob_secret == NULL) {
        fprintf(stdout, "\nThis is awkward, we ran out of memory.\n\n");
        goto end;
    }

    ret = alice_start(rng, dump);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = bob_start(rng, dump);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = alice_get_secret(alice_secret, secret_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = bob_get_secret(bob_secret, secret_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Test to make sure the secrets are the same */
    if (memcmp(alice_secret, bob_secret, secret_size) == 0) {
        fprintf(stdout, "\nAlice and Bob's secrets match.\n\n");
    } else {
        fprintf(stdout, "\nAlice and Bob's secrets do NOT match.\n\n");
    }

    if (dump) {
        ret = save_data(ALICE_SECRET_FNAME, alice_secret, secret_size);
        if (ret != IQR_OK) {
            goto end;
        }
        ret = save_data(BOB_SECRET_FNAME, bob_secret, secret_size);
    }

end:
    /* These secrets are private, sensitive data, be sure to clear memory
     * containing them when you're done.
     */
    secure_memzero(alice_secret, secret_size);
    secure_memzero(bob_secret, secret_size);
    free(alice_secret);
    free(bob_secret);

    cleanup_alice();
    cleanup_bob();
    cleanup_comms();

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// SIDH.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_RNG **rng)
{
    /* Create a Global Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ContextCreate(): %s\n", iqr_StrError(ret));
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
//---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Generic POSIX file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size)
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
    fprintf(stdout, "sidh [variant p503|p751] [--dump]\n");
    fprintf(stdout, "        --variant p751\n");
    fprintf(stdout, "        --dump Dumps the generated keys and secrets to file.\n");
    fprintf(stdout, "               Filenames:\n");
    fprintf(stdout, "                 Alice's key:    alice_key.dat\n");
    fprintf(stdout, "                 Bob's key:      bob_key.dat\n");
    fprintf(stdout, "                 Alice's secret: alice_secret.dat\n");
    fprintf(stdout, "                 Bob's secret:   bob_secret.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const iqr_SIDHVariant *variant, bool dump)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_SIDH_P751) {
        fprintf(stdout, "    variant: p751\n");
    } else {
        fprintf(stdout, "    variant: p503\n");
    }
    fprintf(stdout, "    Dump data to files: ");
    if (dump) {
        fprintf(stdout, "True\n");
    } else {
        fprintf(stdout, "False\n");
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

static iqr_retval parse_commandline(int argc, const char **argv, const iqr_SIDHVariant **variant, bool *dump)
{
    int i = 1;

    while (i != argc) {
        if (paramcmp(argv[i], "--dump") == 0) {
            *dump = true;
        } else if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant p503|p751] */
            i++;
            if (paramcmp(argv[i], "p503") == 0) {
                *variant = &IQR_SIDH_P503;
            } else if  (paramcmp(argv[i], "p751") == 0) {
                *variant = &IQR_SIDH_P751;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else {
            usage();
            return IQR_EBADVALUE;
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
    iqr_Context *ctx = NULL;
    iqr_RNG *rng = NULL;
    bool dump = false;
    const iqr_SIDHVariant *variant = &IQR_SIDH_P751;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &dump);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], variant, dump);

    /* IQR initialization that is not specific to SIDH. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of SIDH. */
    ret = showcase_sidh(ctx, rng, variant, dump);

cleanup:
    /* Clean up. */
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
