/** @file main.c Demonstrate the toolkit's ECDH implementation.
 *
 * @copyright Copyright 2017 ISARA Corporation
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

#include "internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iqr_context.h"
#include "iqr_ecdh.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static void *secure_memset(void *b, int c, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the use of the ECDH algorithm to generate a
// shared secret.
//
// This function assumes that all the parameters have already been validated.
// However, the function will exit early if there is a file system related
// failure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_ecdh(const iqr_Context *ctx, const iqr_RNG *rng, bool dump, const iqr_ECDHCurve *curve)
{
    iqr_retval ret = init_comms();
    if (ret != IQR_OK) {
        return ret;
    }

    ret = init_alice(ctx, curve);
    if (ret != IQR_OK) {
        cleanup_comms();
        return ret;
    }
    ret = init_bob(ctx, curve);
    if (ret != IQR_OK) {
        cleanup_alice();
        cleanup_comms();
        return ret;
    }

    /* Either Bob or Alice could go first in this protocol, since both can
     * derive their own public key without any information from the other. For
     * more information on how the ECDH data protocol works see the README.md.
     */
    uint8_t *alice_secret = NULL;
    size_t alice_secret_size = 0;
    uint8_t *bob_secret = NULL;
    size_t bob_secret_size = 0;

    ret = alice_start(rng, dump);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = bob_start(rng, dump);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = alice_get_secret(&alice_secret, &alice_secret_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = bob_get_secret(&bob_secret, &bob_secret_size);
    if (ret != IQR_OK) {
        goto end;
    }

    if (alice_secret_size != bob_secret_size) {
        ret = IQR_EBADRESULT;
        goto end;
    }

    /* Test to make sure the secrets are the same */
    if (memcmp(alice_secret, bob_secret, alice_secret_size) == 0) {
        fprintf(stdout, "\nAlice and Bob's secrets match.\n\n");
    } else {
        fprintf(stdout, "\nAlice and Bob's secrets do NOT match.\n\n");
    }

    if (dump) {
        ret = save_data(ALICE_SECRET_FNAME, alice_secret, alice_secret_size);
        if (ret != IQR_OK) {
            goto end;
        }
        ret = save_data(BOB_SECRET_FNAME, bob_secret, bob_secret_size);
    }

end:
    /* These secrets are private, sensitive data, be sure to clear memory containing them when you're done */
    if (alice_secret != NULL) {
        secure_memset(alice_secret, 0, alice_secret_size);
    }

    if (bob_secret != NULL) {
        secure_memset(bob_secret, 0, bob_secret_size);
    }

    cleanup_alice();
    cleanup_bob();
    cleanup_comms();

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// ECDH.
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
    fprintf(stdout, "ecdh [--dump] [--curve nistp256|nistp384|nistp521|x25519]\n");
    fprintf(stdout, "        --dump Dumps the generated keys and secrets to file.\n");
    fprintf(stdout, "               Filenames:\n");
    fprintf(stdout, "                 Alice's key:    alice_key.dat\n");
    fprintf(stdout, "                 Bob's key:      bob_key.dat\n");
    fprintf(stdout, "                 Alice's secret: alice_secret.dat\n");
    fprintf(stdout, "                 Bob's secret:   bob_secret.dat\n");
    fprintf(stdout, "        --curve The ECDH curve to use.\n");
    fprintf(stdout, "               Valid values are:\n");
    fprintf(stdout, "                 * nistp256\n");
    fprintf(stdout, "                 * nistp384\n");
    fprintf(stdout, "                 * nistp521\n");
    fprintf(stdout, "                 * x25519\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, bool dump, const iqr_ECDHCurve *curve)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    Dump data to files: ");
    if (dump) {
        fprintf(stdout, "True\n");
    } else {
        fprintf(stdout, "False\n");
    }

    fprintf(stdout, "    Curve: ");
    if (curve == &IQR_ECDH_NISTP256) {
        fprintf(stdout, "nistp256\n");
    } else if (curve == &IQR_ECDH_NISTP384) {
        fprintf(stdout, "nistp384\n");
    } else if (curve == &IQR_ECDH_NISTP521) {
        fprintf(stdout, "nistp521\n");
    } else if (curve == &IQR_ECDH_X25519) {
        fprintf(stdout, "x25519\n");
    } else {
        fprintf(stdout, "Invalid\n");
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

static iqr_retval parse_commandline(int argc, const char **argv, bool *dump, const iqr_ECDHCurve **curve)
{
    int i = 1;

    while (i != argc) {
        if (paramcmp(argv[i], "--dump") == 0) {
            *dump = true;
        } else if (paramcmp(argv[i], "--curve") == 0) {
            i++;
            if (paramcmp(argv[i], "nistp256") == 0) {
                *curve = &IQR_ECDH_NISTP256;
            } else if (paramcmp(argv[i], "nistp384") == 0) {
                *curve = &IQR_ECDH_NISTP384;
            } else if (paramcmp(argv[i], "nistp521") == 0) {
                *curve = &IQR_ECDH_NISTP521;
            } else if (paramcmp(argv[i], "x25519") == 0) {
                *curve = &IQR_ECDH_X25519;
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
// Secure (not really) memset().
// ---------------------------------------------------------------------------------------------------------------------------------

static void *secure_memset(void *b, int c, size_t len)
{
    /** This memset() is NOT secure. It could and probably will be optimized out by the compiler. There isn't a secure,
     * portable memset() available before C11 which provides memset_s(). Windows also provides SecureZeroMemory().
     *
     * This is just for sample purposes, do your own due diligence when choosing a secure memset() so you can securely
     * clear sensitive data.
     */
    return memset(b, c, len);
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
    const iqr_ECDHCurve *curve = &IQR_ECDH_NISTP256;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &dump, &curve);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], dump, curve);

    /* IQR initialization that is not specific to ECDH. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of ECDH. */
    ret = showcase_ecdh(ctx, rng, dump, curve);

cleanup:
    /* Clean up. */
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
