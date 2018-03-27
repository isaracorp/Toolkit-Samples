/** @file main.c
 *
 * @brief Demonstrate the toolkit's McEliece QC-MDPC key encapsulation
 * mechanism.
 *
 * @copyright Copyright 2016-2018 ISARA Corporation
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
#include "iqr_mceliece.h"
#include "iqr_retval.h"
#include "iqr_rng.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static void secure_memzero(void *b, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the generation of McEliece QC-MDPC public and
// private keys.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_mceliece_key_gen(const iqr_McElieceParams *params, const iqr_RNG *rng,
    const char *pub_file, const char *priv_file)
{
    iqr_McEliecePublicKey *pub = NULL;
    iqr_McEliecePrivateKey *priv = NULL;

    const size_t pub_raw_size = IQR_MCELIECE_PUBLIC_KEY_SIZE;
    uint8_t *pub_raw = NULL;

    const size_t priv_raw_size = IQR_MCELIECE_PRIVATE_KEY_SIZE;
    uint8_t *priv_raw = NULL;

    fprintf(stdout, "Creating McEliece QC-MDPC key-pair. This could take a while with strong keys.\n");

    iqr_retval ret = iqr_McElieceCreateKeyPair(params, rng, &pub, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_McElieceCreateKeyPair(): %s\n", iqr_StrError(ret));
        goto end;
    }
    fprintf(stdout, "McEliece QC-MDPC public and private key-pair has been created\n");

    pub_raw = calloc(1, pub_raw_size);
    if (pub_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_McElieceExportPublicKey(pub, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_McElieceExportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public key has been exported.\n");

    priv_raw = calloc(1, priv_raw_size);
    if (priv_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_McElieceExportPrivateKey(priv, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_McElieceExportPrivateKey(): %s\n", iqr_StrError(ret));
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

    iqr_McElieceDestroyPublicKey(&pub);
    iqr_McElieceDestroyPrivateKey(&priv);

    free(pub_raw);
    free(priv_raw);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of McEliece QC-MDPC parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_mceliece_params_creation(const iqr_Context *ctx, iqr_McElieceParams **params)
{
    /* Create McEliece parameters. */
    iqr_retval ret = iqr_McElieceCreateParams(ctx, IQR_HASHALGO_SHA2_256, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_McElieceCreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "McEliece QC-MDPC parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// McEliece.
// ---------------------------------------------------------------------------------------------------------------------------------


// ---------------------------------------------------------------------------------------------------------------------------------
// Initialize the toolkit by creating a context, registering hash
// algorithm, and creating a RNG object.
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

    /* Globally register the hashing functions. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "Hash functions have been registered in the context.\n");

    /* Create a HMAC DRBG object. */
    ret = iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA2_256, rng);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGCreateHMACDRBG(): %s\n", iqr_StrError(ret));
        return ret;
    }

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
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "mceliece_generate_keys [--pub <filename>] [--priv <filename>]\n");
    fprintf(stdout, "    Default for the sample (when no option is specified):\n");
    fprintf(stdout, "        --pub pub.key\n");
    fprintf(stdout, "        --priv priv.key\n");
}

/* Tests if two parameters match.
 * Returns 0 if the two parameter match, non-zero otherwise.
 * Parameters are expected to be less than 32 characters in length.
 */
static int paramcmp(const char *p1 , const char *p2)
{
    const size_t max_param_size = 32;

    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }

    return strncmp(p1, p2, max_param_size);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char * pub, const char * priv)
{
    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    key size: 32771 bits\n");
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const char **public_key_file, const char **private_key_file)
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
    iqr_Context * ctx = NULL;
    iqr_RNG *rng = NULL;
    iqr_McElieceParams *parameters = NULL;

    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    const char *public_key_file = "pub.key";
    const char *private_key_file = "priv.key";

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &public_key_file, &private_key_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Show the parameters for the program. */
    preamble(argv[0], public_key_file, private_key_file);

    /* IQR toolkit initialization. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the creation of McEliece QC-MDPC parameter structure. */
    ret = showcase_mceliece_params_creation(ctx, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the generation of McEliece QC-MDPC public/private keys. */
    ret = showcase_mceliece_key_gen(parameters, rng, public_key_file, private_key_file);

cleanup:
    iqr_McElieceDestroyParams(&parameters);
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
