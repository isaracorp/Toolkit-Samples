/** @file main.c
 *
 * @brief Demonstrate the toolkit's SIKE key encapsulation mechanism.
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
#include "iqr_sike.h"
#include "iqr_retval.h"
#include "iqr_rng.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static void secure_memzero(void *b, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the generation of SIKE public and
// private keys.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_sike_key_gen(const iqr_SIKEParams *params, const iqr_RNG *rng,
    const char *pub_file, const char *priv_file)
{
    iqr_SIKEPublicKey *pub = NULL;
    iqr_SIKEPrivateKey *priv = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    fprintf(stdout, "Creating SIKE key-pair.\n");

    iqr_retval ret = iqr_SIKECreateKeyPair(params, rng, &pub, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKECreateKeyPair(): %s\n", iqr_StrError(ret));
        goto end;
    }
    fprintf(stdout, "SIKE public and private key-pair has been created\n");

    ret = iqr_SIKEGetPublicKeySize(params, &pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKEGetPublicKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    pub_raw = calloc(1, pub_raw_size);
    if (pub_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_SIKEExportPublicKey(pub, pub_raw, pub_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKEExportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public key has been exported.\n");

    ret = iqr_SIKEGetPrivateKeySize(params, &priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKEGetPrivateKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    priv_raw = calloc(1, priv_raw_size);
    if (priv_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_SIKEExportPrivateKey(priv, priv_raw, priv_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKEExportPrivateKey(): %s\n", iqr_StrError(ret));
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

    iqr_SIKEDestroyPublicKey(&pub);
    iqr_SIKEDestroyPrivateKey(&priv);

    free(pub_raw);
    free(priv_raw);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of SIKE parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_sike_params_creation(const iqr_Context *ctx, const iqr_SIKEVariant *variant, iqr_SIKEParams **params)
{
    /* Create sike parameters. */
    iqr_retval ret = iqr_SIKECreateParams(ctx, variant, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIKECreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "SIKE parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// sike.
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

    /* This sets the SHA2-256 functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the SHA3-256 functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_256, &IQR_HASH_DEFAULT_SHA3_256);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the SHA3-512 functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_512, &IQR_HASH_DEFAULT_SHA3_512);
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
    fprintf(stdout, "sike_generate_keys [--variant p503|p751] [--pub <filename>] [--priv <filename>]\n");
    fprintf(stdout, "    Default for the sample (when no option is specified):\n");
    fprintf(stdout, "        --variant p751\n");
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

static void preamble(const char *cmd,  const iqr_SIKEVariant *variant, const char * pub, const char * priv)
{
    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    if (variant == &IQR_SIKE_P751) {
        fprintf(stdout, "    variant: p751\n");
    } else {
        fprintf(stdout, "    variant: p503\n");
    }
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    private key file: %s\n", priv);
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_SIKEVariant **variant, const char **public_key_file,
    const char **private_key_file)
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
        } else if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant p503|p751] */
            i++;
            if (paramcmp(argv[i], "p503") == 0) {
                *variant = &IQR_SIKE_P503;
            } else if  (paramcmp(argv[i], "p751") == 0) {
                *variant = &IQR_SIKE_P751;
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
    iqr_Context * ctx = NULL;
    iqr_RNG *rng = NULL;
    iqr_SIKEParams *parameters = NULL;
    const iqr_SIKEVariant *variant = &IQR_SIKE_P751;

    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    const char *public_key_file = "pub.key";
    const char *private_key_file = "priv.key";

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &public_key_file, &private_key_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Show the parameters for the program. */
    preamble(argv[0], variant, public_key_file, private_key_file);

    /* IQR toolkit initialization. */
    ret = init_toolkit(&ctx, &rng);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the creation of SIKE parameter structure. */
    ret = showcase_sike_params_creation(ctx, variant, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the generation of SIKE public/private keys. */
    ret = showcase_sike_key_gen(parameters, rng, public_key_file, private_key_file);

cleanup:
    iqr_SIKEDestroyParams(&parameters);
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}