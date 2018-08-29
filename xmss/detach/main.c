/** @file main.c
 *
 * @brief Detach a portion of the XMSS state into a separate file.
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
#include <limits.h>
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
#include "iqr_xmss.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);
static void secure_memzero(void *b, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases state detachment using the XMSS signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_xmss_detach(const iqr_Context *ctx, iqr_XMSSHeight height, const iqr_XMSSTreeStrategy *strategy,
    const char *priv_file, const char *state_file, uint32_t num_signatures, const char *detached_state_file)
{
    iqr_XMSSParams *params = NULL;
    iqr_XMSSPrivateKey *priv = NULL;
    iqr_XMSSPrivateKeyState *state = NULL;
    iqr_XMSSPrivateKeyState *detached_state = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    size_t state_raw_size = 0;
    uint8_t *state_raw = NULL;

    size_t detached_state_raw_size = 0;
    uint8_t *detached_state_raw = NULL;

    uint32_t max_sigs = 0;
    uint32_t remaining_sigs = 0;
    uint32_t detached_remaining_sigs = 0;

    iqr_retval ret = iqr_XMSSCreateParams(ctx, strategy, height, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the raw private key. */
    ret = load_data(priv_file, &priv_raw, &priv_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Load the private key state. */
    ret = load_data(state_file, &state_raw, &state_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_XMSSImportPrivateKey(params, priv_raw, priv_raw_size, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key has been imported.\n");

    ret = iqr_XMSSImportState(params, state_raw, state_raw_size, &state);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSImportState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key state has been imported.\n");

    ret = iqr_XMSSDetachState(priv, state, num_signatures, &detached_state);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSDetachState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_XMSSGetSignatureCount(state, &max_sigs, &remaining_sigs);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSGetMaximumSignatureCount(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_XMSSGetSignatureCount(detached_state, &max_sigs, &detached_remaining_sigs);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSGetMaximumSignatureCount(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Original state has %d signatures remaining.\n", remaining_sigs);
    fprintf(stdout, "Detached state has %d signatures remaining.\n", detached_remaining_sigs);

    /* Export the updated original state. */
    ret = iqr_XMSSExportState(state, state_raw, state_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSExportState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(state_file, state_raw, state_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Export the newly detached state. */
    ret = iqr_XMSSGetStateSize(detached_state, &detached_state_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSGetStateSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    detached_state_raw = calloc(1, detached_state_raw_size);
    if (detached_state_raw == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_XMSSExportState(detached_state, state_raw, state_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSExportState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(detached_state_file, state_raw, state_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

end:
    if (priv_raw != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memzero(priv_raw, priv_raw_size);
    }
    free(priv_raw);
    free(state_raw);
    free(detached_state_raw);

    iqr_XMSSDestroyPrivateKey(&priv);
    iqr_XMSSDestroyState(&state);
    iqr_XMSSDestroyState(&detached_state);
    iqr_XMSSDestroyParams(&params);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// XMSS.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// This function takes a message buffer and creates a digest out of it.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create a Global Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
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

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size)
{
    iqr_retval ret = IQR_OK;

    FILE *fp = fopen(fname, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    /* Obtain file size. */
    fseek(fp , 0 , SEEK_END);
#if defined(_WIN32) || defined(_WIN64)
    const int64_t tmp_size64 = (int64_t)_ftelli64(fp);

    if (tmp_size64 < 0) {
        fprintf(stderr, "Failed on _ftelli64(): %s\n", strerror(errno));
        ret = IQR_EBADVALUE;
        goto end;
    } else if ((uint64_t)tmp_size64 > (uint64_t)SIZE_MAX) {
        /* On 32-bit systems, we cannot allocate enough memory for large key files. */
        ret = IQR_ENOMEM;
        goto end;
    }

    /* Due to a bug in GCC 7.2, it is necessary to make tmp_size volatile.
     * Otherwise, the variable is removed by the compiler and tmp_size64 is used
     * instead. This causes the calloc() call further down to raise a compiler
     * warning. */
    volatile size_t tmp_size = (size_t)tmp_size64;
#else
    const size_t tmp_size = (size_t)ftell(fp);
#endif
    if (ferror(fp) != 0) {
        fprintf(stderr, "Failed on ftell(): %s\n", strerror(errno));
        ret = IQR_EBADVALUE;
        goto end;
    }

    rewind(fp);

    if (tmp_size > 0) {
        uint8_t *tmp = NULL;

        /* calloc with a param of 0 could return a pointer or NULL depending on
         * implementation, so skip all this when the size is 0 so we
         * consistently return NULL with a size of 0. In some samples it's
         * useful to take empty files as input so users can pass NULL or 0 for
         * optional parameters.
         */
        tmp = calloc(1, tmp_size);
        if (tmp == NULL) {
            fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
            ret = IQR_EBADVALUE;
            goto end;
        }

        size_t read_size = fread(tmp, 1, tmp_size, fp);
        if (read_size != tmp_size) {
            fprintf(stderr, "Failed on fread(): %s\n", strerror(errno));
            free(tmp);
            tmp = NULL;
            ret = IQR_EBADVALUE;
            goto end;
        }

        *data_size = tmp_size;
        *data = tmp;

        fprintf(stdout, "Successfully loaded %s (%zu bytes)\n", fname, *data_size);
    }

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
    fprintf(stdout, "xmss_detach [--priv <filename>] [--state <filename>] [--detached-state <filename>]\n"
        "  [--num-sigs <number>] [--height 10|16|20] [--strategy bds|full]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --priv priv.key\n");
    fprintf(stdout, "        --state priv.state\n");
    fprintf(stdout, "        --strategy full\n");
    fprintf(stdout, "        --height 5\n");
    fprintf(stdout, "        --detached-state detached.state\n");
    fprintf(stdout, "        --num-sigs 1\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *priv, const char *state, iqr_XMSSHeight height,
    const iqr_XMSSTreeStrategy *strategy, uint32_t num_sigs, const char *detached_state)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    private key state file: %s\n", state);
    fprintf(stdout, "    private key detached state file: %s\n", detached_state);
    fprintf(stdout, "    detaching %d signatures\n", num_sigs);

    if (IQR_XMSS_HEIGHT_10 == height) {
        fprintf(stdout, "    height: IQR_XMSS_HEIGHT_10\n");
    } else if (IQR_XMSS_HEIGHT_16 == height) {
        fprintf(stdout, "    height: IQR_XMSS_HEIGHT_15\n");
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
static int paramcmp(const char *p1 , const char *p2)
{
    const size_t max_param_size = 32;  // Arbitrary, but reasonable.
    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }
    return strncmp(p1, p2, max_param_size);
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **priv, const char **state, iqr_XMSSHeight *height,
    const iqr_XMSSTreeStrategy **strategy, uint32_t *num_signatures, const char **detached_state)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *priv = argv[i];
        } else if (paramcmp(argv[i], "--state") == 0) {
            /* [--state <filename>] */
            i++;
            *state = argv[i];
        } else if (paramcmp(argv[i], "--detached-state") == 0) {
            /* [--detached-state <filename>] */
            i++;
            *detached_state = argv[i];
        } else if (paramcmp(argv[i], "--height") == 0) {
            /* [--height 5|10|15|20|25] */
            i++;
            if  (paramcmp(argv[i], "10") == 0) {
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
        } else if (paramcmp(argv[i], "--num-sigs") == 0) {
            /* [--num-sigs <number>] */
            i++;

            char *end = NULL;
            const uint64_t val = strtoull(argv[i], &end, 10);
            if (end == argv[i] || *end != '\0' || (val == ULLONG_MAX && errno == ERANGE)) {
                usage();
                return IQR_EBADVALUE;
            }
            *num_signatures = (uint32_t)val;
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
     *  here.
     */
    const char *priv = "priv.key";
    const char *state = "priv.state";
    const char *detached_state = "detached.state";
    const iqr_XMSSTreeStrategy *strategy = &IQR_XMSS_FULL_STRATEGY;
    iqr_XMSSHeight height = IQR_XMSS_HEIGHT_10;
    uint32_t num_sigs = 1;

    iqr_Context *ctx = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &priv, &state, &height, &strategy, &num_sigs, &detached_state);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], priv, state, height, strategy, num_sigs, detached_state);

    /* IQR initialization that is not specific to XMSS. */
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of XMSS signing.
     */
    ret = showcase_xmss_detach(ctx, height, strategy, priv, state, num_sigs, detached_state);

cleanup:
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
