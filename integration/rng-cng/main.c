/** @file main.c
 *
 * @brief Produce random numbers using the toolkit's RNG schemes.
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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers.
#endif

#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>

#include <stdbool.h>
#include <stdio.h>

// This may not exist in <ntstatus.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"rng-cng [--output <filename>] [--count <bytes>]\n"
"\n"
"    Defaults:\n"
"        --output random.dat\n"
"        --count 256\n"
"\n"
"  Uses the Windows BCRYPT_RNG_ALGORITHM as a source of random data.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// Windows CNG as a toolkit RNG.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval cng_rng_initialize(void **state, const uint8_t *seed, size_t seed_size)
{
    (void)seed;  // Unused by the BCRYPT_RNG_ALGORITHM.
    (void)seed_size;

    // Sanity-check inputs.
    if (state == NULL) {
        return IQR_ENULLPTR;
    }

    if (*state != NULL) {
        return IQR_EINVPTR;
    }

    BCRYPT_ALG_HANDLE alg = NULL;

    // Open a handle to the CNG.
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (NT_SUCCESS(status) == false) {
        return IQR_ENOTINIT;
    }

    *state = alg;
    return IQR_OK;
}

static iqr_retval cng_rng_reseed(void *state, const uint8_t *entropy, size_t entropy_size)
{
    (void)state;  // Unused by the BCRYPT_RNG_ALGORITHM.
    (void)entropy;
    (void)entropy_size;

    // The CNG random number generator will never need reseeding.
    return IQR_OK;
}

static iqr_retval cng_rng_getbytes(void *state, uint8_t *buf, size_t buf_size)
{
    // Sanity-check input.
    if (state == NULL || buf == NULL) {
        return IQR_ENULLPTR;
    }

    if (buf_size == 0) {
        return IQR_EINVBUFSIZE;
    }

    BCRYPT_ALG_HANDLE alg = (BCRYPT_ALG_HANDLE)state;

    // Generate requested random bytes.
    NTSTATUS status = BCryptGenRandom(alg, (PUCHAR)buf, (ULONG)buf_size, 0);
    if (NT_SUCCESS(status) == false) {
        return IQR_EINVOBJECT;
    }

    return IQR_OK;
}

static iqr_retval cng_rng_cleanup(void **state)
{
    // Sanity-check input.
    if (state == NULL) {
        return IQR_ENULLPTR;
    }

    BCRYPT_ALG_HANDLE alg = (BCRYPT_ALG_HANDLE)*state;

    // Close the provider handle.
    NTSTATUS status = BCryptCloseAlgorithmProvider(alg, 0);
    if (NT_SUCCESS(status) == false) {
        return IQR_EINVOBJECT;
    }

    *state = NULL;
    return IQR_OK;
}

// Create the callback structure.
static const iqr_RNGCallbacks cng_rng = {
    .initialize = cng_rng_initialize,
    .reseed = cng_rng_reseed,
    .getbytes = cng_rng_getbytes,
    .cleanup = cng_rng_cleanup
};

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases random number generation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_rng(iqr_Context *ctx, const char *output, size_t count)
{
    uint8_t *data = calloc(1, count);
    if (data == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return IQR_ENOMEM;
    }

    iqr_RNG *rng = NULL;

    iqr_retval ret = iqr_RNGCreate(ctx, &cng_rng, &rng);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGCreate(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "RNG object has been created.\n");

    /* The CNG RNG doesn't need seeding, but iqr_RNGInitialize() must be called
     * to initialize the RNG's internal state/objects. Since iqr_RNGInitialize()
     * requires non-NULL, non-zero input, we use dummy data here.
     * Your application code might be providing seed data anyway, if not
     * specifically written for a seed-less RNG.
     */
    const uint8_t seed[] = { 0 };
    const size_t seed_size = sizeof(seed);

    ret = iqr_RNGInitialize(rng, seed, seed_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGInitialize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_RNGGetBytes(rng, data, count);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGGetBytes(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "RNG data has been read.\n");

    ret = save_data(output, data, count);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Random data has been saved to disk.\n");

end:
    free(data);
    data = NULL;
    iqr_RNGDestroy(&rng);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// RNG.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create a Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
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

static void preamble(const char *cmd, const char *output, size_t count)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    randomness output file: %s\n", output);
    fprintf(stdout, "    randomness output byte count: %zu\n", count);
    fprintf(stdout, "\n");
}

/* Parse a parameter string which is supposed to be a positive integer
 * and return the value or -1 if the string is not properly formatted.
 */
static int32_t get_positive_int_param(const char *p)
{
    char *end = NULL;
    errno = 0;
    const long l = strtol(p, &end, 10);
    // Check for conversion errors.
    if (errno != 0) {
        return -1;
    }
    // Check that the string contained only a number and nothing else.
    if (end == NULL || end == p || *end != '\0') {
        return -1;
    }
    if (l < 0 || l > INT_MAX) {
        return -1;
    }
    return (int32_t)l;
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **output, size_t *count)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }
        if (paramcmp(argv[i], "--output") == 0) {
            /* [--output <filename>] */
            i++;
            *output = argv[i];
        } else if (paramcmp(argv[i], "--count") == 0) {
            i++;
            int32_t sz = get_positive_int_param(argv[i]);
            if (sz <= 0) {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
            *count = (size_t)sz;
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
    const char *output = "random.dat";
    const size_t default_count = 256;
    size_t count = default_count;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &output, &count);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], output, count);

    /* IQR initialization that is not specific to RNG. */
    iqr_Context *ctx = NULL;
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of random number generation. */
    ret = showcase_rng(ctx, output, count);
    if (ret != IQR_OK) {
        goto cleanup;
    }

cleanup:
    iqr_DestroyContext(&ctx);

    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
