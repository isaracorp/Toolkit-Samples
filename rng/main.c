/** @file main.c
 *
 * @brief Produce random numbers using the toolkit's RNG schemes.
 *
 * @copyright Copyright (C) 2016-2019, ISARA Corporation
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

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"rng [--hash sha2-256|sha2-384|sha2-512|sha3-256|sha3-512]\n"
"  [--seed <filename>] [--reseed <filename>] [--output <filename>]\n"
"  [--count <bytes>]\n"
"    Defaults are: \n"
"        --hash sha2-256\n"
"        --output random.dat\n"
"        --count 256\n"
"  Uses HMAC-DRBG with the specified hash.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases random number generation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_rng(iqr_Context *ctx, iqr_HashAlgorithmType hash, const uint8_t *seed_data, size_t seed_size,
    const uint8_t *reseed_data, size_t reseed_size, const char *output, size_t count)
{
    uint8_t *data = calloc(1, count);
    if (data == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return IQR_ENOMEM;
    }

    iqr_RNG *rng = NULL;

    iqr_retval ret = iqr_RNGCreateHMACDRBG(ctx, hash, &rng);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGCreateHMACDRBG(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "RNG object has been created.\n");

    ret = iqr_RNGInitialize(rng, seed_data, seed_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGInitialize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "RNG object has been seeded.\n");

    if (reseed_size > 0) {
        /** We reseed right away to follow the flow of the NIST test vectors.
         * In real life you would reseed as more randomness becomes available.
         * In this sample the user can avoid a reseed by providing an empty
         * reseed file.
         */
        ret = iqr_RNGReseed(rng, reseed_data, reseed_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_RNGReseed(): %s\n", iqr_StrError(ret));
            goto end;
        }

        fprintf(stdout, "RNG object has been reseeded.\n");
    }

    size_t initial_read_size = count / 2;
    if (initial_read_size != 0) {
        ret = iqr_RNGGetBytes(rng, data, initial_read_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_RNGGetBytes(): %s\n", iqr_StrError(ret));
            goto end;
        }
    }

    ret = iqr_RNGGetBytes(rng, data + initial_read_size, count - initial_read_size);
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

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_HashAlgorithmType hash, const iqr_HashCallbacks *cb)
{
    /* Create a Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, hash, cb);
    if (ret != IQR_OK) {
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
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, iqr_HashAlgorithmType hash, const char *seed, const char *reseed, const char *output,
    size_t count)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);

    if (IQR_HASHALGO_SHA2_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_256\n");
    } else if (IQR_HASHALGO_SHA2_384 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_384\n");
    } else if (IQR_HASHALGO_SHA2_512 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_512\n");
    } else if (IQR_HASHALGO_SHA3_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA3_256\n");
    } else if (IQR_HASHALGO_SHA3_512 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA3_512\n");
    }

    if (seed != NULL) {
        fprintf(stdout, "    seed source: %s\n", seed);
    } else {
        fprintf(stdout, "    seed: NIST HMAC-DRBG test vectors\n");
    }
    if (reseed != NULL) {
        fprintf(stdout, "    reseed source: %s\n", reseed);
    } else {
        fprintf(stdout, "    reseed: NIST HMAC-DRBG test vectors\n");
    }
    fprintf(stdout, "    randomness output file: %s\n", output);
    fprintf(stdout, "    randomness output byte count: %zu\n", count);
    fprintf(stdout, "\n");
}

/* Parse a parameter string which is supposed to be a positive integer
 * and return the value or -1 if the string is not properly formatted.
 */
static int32_t get_positive_int_param(const char *p) {
    char *end = NULL;
    errno = 0;
    const long l = strtol(p, &end, 10);
    // Check for conversion errors.
    if (errno != 0) {
        return -1;
    }
    // Check that the string contained only a number and nothing else.
    if (end == NULL || end == p || *end != '\0' ) {
        return -1;
    }
    if (l < 0 || l > INT_MAX) {
        return -1;
    }
    return (int32_t)l;
}

static iqr_retval parse_commandline(int argc, const char **argv, iqr_HashAlgorithmType *hash, const iqr_HashCallbacks **cb,
    const char **seed, const char **reseed, const char **output, size_t *count)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }
        if (paramcmp(argv[i], "--hash") == 0) {
            /* [--hash sha2-256|sha2-384|sha2-512|sha3-256|sha3-512]
             */
            i++;
            if (paramcmp(argv[i], "sha2-256") == 0) {
                *hash = IQR_HASHALGO_SHA2_256;
                *cb = &IQR_HASH_DEFAULT_SHA2_256;
            } else if (paramcmp(argv[i], "sha2-384") == 0) {
                *hash = IQR_HASHALGO_SHA2_384;
                *cb = &IQR_HASH_DEFAULT_SHA2_384;
            } else if (paramcmp(argv[i], "sha2-512") == 0) {
                *hash = IQR_HASHALGO_SHA2_512;
                *cb = &IQR_HASH_DEFAULT_SHA2_512;
            } else if (paramcmp(argv[i], "sha3-256") == 0) {
                *hash = IQR_HASHALGO_SHA3_256;
                *cb = &IQR_HASH_DEFAULT_SHA3_256;
            } else if (paramcmp(argv[i], "sha3-512") == 0) {
                *hash = IQR_HASHALGO_SHA3_512;
                *cb = &IQR_HASH_DEFAULT_SHA3_512;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--seed") == 0) {
            /* [--seed <filename>] */
            i++;
            *seed = argv[i];
        } else if (paramcmp(argv[i], "--reseed") == 0) {
            /* [--reseed <filename>] */
            i++;
            *reseed = argv[i];
        } else if (paramcmp(argv[i], "--output") == 0) {
            /* [--output <filename>] */
            i++;
            *output = argv[i];
        } else if (paramcmp(argv[i], "--count") == 0) {
            i++;
            int32_t sz  = get_positive_int_param(argv[i]);
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
// NIST test vectors used by the main() function if the user doesn't specify any
// seed/reseed data.
// ---------------------------------------------------------------------------------------------------------------------------------

static const uint8_t default_seed_data[] = {
    0x06, 0x03, 0x2c, 0xd5, 0xee, 0xd3, 0x3f, 0x39, 0x26, 0x5f, 0x49, 0xec, 0xb1, 0x42, 0xc5, 0x11,  // EntropyInput
    0xda, 0x9a, 0xff, 0x2a, 0xf7, 0x12, 0x03, 0xbf, 0xfa, 0xf3, 0x4a, 0x9c, 0xa5, 0xbd, 0x9c, 0x0d,
    0x0e, 0x66, 0xf7, 0x1e, 0xdc, 0x43, 0xe4, 0x2a, 0x45, 0xad, 0x3c, 0x6f, 0xc6, 0xcd, 0xc4, 0xdf   // Nonce
};
static const uint8_t default_reseed_data[] = {
    0x01, 0x92, 0x0a, 0x4e, 0x66, 0x9e, 0xd3, 0xa8, 0x5a, 0xe8, 0xa3, 0x3b, 0x35, 0xa7, 0x4a, 0xd7,
    0xfb, 0x2a, 0x6b, 0xb4, 0xcf, 0x39, 0x5c, 0xe0, 0x03, 0x34, 0xa9, 0xc9, 0xa5, 0xa5, 0xd5, 0x52
};
static const uint8_t default_expected_data[] = {
    0x76, 0xfc, 0x79, 0xfe, 0x9b, 0x50, 0xbe, 0xcc, 0xc9, 0x91, 0xa1, 0x1b, 0x56, 0x35, 0x78, 0x3a,
    0x83, 0x53, 0x6a, 0xdd, 0x03, 0xc1, 0x57, 0xfb, 0x30, 0x64, 0x5e, 0x61, 0x1c, 0x28, 0x98, 0xbb,
    0x2b, 0x1b, 0xc2, 0x15, 0x00, 0x02, 0x09, 0x20, 0x8c, 0xd5, 0x06, 0xcb, 0x28, 0xda, 0x2a, 0x51,
    0xbd, 0xb0, 0x38, 0x26, 0xaa, 0xf2, 0xbd, 0x23, 0x35, 0xd5, 0x76, 0xd5, 0x19, 0x16, 0x08, 0x42,
    0xe7, 0x15, 0x8a, 0xd0, 0x94, 0x9d, 0x1a, 0x9e, 0xc3, 0xe6, 0x6e, 0xa1, 0xb1, 0xa0, 0x64, 0xb0,
    0x05, 0xde, 0x91, 0x4e, 0xac, 0x2e, 0x9d, 0x4f, 0x2d, 0x72, 0xa8, 0x61, 0x6a, 0x80, 0x22, 0x54,
    0x22, 0x91, 0x82, 0x50, 0xff, 0x66, 0xa4, 0x1b, 0xd2, 0xf8, 0x64, 0xa6, 0xa3, 0x8c, 0xc5, 0xb6,
    0x49, 0x9d, 0xc4, 0x3f, 0x7f, 0x2b, 0xd0, 0x9e, 0x1e, 0x0f, 0x8f, 0x58, 0x85, 0x93, 0x51, 0x24
};

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* Default values.  Please adjust the usage message if you make changes
     * here.
     */
    iqr_HashAlgorithmType hash = IQR_HASHALGO_SHA2_256;
    const iqr_HashCallbacks *cb = &IQR_HASH_DEFAULT_SHA2_256;

    const char *seed = NULL;
    uint8_t *loaded_seed_data = NULL;
    const uint8_t *seed_data = default_seed_data;
    size_t seed_size = sizeof(default_seed_data);

    const char *reseed = NULL;
    uint8_t *loaded_reseed_data = NULL;
    const uint8_t *reseed_data = default_reseed_data;
    size_t reseed_size = sizeof(default_reseed_data);

    const char *output = "random.dat";
    const size_t default_count = 256;
    size_t count = default_count;
    uint8_t *validate = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &hash, &cb, &seed, &reseed, &output, &count);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], hash, seed, reseed, output, count);

    /* IQR initialization that is not specific to RNG. */
    iqr_Context *ctx = NULL;
    ret = init_toolkit(&ctx, hash, cb);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    if (seed != NULL) {
        ret = load_data(seed, &loaded_seed_data, &seed_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        seed_data = loaded_seed_data;
    }

    if (reseed != NULL) {
        ret = load_data(reseed, &loaded_reseed_data, &reseed_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        reseed_data = loaded_reseed_data;
    }

    /** This function showcases the usage of random number generation.
     */
    ret = showcase_rng(ctx, hash, seed_data, seed_size, reseed_data, reseed_size, output, count);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    if (seed_data == default_seed_data && reseed_data == default_reseed_data && hash == IQR_HASHALGO_SHA2_256 &&
        count == default_count) {
        /** The user has decided to use the default seed/reseed data, which
         * we've chosen as the NIST test vectors. So for fun we've decided to
         * verify the output against the expected NIST output and prove that it
         * works.
         *
         * The NIST test reads two chunks of data and compares against the
         * second read. In showcase_rng we read in two chunks as well, but saved
         * the entire data, so when we do the comparison here we just compare
         * the second half of the output to the test vector.
         */
        ret = load_data(output, &validate, &count);
        if (ret != IQR_OK) {
            goto cleanup;
        }

        // The NIST vector validation calls GetBytes twice and only verifies the
        // second call, so we do that here too by checking only the second half
        // of the output.
        if (memcmp(validate + count - sizeof(default_expected_data), default_expected_data, sizeof(default_expected_data)) == 0) {
            fprintf(stdout, "You're using the default NIST data and the output matches!\n");
        } else {
            fprintf(stdout, "You're using the default NIST data but the output DOESN'T MATCH!\n");
        }
    }

cleanup:
    free(validate);
    validate = NULL;
    free(loaded_reseed_data);
    loaded_reseed_data = NULL;
    free(loaded_seed_data);
    loaded_seed_data = NULL;

    iqr_DestroyContext(&ctx);

    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
