/** @file main.c
 *
 * @brief Produce random numbers using the toolkit's RNG schemes.
 *
 * @copyright Copyright (C) 2016-2023, ISARA Corporation, All Rights Reserved.
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
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"rng-urandom [--seed <filename>] [--reseed <filename>] [--output <filename>]\n"
"  [--count <bytes>]\n"
"\n"
"    Defaults:\n"
"        --output random.dat\n"
"        --count 256\n"
"\n"
"  Uses /dev/urandom as a source of random data.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// Use /dev/urandom as a toolkit RNG.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval devurandom_initialize(void **state, const uint8_t *seed, size_t seed_size)
{
    // Sanity-check inputs.
    if (state == NULL || seed == NULL) {
        return IQR_ENULLPTR;
    }

    if (*state != NULL) {
        return IQR_EINVPTR;
    }

    // The caller must provide seed data.
    if (seed_size == 0) {
        return IQR_EINVBUFSIZE;
    }

    // Allocating a fundamental type like this is a bit weird, but we do it so
    // the RNG is self-contained. In this case, the device handle is the only
    // state, otherwise we'd be allocating and maintaining a larger structure.
    int *device_handle = calloc(1, sizeof(int));
    if (device_handle == NULL) {
        return IQR_ENOMEM;
    }

    iqr_retval result = IQR_OK;

    // Write our seed data to the device.
    *device_handle = open("/dev/urandom", O_RDWR);
    if (*device_handle == -1) {
        result = IQR_ENOTINIT;
        goto cleanup;
    }

    while (seed_size > 0) {
        ssize_t bytes_written = write(*device_handle, seed, seed_size);
        if (bytes_written == -1) {
            // Some /dev/urandom devices appear writeable, but fail on the
            // write call.
            fprintf(stderr, "Unable to write to /dev/urandom; seed data will be ignored.\n");
            break;
        }
        seed_size -= (size_t)bytes_written;
        seed += bytes_written;
    }

    // We don't need to allocate state, just store the file descriptor.
    *state = device_handle;
    return result;

cleanup:
    if (*device_handle != -1) {
        close(*device_handle);
    }
    free(device_handle);
    device_handle = NULL;

    return result;
}

static iqr_retval devurandom_reseed(void *state, const uint8_t *entropy, size_t entropy_size)
{
    // Sanity-check input.
    if (state == NULL || entropy == NULL) {
        return IQR_ENULLPTR;
    }

    if (entropy_size == 0) {
        return IQR_EINVBUFSIZE;
    }

    // Add the data to your RNG's entropy.
    int *device_handle = state;
    while (entropy_size > 0) {
        ssize_t bytes_written = write(*device_handle, entropy, entropy_size);
        if (bytes_written == -1) {
            // Some /dev/urandom devices appear writeable, but fail on the
            // write call.
            fprintf(stderr, "Unable to write to /dev/urandom; reseed data will be ignored.\n");
            break;
        }
        entropy += bytes_written;
        entropy_size -= (size_t)bytes_written;
    }

    return IQR_OK;
}

static iqr_retval devurandom_getbytes(void *state, uint8_t *buf, size_t buf_size)
{
    // Sanity-check input.
    if (state == NULL || buf == NULL) {
        return IQR_ENULLPTR;
    }

    if (buf_size == 0) {
        return IQR_EINVBUFSIZE;
    }

    // Generate random bytes and write them into the buffer.
    int *device_handle = state;
    while (buf_size > 0) {
        ssize_t bytes_read = read(*device_handle, buf, buf_size);
        if (bytes_read == -1) {
            return IQR_EINVDATA;
        }
        buf += bytes_read;
        buf_size -= (size_t)bytes_read;
    }

    return IQR_OK;
}

static iqr_retval devurandom_cleanup(void **state)
{
    // Sanity-check input.
    if (state == NULL) {
        return IQR_ENULLPTR;
    }

    // Clean up and deallocate any state you allocated.
    int *device_handle = *state;
    close(*device_handle);
    free(device_handle);
    *state = NULL;

    return IQR_OK;
}

// Create the callback structure.
static const iqr_RNGCallbacks devurandom_rng = {
    .initialize = devurandom_initialize,
    .reseed = devurandom_reseed,
    .getbytes = devurandom_getbytes,
    .cleanup = devurandom_cleanup
};

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases random number generation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_rng(iqr_Context *ctx, const uint8_t *seed_data, size_t seed_size, const uint8_t *reseed_data,
    size_t reseed_size, const char *output, size_t count)
{
    uint8_t *data = calloc(1, count);
    if (data == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return IQR_ENOMEM;
    }

    iqr_RNG *rng = NULL;

    iqr_retval ret = iqr_RNGCreate(ctx, &devurandom_rng, &rng);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGCreate(): %s\n", iqr_StrError(ret));
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
        /* We reseed right away to follow the flow of the NIST test vectors.
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

static void preamble(const char *cmd, const char *seed, const char *reseed, const char *output, size_t count)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);

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

static iqr_retval parse_commandline(int argc, const char **argv, const char **seed, const char **reseed, const char **output,
    size_t *count)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }
        if (paramcmp(argv[i], "--seed") == 0) {
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

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* Default values. Please adjust the usage message if you make changes
     * here.
     */
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

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &seed, &reseed, &output, &count);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], seed, reseed, output, count);

    /* IQR initialization that is not specific to RNG. */
    iqr_Context *ctx = NULL;
    ret = init_toolkit(&ctx);
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

    /* This function showcases the usage of random number generation. */
    ret = showcase_rng(ctx, seed_data, seed_size, reseed_data, reseed_size, output, count);
    if (ret != IQR_OK) {
        goto cleanup;
    }

cleanup:
    free(loaded_reseed_data);
    loaded_reseed_data = NULL;
    free(loaded_seed_data);
    loaded_seed_data = NULL;

    iqr_DestroyContext(&ctx);

    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
