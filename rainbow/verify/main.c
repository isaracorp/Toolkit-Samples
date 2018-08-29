/** @file main.c
 *
 * @brief Verify a signature using the toolkit's Rainbow signature scheme.
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
#include <string.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_rainbow.h"
#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the verification of a Rainbow signature against a
// digest.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_rainbow_verify(const iqr_Context *ctx, const iqr_RainbowVariant *variant, const char *pub_file,
    const char *message_file, const char *sig_file)
{
    iqr_RainbowParams *params = NULL;
    iqr_RainbowPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t message_size = 0;
    uint8_t *message = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    iqr_retval ret = iqr_RainbowCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the public key and signature from disk. */
    ret = load_data(pub_file, &pub_raw, &pub_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = load_data(sig_file, &sig, &sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Import the public key data and create a public key object. */
    ret = iqr_RainbowImportPublicKey(params, pub_raw, pub_raw_size, &pub);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RainbowImportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public key has been loaded successfully!\n");

    /* Load the message. */
    ret = load_data(message_file, &message, &message_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_RainbowVerify(pub, message, message_size, sig, sig_size);
    if (ret == IQR_OK) {
        fprintf(stdout, "Rainbow verified the signature successfully!\n");
    } else {
        fprintf(stderr, "Failed on iqr_RainbowVerify(): %s\n", iqr_StrError(ret));
    }

end:
    iqr_RainbowDestroyPublicKey(&pub);
    iqr_RainbowDestroyParams(&params);

    free(message);
    free(pub_raw);
    free(sig);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// the Rainbow signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create a Global Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used by the scheme. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_384, &IQR_HASH_DEFAULT_SHA2_384);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_512, &IQR_HASH_DEFAULT_SHA2_512);
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

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size)
{
    FILE *fp = fopen(fname, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    /* Obtain file size. */
    fseek(fp , 0 , SEEK_END);
    size_t tmp_size = (size_t)ftell(fp);
    rewind(fp);

    iqr_retval ret = IQR_OK;
    uint8_t *tmp = NULL;
    if (tmp_size != 0) {
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
    }

    *data_size = tmp_size;
    *data = tmp;

    fprintf(stdout, "Successfully loaded %s (%zu bytes)\n", fname, *data_size);

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
    fprintf(stdout, "rainbow_verify [--security IIIb|IIIc|IVa|Vc|VIa|VIb] [--sig <filename>]\n"
                    "  [--pub <filename>] [--message <filename>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --security IIIb\n");
    fprintf(stdout, "        --sig sig.dat\n");
    fprintf(stdout, "        --pub pub.key\n");
    fprintf(stdout, "        --message message.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const iqr_RainbowVariant *variant, const char *sig, const char *pub, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_RAINBOW_GF31_64_32_48) {
        fprintf(stdout, "    security level: IIIb. parameter set: (GF(31), 64, 32, 48)\n");
    } else if (variant == &IQR_RAINBOW_GF256_68_36_36) {
        fprintf(stdout, "    security level: IIIc. parameter set: (GF(256), 68, 36, 36)\n");
    } else if (variant == &IQR_RAINBOW_GF16_56_48_48) {
        fprintf(stdout, "    security level: IVa. parameter set: (GF(16), 56, 48, 48)\n");
    } else if (variant == &IQR_RAINBOW_GF256_92_48_48) {
        fprintf(stdout, "    security level: Vc. parameter set: (GF(256), 92, 48, 48)\n");
    } else if (variant == &IQR_RAINBOW_GF16_76_64_64) {
        fprintf(stdout, "    security level: VIa. parameter set: (GF(16), 76, 64, 64)\n");
    } else if (variant == &IQR_RAINBOW_GF31_84_56_56) {
        fprintf(stdout, "    security level: VIb. parameter set: (GF(31), 84, 56, 56)\n");
    }
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    message data file: %s\n", message);
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

static iqr_retval parse_commandline(int argc, const char **argv, const iqr_RainbowVariant **variant, const char **sig,
    const char **pub, const char **message)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--security") == 0) {
            /* [--security IIIb|IIIc|IVa|Vc|VIa|VIb] */
            i++;
            if  (paramcmp(argv[i], "IIIb") == 0) {
                *variant = &IQR_RAINBOW_GF31_64_32_48;
            } else if  (paramcmp(argv[i], "IIIc") == 0) {
                *variant = &IQR_RAINBOW_GF256_68_36_36;
            } else if  (paramcmp(argv[i], "IVa") == 0) {
                *variant = &IQR_RAINBOW_GF16_56_48_48;
            } else if  (paramcmp(argv[i], "Vc") == 0) {
                *variant = &IQR_RAINBOW_GF256_92_48_48;
            } else if  (paramcmp(argv[i], "VIa") == 0) {
                *variant = &IQR_RAINBOW_GF16_76_64_64;
            } else if  (paramcmp(argv[i], "VIb") == 0) {
                *variant = &IQR_RAINBOW_GF31_84_56_56;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--sig") == 0) {
            /* [--sig <filename>] */
            i++;
            *sig = argv[i];
        } else if (paramcmp(argv[i], "--pub") == 0) {
            /* [--pub <filename>] */
            i++;
            *pub = argv[i];
        } else if (paramcmp(argv[i], "--message") == 0) {
           /* [--message <filename>] */
           i++;
           *message = argv[i];
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
    /* Default values.  Please adjust the usage() message if you make changes
     * here. */
    const char *sig = "sig.dat";
    const char *pub = "pub.key";
    const char *message = "message.dat";

    const iqr_RainbowVariant *variant = &IQR_RAINBOW_GF31_64_32_48;

    iqr_Context *ctx = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &sig, &pub, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], variant, sig, pub, message);

    /* IQR initialization that is not specific to Rainbow. */
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of Rainbow signature verification.
     */
    ret = showcase_rainbow_verify(ctx, variant, pub, message, sig);

cleanup:
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
