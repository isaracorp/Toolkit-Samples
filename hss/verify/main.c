/** @file main.c
 *
 * @brief Verify a signature using the toolkit's HSS signature scheme.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_hss.h"
#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the verification of an HSS signature against a
// digest.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_hss_verify(const iqr_Context *ctx, iqr_HSSWinternitz w, iqr_HSSHeight height, const uint8_t *digest,
    const char *pub_file, const char *sig_file)
{
    iqr_HSSParams *params = NULL;
    iqr_HSSPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    /* The tree strategy chosen will have no effect on verification. */
    iqr_retval ret = iqr_HSSCreateParams(ctx, &IQR_HSS_VERIFY_ONLY_STRATEGY, w, height, IQR_HSS_LEVEL_1, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSCreateParams(): %s\n", iqr_StrError(ret));
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
    ret = iqr_HSSImportPublicKey(params, pub_raw, pub_raw_size, &pub);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSImportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public key has been loaded successfully!\n");

    ret = iqr_HSSVerify(pub, digest, IQR_SHA2_512_DIGEST_SIZE, sig, sig_size);
    if (ret == IQR_OK) {
        fprintf(stdout, "HSS verified the signature successfully!\n");
    } else {
        fprintf(stderr, "Failed on iqr_HSSVerify(): %s\n", iqr_StrError(ret));
    }

    iqr_HSSDestroyPublicKey(&pub);

end:
    free(pub_raw);
    free(sig);

    iqr_HSSDestroyParams(&params);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// HSS.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// This function takes a message buffer and creates a digest out of it.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval create_digest(const iqr_Context *ctx, uint8_t *data, size_t data_size, uint8_t *out_digest)
{
    iqr_Hash *hash = NULL;
    iqr_retval ret = iqr_HashCreate(ctx, IQR_HASHALGO_SHA2_512, &hash);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashCreate(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* The HSS scheme will sign a digest of the message, so we need a digest
     * of our message.  This will give us that digest.
     */
    ret = iqr_HashMessage(hash, data, data_size, out_digest, IQR_SHA2_512_DIGEST_SIZE);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashMessage(): %s\n", iqr_StrError(ret));
        iqr_HashDestroy(&hash);
        return ret;
    }

    iqr_HashDestroy(&hash);
    return IQR_OK;
}

static iqr_retval init_toolkit(iqr_Context **ctx, const char *message, uint8_t **digest)
{
    uint8_t *message_raw = NULL;
    size_t message_raw_size = 0;

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

    /* SHA2-512 produces a 64-byte digest, which is required by iqr_HSSVerify. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_512, &IQR_HASH_DEFAULT_SHA2_512);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* Before we do any work, lets make sure we can load the message file. */
    ret = load_data(message, &message_raw, &message_raw_size);
    if (ret != IQR_OK) {
        return ret;
    }

    *digest = calloc(1, IQR_SHA2_512_DIGEST_SIZE);
    if (*digest == NULL) {
        fprintf(stderr, "Failed to allocate space for the digest\n");
        free(message_raw);
        return IQR_ENOMEM;
    }

    /* Calculate the digest */
    ret = create_digest(*ctx, message_raw, message_raw_size, *digest);
    if (ret != IQR_OK) {
        free(message_raw);
        free(*digest);
        *digest = NULL;
        return ret;
    }

    free(message_raw);
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

    /* Due to a bug in GCC 7.2, it is necessary to make tmp_size volatile. Otherwise,
     * the variable is removed by the compiler and tmp_size64 is used instead. This
     * causes the calloc() call further down to raise a compiler warning. */
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
    fprintf(stdout, "hss_verify [--sig <filename>] [--pub <filename>] [--winternitz 1|2|4|8]\n"
"  [--height 5|10|15|20|25] [--message <filename>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --sig sig.dat\n");
    fprintf(stdout, "        --pub pub.key\n");
    fprintf(stdout, "        --winternitz 4\n");
    fprintf(stdout, "        --height 5\n");
    fprintf(stdout, "        --message message.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *sig, const char *pub, iqr_HSSWinternitz w, iqr_HSSHeight height,
    const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    public key file: %s\n", pub);

    if (IQR_HSS_WINTERNITZ_1 == w) {
        fprintf(stdout, "    winternitz value: IQR_HSS_WINTERNITZ_1\n");
    } else if (IQR_HSS_WINTERNITZ_2 == w) {
        fprintf(stdout, "    winternitz value: IQR_HSS_WINTERNITZ_2\n");
    } else if (IQR_HSS_WINTERNITZ_4 == w) {
        fprintf(stdout, "    winternitz value: IQR_HSS_WINTERNITZ_4\n");
    } else if (IQR_HSS_WINTERNITZ_8 == w) {
        fprintf(stdout, "    winternitz value: IQR_HSS_WINTERNITZ_8\n");
    } else {
        fprintf(stdout, "    winternitz value: INVALID\n");
    }

    if (IQR_HSS_HEIGHT_5 == height) {
        fprintf(stdout, "    height: IQR_HSS_HEIGHT_5\n");
    } else if (IQR_HSS_HEIGHT_10 == height) {
        fprintf(stdout, "    height: IQR_HSS_HEIGHT_10\n");
    } else if (IQR_HSS_HEIGHT_15 == height) {
        fprintf(stdout, "    height: IQR_HSS_HEIGHT_15\n");
    } else if (IQR_HSS_HEIGHT_20 == height) {
        fprintf(stdout, "    height: IQR_HSS_HEIGHT_20\n");
    } else if (IQR_HSS_HEIGHT_25 == height) {
        fprintf(stdout, "    height: IQR_HSS_HEIGHT_25\n");
    } else {
        fprintf(stdout, "    height: INVALID\n");
    }

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

static iqr_retval parse_commandline(int argc, const char **argv, const char **sig, const char **pub, iqr_HSSWinternitz *w,
    iqr_HSSHeight *height, const char **message)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--sig") == 0) {
            /* [--sig <filename>] */
            i++;
            *sig = argv[i];
        } else if (paramcmp(argv[i], "--pub") == 0) {
            /* [--pub <filename>] */
            i++;
            *pub = argv[i];
        } else if (paramcmp(argv[i], "--winternitz") == 0) {
            /* [--winternitz 1|2|4|8] */
            i++;
            if (paramcmp(argv[i], "1") == 0) {
                *w = IQR_HSS_WINTERNITZ_1;
            } else if  (paramcmp(argv[i], "2") == 0) {
                *w = IQR_HSS_WINTERNITZ_2;
            } else if  (paramcmp(argv[i], "4") == 0) {
                *w = IQR_HSS_WINTERNITZ_4;
            } else if  (paramcmp(argv[i], "8") == 0) {
                *w = IQR_HSS_WINTERNITZ_8;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--height") == 0) {
            /* [--height 5|10|15|20|25] */
            i++;
            if (paramcmp(argv[i], "5") == 0) {
                *height = IQR_HSS_HEIGHT_5;
            } else if  (paramcmp(argv[i], "10") == 0) {
                *height = IQR_HSS_HEIGHT_10;
            } else if  (paramcmp(argv[i], "15") == 0) {
                *height = IQR_HSS_HEIGHT_15;
            } else if  (paramcmp(argv[i], "20") == 0) {
                *height = IQR_HSS_HEIGHT_20;
            } else if  (paramcmp(argv[i], "25") == 0) {
                *height = IQR_HSS_HEIGHT_25;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
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
    iqr_HSSWinternitz w = IQR_HSS_WINTERNITZ_4;
    iqr_HSSHeight height =  IQR_HSS_HEIGHT_5;

    iqr_Context *ctx = NULL;
    uint8_t *digest = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &sig, &pub, &w, &height, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], sig, pub, w, height, message);

    /* IQR initialization that is not specific to HSS. */
    ret = init_toolkit(&ctx, message, &digest);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of HSS signature verification.
     */
    ret = showcase_hss_verify(ctx, w, height, digest, pub, sig);

cleanup:
    iqr_DestroyContext(&ctx);
    free(digest);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}